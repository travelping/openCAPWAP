/*******************************************************************************************
 * Copyright (c) 2006-7 Laboratorio di Sistemi di Elaborazione e Bioingegneria Informatica *
 *                      Universita' Campus BioMedico - Italy                               *
 *                                                                                         *
 * This program is free software; you can redistribute it and/or modify it under the terms *
 * of the GNU General Public License as published by the Free Software Foundation; either  *
 * version 2 of the License, or (at your option) any later version.                        *
 *                                                                                         *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY         *
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A         *
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.                *
 *                                                                                         *
 * You should have received a copy of the GNU General Public License along with this       *
 * program; if not, write to the:                                                          *
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,                    *
 * MA  02111-1307, USA.                                                                    *
 *                                                                                         *
 * --------------------------------------------------------------------------------------- *
 * Project:  Capwap                                                                        *
 *                                                                                         *
 * Author :  Ludovico Rossi (ludo@bluepixysw.com)                                          *
 *           Del Moro Andrea (andrea_delmoro@libero.it)                                    *
 *           Giovannini Federica (giovannini.federica@gmail.com)                           *
 *           Massimo Vellucci (m.vellucci@unicampus.it)                                    *
 *           Mauro Bisson (mauro.bis@gmail.com)                                            *
 *******************************************************************************************/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "CWWTP.h"

/*________________________________________________________________*/
/*  *******************___CAPWAP VARIABLES___*******************  */
int gCWMaxDiscoveries = 10;

/*_________________________________________________________*/
/*  *******************___VARIABLES___*******************  */
int gCWDiscoveryCount;
CWList ACList = CW_LIST_INIT;

#ifdef CW_DEBUGGING
int gCWDiscoveryInterval = 3;	//5;
int gCWMaxDiscoveryInterval = 4;	//20;
#else
int gCWDiscoveryInterval = 5;
int gCWMaxDiscoveryInterval = 20;
#endif

/*_____________________________________________________*/
/*  *******************___MACRO___*******************  */
#define CWWTPFoundAnAC()    (gACInfoPtr != NULL /*&& gACInfoPtr->preferredAddress.ss_family != AF_UNSPEC*/)

/*__________________________________________________________*/
/*  *******************___PROTOTYPES___*******************  */
CWBool CWReceiveDiscoveryResponse();
void CWWTPEvaluateAC(CWACInfoValues * ACInfoPtr);
CWBool CWReadResponses();
CWBool CWAssembleDiscoveryRequest(CWProtocolMessage ** messagesPtr, int seqNum);
CWBool CWParseDiscoveryResponseMessage(unsigned char *msg, int len, int *seqNumPtr, CWACInfoValues * ACInfoPtr);

typedef struct {
	CWNetworkLev4Address address;
        CWBool received;
        int seqNum;
} CWDiscoverAC;

typedef struct {
        int priority;
        CWNetworkLev4Address address;
} CWDiscoveredAC;

static int DiscoveredACCount = 0;
static int CurrentDiscoveredAC = 0;
static CWDiscoveredAC *DiscoveredAC = NULL;

#define DAC_BLOCK_SIZE 32

/*_________________________________________________________*/
/*  *******************___FUNCTIONS___*******************  */

static void CWDestroyDiscoverAC(void *f)
{
       CW_FREE_OBJECT(f);
}

static void CWDestroyDiscoverACList(CWList *ACList)
{
       CWDeleteList(ACList, CWDestroyDiscoverAC);
       *ACList = NULL;
}

static CWBool CWAddDiscoverACAddress(CWList *ACList, CWNetworkLev4Address *address)
{
       CWUseSockNtop(address, CWDebugLog("CWAddDiscoverACAddress: %s", str);
               );

       if (!CWSearchInList(*ACList, (void *)address, CWNetworkCompareAddress)) {
               CWDiscoverAC *AC;

	       if ((AC = rzalloc(NULL, CWDiscoverAC)) == NULL)
		       return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

               CW_COPY_NET_ADDR_PTR(&AC->address, address);
               AC->received = 0;

               if (!CWAddElementToList(ACList, AC)) {
                       CW_FREE_OBJECT(AC);
                       return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
               }
       } else
               CWDebugLog("Duplicate IP, already in List");

       return CW_TRUE;
}

static CWBool CWAddDiscoverAC(CWList *ACList, const char *host)
{

       struct addrinfo hints, *result, *rp;
       char serviceName[5];
       CWSocket sock;

       CWDebugLog("CWAddDiscoverAC: %s", host);

       if (host == NULL)
               return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

       CW_ZERO_MEMORY(&hints, sizeof(struct addrinfo));

#ifdef IPv6
       if (gNetworkPreferredFamily == CW_IPv6) {
               hints.ai_family = AF_INET6;
               hints.ai_flags = AI_V4MAPPED;
       } else {
               hints.ai_family = AF_INET;
       }
#else
       hints.ai_family = AF_INET;
#endif
       hints.ai_socktype = SOCK_DGRAM;

       snprintf(serviceName, sizeof(serviceName), "%d", CW_CONTROL_PORT);

       if (getaddrinfo(host, serviceName, &hints, &result) != 0)
               return CWErrorRaise(CW_ERROR_GENERAL, "Can't resolve hostname");

       for (rp = result; rp != NULL; rp = rp->ai_next) {
               sock = socket(rp->ai_family, rp->ai_socktype,
                            rp->ai_protocol);
               if (sock == -1)
                       continue;

               CWAddDiscoverACAddress(ACList, (CWNetworkLev4Address *)rp->ai_addr);
               close(sock);
       }
       freeaddrinfo(result);

       return CW_TRUE;
}

/*
 * Manage Discovery State
 */
CWStateTransition CWWTPEnterDiscovery()
{
	int i;

	CWLog("\n");
	CWLog("######### Discovery State #########");

	/* reset Discovery state */
	gCWDiscoveryCount = 0;

	CWNetworkCloseSocket(gWTPSocket);
	CWNetworkCloseSocket(gWTPDataSocket);
#ifndef CW_NO_DTLS
	CWSecurityDestroySession(&gWTPSession);
	CWSecurityDestroyContext(&gWTPSecurityContext);
#endif

	if (!CWErr(CWNetworkInitSocketClient(&gWTPSocket, NULL))) {
		return CW_QUIT;
	}

	if (DiscoveredACCount != 0 && CurrentDiscoveredAC < DiscoveredACCount) {
		/* reset to highes prio AC */
		CurrentDiscoveredAC = 0;

		/* try to select it*/
		if (CWWTPPickAC()) {
			CWUseSockNtop(&(gACInfoPtr->preferredAddress),
				      CWLog("Preferred AC: \"%s\", at address: %s", gACInfoPtr->name, str);
				);

			return CW_ENTER_JOIN;
		}
	}

	CWResetDiscoveredACAddresses();

	/*
	 * note: gCWACList can be freed and reallocated (reading from config file)
	 * at each transition to the discovery state to save memory space
	 */
	CWDebugLog("gCWACCount: %d", gCWACCount);
	for (i = 0; i < gCWACCount; i++)
		CWAddDiscoverAC(&ACList, gCWACList[i].address);

	/* wait a random time */
	sleep(CWRandomIntInRange(gCWDiscoveryInterval, gCWMaxDiscoveryInterval));

	CW_REPEAT_FOREVER {
		CWBool sentSomething = CW_FALSE;
		CWDiscoverAC *AC;

		/* we get no responses for a very long time */
		if (gCWDiscoveryCount == gCWMaxDiscoveries) {
			CWDestroyDiscoverACList(&ACList);
			return CW_ENTER_SULKING;
		}

		/* send Requests to one or more ACs */
		for (AC = CWListGetNext(ACList, CW_LIST_ITERATE_RESET);
		     AC != NULL;
		     AC = CWListGetNext(ACList, CW_LIST_ITERATE)) {

                        /* if this AC has responded to us... */
                        if (AC->received)
                                continue;

                        /* ...send a Discovery Request */

                        CWProtocolMessage *msgPtr = NULL;

                        /* get sequence number (and increase it) */
                        AC->seqNum = CWGetSeqNum();

                        if (!CWErr(CWAssembleDiscoveryRequest(&msgPtr, AC->seqNum)))
                                exit(1);

                        CWUseSockNtop(&AC->address, CWLog("WTP sends Discovery Request to: %s", str););
                        (void)CWErr(CWNetworkSendUnsafeUnconnected(gWTPSocket, &AC->address, (*msgPtr).msg, (*msgPtr).offset));

                        CW_FREE_PROTOCOL_MESSAGE(*msgPtr);
                        CW_FREE_OBJECT(msgPtr);

                        /*
                         * we sent at least one Request in this loop
                         * (even if we got an error sending it)
                         */
                        sentSomething = CW_TRUE;
		}

		/* All AC sent the response (so we didn't send any request) */
		if (!sentSomething && CWWTPFoundAnAC())
			break;

		gCWDiscoveryCount++;

		/* wait for Responses */
		if (CWErr(CWReadResponses()) && CWWTPFoundAnAC()) {
			/* we read at least one valid Discovery Response */
			break;
		}

		CWLog("WTP Discovery-To-Discovery (%d)", gCWDiscoveryCount);
	}

	CWLog("WTP Picks an AC");

	/* crit error: we should have received at least one Discovery Response */
	if (!CWWTPFoundAnAC()) {
		CWDestroyDiscoverACList(&ACList);
		CWLog("No Discovery response Received");
		return CW_ENTER_DISCOVERY;
	}

	if (!CWWTPPickAC())
		/* if the AC is multi homed, we select our favorite AC's interface */
		CWWTPPickACInterface();

	CWUseSockNtop(&(gACInfoPtr->preferredAddress),
		      CWLog("Preferred AC: \"%s\", at address: %s", gACInfoPtr->name, str);
	    );

	CWDestroyDiscoverACList(&ACList);
	return CW_ENTER_JOIN;
}

/*
 * Wait DiscoveryInterval time while receiving Discovery Responses.
 */
CWBool CWReadResponses()
{

	CWBool result = CW_FALSE;

	struct timeval timeout, before, after, delta, newTimeout;

	timeout.tv_sec = newTimeout.tv_sec = gCWDiscoveryInterval;
	timeout.tv_usec = newTimeout.tv_usec = 0;

	gettimeofday(&before, NULL);

	CW_REPEAT_FOREVER {
		/* check if something is available to read until newTimeout */
		if (CWNetworkTimedPollRead(gWTPSocket, &newTimeout)) {
			/* success
			 * if there was no error, raise a "success error", so we can easily handle
			 * all the cases in the switch
			 */
			CWErrorRaise(CW_ERROR_SUCCESS, NULL);
		}

		switch (CWErrorGetLastErrorCode()) {
		case CW_ERROR_TIME_EXPIRED:
			goto cw_time_over;
			break;

		case CW_ERROR_SUCCESS:
			result = CWReceiveDiscoveryResponse();
		case CW_ERROR_INTERRUPTED:
			/*
			 * something to read OR interrupted by the system
			 * wait for the remaining time (NetworkPoll will be recalled with the remaining time)
			 */
			gettimeofday(&after, NULL);

			CWTimevalSubtract(&delta, &after, &before);
			if (CWTimevalSubtract(&newTimeout, &timeout, &delta) == 1) {
				/* negative delta: time is over */
				goto cw_time_over;
			}
			break;
		default:
			CWErrorHandleLast();
			goto cw_error;
			break;
		}
	}
 cw_time_over:
	/* time is over */
	CWDebugLog("Timer expired during receive");
 cw_error:
	return result;
}

/*
 * Gets a datagram from network that should be a Discovery Response.
 */
CWBool CWReceiveDiscoveryResponse()
{
	unsigned char buf[CW_BUFFER_SIZE];
	CWDiscoverAC *AC;
	CWNetworkLev4Address addr;
	CWACInfoValues *ACInfoPtr;
	int seqNum;
	int readBytes;

	/* receive the datagram */
	if (!CWErr(CWNetworkReceiveUnsafe(gWTPSocket, buf, CW_BUFFER_SIZE - 1, 0, &addr, &readBytes))) {
		return CW_FALSE;
	}
	if (readBytes == 0)
		/* no error, but no data == orderly shutdown */
		return CW_FALSE;

	/* we received response from this address */
	CWUseSockNtop(&addr, CWLog("Discovery Response from:%s", str);
		);

	AC = (CWDiscoverAC *)CWSearchInList(ACList, (void *)&addr, CWNetworkCompareAddress);
	if (!AC)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "got discovery response from invalid address");

	if (!(ACInfoPtr = ralloc(NULL, CWACInfoValues)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	CW_COPY_NET_ADDR_PTR(&(ACInfoPtr->incomingAddress), &(addr));

	/* check if it is a valid Discovery Response */
	if (!CWErr(CWParseDiscoveryResponseMessage(buf, readBytes, &seqNum, ACInfoPtr))) {

		CW_FREE_OBJECT(ACInfoPtr);
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Received something different from a"
				    " Discovery Response while in Discovery State");

	}

	if (AC->seqNum != seqNum) {
		CW_FREE_OBJECT(ACInfoPtr);
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Sequence Number of Response doesn't macth Request");
	}
	AC->received = CW_TRUE;

	/* see if this AC is better than the one we have stored */
	CWWTPEvaluateAC(ACInfoPtr);

	return CW_TRUE;
}

void CWResetDiscoveredACAddresses()
{
	DiscoveredACCount = 0;
	CurrentDiscoveredAC = 0;
	CW_FREE_OBJECT(DiscoveredAC);
}

CWBool CWAddDiscoveredACAddress(unsigned char priority,
				int family,
				struct sockaddr *addr, socklen_t addrlen)
{
	CWDiscoveredAC *AC;

	if (DiscoveredAC == NULL ||
	    DiscoveredACCount % DAC_BLOCK_SIZE == 0) {
		DiscoveredAC = realloc(DiscoveredAC,
				       (DiscoveredACCount + DAC_BLOCK_SIZE) * sizeof(CWDiscoveredAC));
		CW_ON_ERROR(DiscoveredAC, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	}

	AC = DiscoveredAC + DiscoveredACCount;
	AC->priority = priority;

	switch (family) {
	case AF_INET: {
		struct sockaddr_in *sockaddr = (struct sockaddr_in *)&AC->address;

		sockaddr->sin_family = family;
		sockaddr->sin_port = htons(CW_CONTROL_PORT);
		CW_COPY_MEMORY(&sockaddr->sin_addr, addr, addrlen);

		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sockaddr = (struct sockaddr_in6 *)&AC->address;

		sockaddr->sin6_family = family;
		sockaddr->sin6_port = htons(CW_CONTROL_PORT);
		CW_COPY_MEMORY(&sockaddr->sin6_addr, addr, addrlen);

		break;
	}
	default:
		break;
	}

	DiscoveredACCount++;
	return CW_TRUE;
}

CWBool CWParseACAddressListWithPrio(CWProtocolMessage * msgPtr, int len)
{
	CWProtocolACAddressListWithPrio *elem =
		(CWProtocolACAddressListWithPrio *)CWProtocolRetrievePtr(msgPtr);

	if (len < sizeof(CWProtocolACAddressListWithPrio))
	    return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
				"Malformed AC Address with Priority Message Element");

	switch (elem->type) {
	case 0: /* DNS */
		/* FIXME: not handled yet, needs care with string length and async DNS lookup */
		break;

	case 1: /* IPv4 */
		if (len < sizeof(CWProtocolACAddressListWithPrio) + sizeof(struct in_addr))
			return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
					    "Malformed AC Address with Priority Message Element");

		CWAddDiscoveredACAddress(elem->priority, AF_INET,
					 (struct sockaddr *)&elem->data, sizeof(struct in_addr));
		break;

#ifdef IPv6
	case 2: /* IPv6 */
		if (len < sizeof(CWProtocolACAddressListWithPrio) + sizeof(struct in6_addr))
			return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
					    "Malformed AC Address with Priority Message Element");
		CWAddDiscoveredACAddress(elem->priority, AF_INET6,
					 (struct sockaddr *)&elem->data, sizeof(struct in6_addr));
		break;
#endif

	default:
		break;
	}

	msgPtr->offset += len;

	return CW_TRUE;
}

void CWWTPEvaluateAC(CWACInfoValues * ACInfoPtr)
{
	if (ACInfoPtr == NULL)
		return;

	if (gACInfoPtr == NULL) {
		/*
		 * this is the first AC we evaluate: so
		 *  it's the best AC we examined so far
		 */
		gACInfoPtr = ACInfoPtr;

	} else {

		CW_FREE_OBJECT(ACInfoPtr);
	}
	/*
	 * ... note: we can add our favourite algorithm to pick the best AC.
	 * We can also consider to remember all the Discovery Responses we
	 * received and not just the best.
	 */
}

int CWCompareDiscoveredAC(const void *__v1, const void *__v2)
{
	CWDiscoveredAC *v1 = (CWDiscoveredAC *)__v1;
	CWDiscoveredAC *v2 = (CWDiscoveredAC *)__v2;

	if (v1->priority > v2->priority) return 1;
	else if (v1->priority < v2->priority) return -1;
	return 0;
}

CWBool CWWTPPickAC()
{
	CWLog("CWWTPPickAC: %p, %d, %d", gACInfoPtr, DiscoveredACCount, CurrentDiscoveredAC);
	if (gACInfoPtr == NULL || DiscoveredACCount == 0 ||
	    CurrentDiscoveredAC >= DiscoveredACCount)
		return CW_FALSE;

	if (CurrentDiscoveredAC == 0)
		qsort(DiscoveredAC, DiscoveredACCount, sizeof(CWDiscoveredAC), CWCompareDiscoveredAC);

	CW_COPY_NET_ADDR_PTR(&(gACInfoPtr->preferredAddress), &DiscoveredAC[CurrentDiscoveredAC].address);
	CurrentDiscoveredAC++;

	CWUseSockNtop(&(gACInfoPtr->preferredAddress), CWDebugLog("NEW preferredAddress: %s", str); );

	return CW_TRUE;
}

/*
 * Pick one interface of the AC (easy if there is just one interface). The
 * current algorithm just pick the Ac with less WTP communicating with it. If
 * the addresses returned by the AC in the Discovery Response don't include the
 * address of the sender of the Discovery Response, we ignore the address in
 * the Response and use the one of the sender (maybe the AC sees garbage
 * address, i.e. it is behind a NAT).
 */
void CWWTPPickACInterface()
{
	int i, min;
	CWBool foundIncoming = CW_FALSE;
	if (gACInfoPtr == NULL)
		return;

	gACInfoPtr->preferredAddress.ss_family = AF_UNSPEC;

	if (gNetworkPreferredFamily == CW_IPv6) {
		goto cw_pick_IPv6;
	}

 cw_pick_IPv4:
	if (gACInfoPtr->IPv4Addresses == NULL || gACInfoPtr->IPv4AddressesCount <= 0)
		return;

	min = gACInfoPtr->IPv4Addresses[0].WTPCount;

	CW_COPY_NET_ADDR_PTR(&(gACInfoPtr->preferredAddress), &(gACInfoPtr->IPv4Addresses[0].addr));

	for (i = 1; i < gACInfoPtr->IPv4AddressesCount; i++) {

		if (!sock_cmp_addr((struct sockaddr *)&(gACInfoPtr->IPv4Addresses[i]),
				   (struct sockaddr *)&(gACInfoPtr->incomingAddress), sizeof(struct sockaddr_in)))
			foundIncoming = CW_TRUE;

		if (gACInfoPtr->IPv4Addresses[i].WTPCount < min) {

			min = gACInfoPtr->IPv4Addresses[i].WTPCount;
			CW_COPY_NET_ADDR_PTR(&(gACInfoPtr->preferredAddress), &(gACInfoPtr->IPv4Addresses[i].addr));
		}
	}

	if (!foundIncoming) {
		/*
		 * If the addresses returned by the AC in the Discovery
		 * Response don't include the address of the sender of the
		 * Discovery Response, we ignore the address in the Response
		 * and use the one of the sender (maybe the AC sees garbage
		 * address, i.e. it is behind a NAT).
		 */
		CW_COPY_NET_ADDR_PTR(&(gACInfoPtr->preferredAddress), &(gACInfoPtr->incomingAddress));
	}
	return;

 cw_pick_IPv6:
	/* CWDebugLog("Pick IPv6"); */
	if (gACInfoPtr->IPv6Addresses == NULL || gACInfoPtr->IPv6AddressesCount <= 0)
		goto cw_pick_IPv4;

	min = gACInfoPtr->IPv6Addresses[0].WTPCount;
	CW_COPY_NET_ADDR_PTR(&(gACInfoPtr->preferredAddress), &(gACInfoPtr->IPv6Addresses[0].addr));

	for (i = 1; i < gACInfoPtr->IPv6AddressesCount; i++) {

		/*
		 * if(!sock_cmp_addr(&(gACInfoPtr->IPv6Addresses[i]),
		 *           &(gACInfoPtr->incomingAddress),
		 *           sizeof(struct sockaddr_in6)))
		 *
		 *  foundIncoming = CW_TRUE;
		 */

		if (gACInfoPtr->IPv6Addresses[i].WTPCount < min) {
			min = gACInfoPtr->IPv6Addresses[i].WTPCount;
			CW_COPY_NET_ADDR_PTR(&(gACInfoPtr->preferredAddress), &(gACInfoPtr->IPv6Addresses[i].addr));
		}
	}
	/*
	   if(!foundIncoming) {
	   CW_COPY_NET_ADDR_PTR(&(gACInfoPtr->preferredAddress),
	   &(gACInfoPtr->incomingAddress));
	   }
	 */
	return;
}

CWBool CWAssembleDiscoveryRequest(CWProtocolMessage ** messagesPtr, int seqNum)
{

	CWProtocolMessage *msgElems = NULL;
	const int msgElemCount = 6;
	CWProtocolMessage *msgElemsBinding = NULL;
	const int msgElemBindingCount = 0;
	int k = -1;
	int fragmentsNum;

	if (messagesPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, msgElemCount, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
	    );

	/* Assemble Message Elements */

	if ((!(CWAssembleMsgElemDiscoveryType(&(msgElems[++k])))) ||
	    (!(CWAssembleMsgElemWTPBoardData(&(msgElems[++k])))) ||
	    (!(CWAssembleMsgElemWTPDescriptor(&(msgElems[++k])))) ||
	    (!(CWAssembleMsgElemWTPFrameTunnelMode(&(msgElems[++k])))) ||
	    (!(CWAssembleMsgElemWTPMACType(&(msgElems[++k])))) ||
	    (!(CWAssembleMsgElemWTPRadioInformation(&(msgElems[++k]))))
	    ) {
		int i;
		for (i = 0; i <= k; i++) {
			CW_FREE_PROTOCOL_MESSAGE(msgElems[i]);
		}
		CW_FREE_OBJECT(msgElems);
		/* error will be handled by the caller */
		return CW_FALSE;
	}

	return CWAssembleMessage(messagesPtr,
				 &fragmentsNum,
				 0,
				 seqNum,
				 CW_MSG_TYPE_VALUE_DISCOVERY_REQUEST,
				 msgElems, msgElemCount, msgElemsBinding, msgElemBindingCount);
}

/*
 *  Parse Discovery Response and return informations in *ACInfoPtr.
 */
CWBool CWParseDiscoveryResponseMessage(unsigned char *msg, int len, int *seqNumPtr, CWACInfoValues * ACInfoPtr)
{

	CWControlHeaderValues controlVal;
	CWProtocolTransportHeaderValues transportVal;
	int offsetTillMessages, i, j;
	char tmp_ABGNTypes;
	CWProtocolMessage completeMsg;

	if (msg == NULL || seqNumPtr == NULL || ACInfoPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CWDebugLog("Parse Discovery Response");

	completeMsg.msg = msg;
	completeMsg.offset = 0;

	CWBool dataFlag = CW_FALSE;
	/* will be handled by the caller */
	if (!(CWParseTransportHeader(&completeMsg, &transportVal, &dataFlag, NULL)))
		return CW_FALSE;
	/* will be handled by the caller */
	if (!(CWParseControlHeader(&completeMsg, &controlVal)))
		return CW_FALSE;

	/* different type */
	if (controlVal.messageTypeValue != CW_MSG_TYPE_VALUE_DISCOVERY_RESPONSE)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Message is not Discovery Response as Expected");

	*seqNumPtr = controlVal.seqNum;

	/* skip timestamp */
	controlVal.msgElemsLen -= CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;

	offsetTillMessages = completeMsg.offset;

	ACInfoPtr->IPv4AddressesCount = 0;
	ACInfoPtr->IPv6AddressesCount = 0;

	/* parse message elements */
	while ((completeMsg.offset - offsetTillMessages) < controlVal.msgElemsLen) {
		unsigned short int type = 0;	/* = CWProtocolRetrieve32(&completeMsg); */
		unsigned short int len = 0;	/* = CWProtocolRetrieve16(&completeMsg); */

		CWParseFormatMsgElem(&completeMsg, &type, &len);
		CWDebugLog("Parsing Message Element: %u, len: %u", type, len);

		switch (type) {
		case CW_MSG_ELEMENT_AC_DESCRIPTOR_CW_TYPE:
			/* will be handled by the caller */
			if (!(CWParseACDescriptor(&completeMsg, len, ACInfoPtr)))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_IEEE80211_WTP_RADIO_INFORMATION_CW_TYPE:
			/* will be handled by the caller */
			if (!(CWParseWTPRadioInformation_FromAC(&completeMsg, len, &tmp_ABGNTypes)))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_AC_NAME_CW_TYPE:
			/* will be handled by the caller */
			if (!(CWParseACName(&completeMsg, len, &(ACInfoPtr->name))))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_CW_CONTROL_IPV4_ADDRESS_CW_TYPE:
			/*
			 * just count how many interfacess we have,
			 * so we can allocate the array
			 */
			ACInfoPtr->IPv4AddressesCount++;
			completeMsg.offset += len;
			break;
		case CW_MSG_ELEMENT_CW_CONTROL_IPV6_ADDRESS_CW_TYPE:
			/*
			 * just count how many interfacess we have,
			 * so we can allocate the array
			 */
			ACInfoPtr->IPv6AddressesCount++;
			completeMsg.offset += len;
			break;
                case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_BW_CW_TYPE: {
                        unsigned int vendorId = CWProtocolRetrieve32(&completeMsg);
                        len -= 4;

                        CWDebugLog("Parsing Vendor Message Element, Vendor: %u", vendorId);
                        switch (vendorId) {
                        case CW_IANA_ENTERPRISE_NUMBER_VENDOR_TRAVELPING: {
                                unsigned short int vendorElemType = CWProtocolRetrieve16(&completeMsg);
                                len -= 2;

                                CWDebugLog("Parsing TP Vendor Message Element: %u", vendorElemType);
                                switch (vendorElemType) {
                                case CW_MSG_ELEMENT_TRAVELPING_AC_ADDRESS_LIST_WITH_PRIORITY:
					if (!(CWParseACAddressListWithPrio(&completeMsg, len)))
						return CW_FALSE;
					break;

                                default:
                                        CWLog("unknown TP Vendor Message Element: %u", vendorElemType);

                                        /* ignore unknown vendor extensions */
                                        completeMsg.offset += len;
                                        break;
                                }
                                break;
			}

                        default:
                                CWLog("unknown Vendor Message Element, Vendor: %u", vendorId);

                                /* ignore unknown vendor extensions */
                                completeMsg.offset += len;
                                break;
                        }
			break;
		}

		default:
			CWLog("unknown Message Element, Element; %u", type);

			/* ignore unknown IE */
			completeMsg.offset += len;
			break;
		}

		/* CWDebugLog("bytes: %d/%d",
		 *        (completeMsg.offset-offsetTillMessages),
		 *        controlVal.msgElemsLen);
		 */
	}

	if (completeMsg.offset != len)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");

	/* actually read each interface info */
	ACInfoPtr->IPv4Addresses = CW_CREATE_ARRAY_ERR(
			    ACInfoPtr->IPv4AddressesCount,
			    CWProtocolIPv4NetworkInterface, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
	    );

	if (ACInfoPtr->IPv6AddressesCount > 0) {

		ACInfoPtr->IPv6Addresses = CW_CREATE_ARRAY_ERR(
				    ACInfoPtr->IPv6AddressesCount,
				    CWProtocolIPv6NetworkInterface, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
		    );
	}

	i = 0, j = 0;

	completeMsg.offset = offsetTillMessages;
	while ((completeMsg.offset - offsetTillMessages) < controlVal.msgElemsLen) {

		unsigned short int type = 0;	/* = CWProtocolRetrieve32(&completeMsg); */
		unsigned short int len = 0;	/* = CWProtocolRetrieve16(&completeMsg); */

		CWParseFormatMsgElem(&completeMsg, &type, &len);

		switch (type) {
		case CW_MSG_ELEMENT_CW_CONTROL_IPV4_ADDRESS_CW_TYPE:
			/* will be handled by the caller */
			if (!(CWParseCWControlIPv4Addresses(&completeMsg, len, &(ACInfoPtr->IPv4Addresses[i]))))
				return CW_FALSE;
			i++;
			break;
		case CW_MSG_ELEMENT_CW_CONTROL_IPV6_ADDRESS_CW_TYPE:
			/* will be handled by the caller */
			if (!(CWParseCWControlIPv6Addresses(&completeMsg, len, &(ACInfoPtr->IPv6Addresses[j]))))
				return CW_FALSE;
			j++;
			break;

		default:
			completeMsg.offset += len;
			break;
		}
	}
	return CW_TRUE;
}
