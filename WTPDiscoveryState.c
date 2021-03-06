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
 * In addition, as a special exception, the copyright holders give permission to link the  *
 * code of portions of this program with the OpenSSL library under certain conditions as   *
 * described in each individual source file, and distribute linked combinations including  * 
 * the two. You must obey the GNU General Public License in all respects for all of the    *
 * code used other than OpenSSL.  If you modify file(s) with this exception, you may       *
 * extend this exception to your version of the file(s), but you are not obligated to do   *
 * so.  If you do not wish to do so, delete this exception statement from your version.    *
 * If you delete this exception statement from all source files in the program, then also  *
 * delete it here.                                                                         *
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
static CWBool CWReceiveDiscoveryResponse();
static void CWWTPEvaluateAC(CWACInfoValues * ACInfoPtr);
static CWBool CWReadResponses();
static CWBool CWAssembleDiscoveryRequest(CWTransportMessage *tm, int seqNum);
static CWBool CWParseDiscoveryResponseMessage(unsigned char *msg, int len, int *seqNumPtr, CWACInfoValues * ACInfoPtr);

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

               if (!CWAddElementToList(NULL, ACList, AC)) {
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

                        CWTransportMessage tm;

                        /* get sequence number (and increase it) */
                        AC->seqNum = CWGetSeqNum();

                        if (!CWErr(CWAssembleDiscoveryRequest(&tm, AC->seqNum)))
                                exit(1);

                        CWUseSockNtop(&AC->address, CWLog("WTP sends Discovery Request to: %s", str););
			CWLog("Data: %p, Length: %zd", tm.parts[0].data, tm.parts[0].pos);
                        (void)CWErr(CWNetworkSendUnsafeUnconnected(gWTPSocket, &AC->address, tm.parts[0].data, tm.parts[0].pos));

			CWReleaseTransportMessage(&tm);

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
	int seqNum = 0;
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

	if (!(ACInfoPtr = rzalloc(NULL, CWACInfoValues)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	CW_COPY_NET_ADDR_PTR(&(ACInfoPtr->incomingAddress), &(addr));

	/* check if it is a valid Discovery Response */
	if (!CWErr(CWParseDiscoveryResponseMessage(buf, readBytes, &seqNum, ACInfoPtr))) {
		ralloc_free(ACInfoPtr);
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

CWBool CWParseACAddressListWithPrio(CWProtocolMessage *pm, int len)
{
	CWProtocolACAddressListWithPrio *elem =
		(CWProtocolACAddressListWithPrio *)CWProtocolRetrievePtr(pm);

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

	pm->pos += len;

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

CWBool CWAssembleDiscoveryRequest(CWTransportMessage *tm, int seqNum)
{
	CWProtocolMessage msg;

	assert(tm != NULL);

	CWLog("Assembling Discovery Request...");
	if (!CWInitMessage(NULL, &msg, CW_MSG_TYPE_VALUE_DISCOVERY_REQUEST, seqNum) ||
	    !CWAssembleMsgElemDiscoveryType(NULL, &msg) ||
	    !CWAssembleMsgElemWTPBoardData(NULL, &msg) ||
	    !CWAssembleMsgElemWTPDescriptor(NULL, &msg) ||
	    !CWAssembleMsgElemWTPFrameTunnelMode(NULL, &msg) ||
	    !CWAssembleMsgElemWTPMACType(NULL, &msg) ||
	    !CWAssembleMsgElemWTPRadioInformation(NULL, &msg))
		goto cw_assemble_error;
	CWFinalizeMessage(&msg);

	if (!CWAssembleMessage(tm, 0, &msg))
		goto cw_assemble_error;

	CWLog("Discovery Request Assembled");
	return CW_TRUE;

 cw_assemble_error:
	CWReleaseMessage(&msg);
        return CW_FALSE;
}

/*
 *  Parse Discovery Response and return informations in *ACInfoPtr.
 */
CWBool CWParseDiscoveryResponseMessage(unsigned char *msg, int len, int *seqNumPtr, CWACInfoValues * ACInfoPtr)
{
	CWProtocolMessage pm;
	CWControlHeaderValues controlVal;
	CWProtocolTransportHeaderValues transportVal;
	char tmp_ABGNTypes;

	assert(msg != NULL);
	assert(seqNumPtr != NULL);
	assert(ACInfoPtr != NULL);

	CWDebugLog("Parse Discovery Response");

	CWInitTransportMessage(&pm, msg, len, 0);

	/* will be handled by the caller */
	if (!(CWParseTransportHeader(&pm, &transportVal, NULL)))
		return CW_FALSE;

	/* will be handled by the caller */
	if (!(CWParseControlHeader(&pm, &controlVal)))
		return CW_FALSE;

	/* different type */
	if (controlVal.messageTypeValue != CW_MSG_TYPE_VALUE_DISCOVERY_RESPONSE)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Message is not Discovery Response as Expected");

	*seqNumPtr = controlVal.seqNum;

	/* skip timestamp */
	controlVal.msgElemsLen -= CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;

	ACInfoPtr->IPv4AddressesCount = 0;
	ACInfoPtr->IPv6AddressesCount = 0;

	CWParseMessageElementStart(&pm);

	/* parse message elements */
	CWParseMessageElementWhile(&pm, controlVal.msgElemsLen) {
		unsigned short int type = 0;	/* = CWProtocolRetrieve32(&pm); */
		unsigned short int len = 0;	/* = CWProtocolRetrieve16(&pm); */

		CWParseFormatMsgElem(&pm, &type, &len);
		CWDebugLog("Parsing Message Element: %u, len: %u", type, len);

		switch (type) {
		case CW_MSG_ELEMENT_AC_DESCRIPTOR_CW_TYPE:
			if (!(CWParseACDescriptor(ACInfoPtr, &pm, len, ACInfoPtr)))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_IEEE80211_WTP_RADIO_INFORMATION_CW_TYPE:
			if (!(CWParseWTPRadioInformation_FromAC(&pm, len, &tmp_ABGNTypes)))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_AC_NAME_CW_TYPE:
			if (!(CWParseACName(ACInfoPtr, &pm, len, &(ACInfoPtr->name))))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_CW_CONTROL_IPV4_ADDRESS_CW_TYPE:
			if (!CWParseCWControlIPv4Addresses(ACInfoPtr, &pm, len, ACInfoPtr))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_CW_CONTROL_IPV6_ADDRESS_CW_TYPE:
			if (!CWParseCWControlIPv6Addresses(ACInfoPtr, &pm, len, ACInfoPtr))
				return CW_FALSE;
			break;
                case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_BW_CW_TYPE: {
			unsigned int vendorId = CWProtocolRetrieve32(&pm);
			unsigned short int vendorElemType = CWProtocolRetrieve16(&pm);
			len -= 6;

			CWDebugLog("Parsing Vendor Message Element, Vendor: %u, Element: %u", vendorId, vendorElemType);
                        switch (vendorId) {
                        case CW_IANA_ENTERPRISE_NUMBER_VENDOR_TRAVELPING: {
                                CWDebugLog("Parsing TP Vendor Message Element: %u", vendorElemType);
                                switch (vendorElemType) {
                                case CW_MSG_ELEMENT_TRAVELPING_AC_ADDRESS_LIST_WITH_PRIORITY:
					if (!(CWParseACAddressListWithPrio(&pm, len)))
						return CW_FALSE;
					break;

                                default:
                                        CWLog("unknown TP Vendor Message Element: %u", vendorElemType);

                                        /* ignore unknown vendor extensions */
					CWParseSkipElement(&pm, len);
                                        break;
                                }
                                break;
			}

                        default:
                                CWLog("unknown Vendor Message Element, Vendor: %u", vendorId);

                                /* ignore unknown vendor extensions */
				CWParseSkipElement(&pm, len);
                                break;
                        }
			break;
		}

		default:
			CWLog("unknown Message Element, Element; %u", type);

			/* ignore unknown IE */
			CWParseSkipElement(&pm, len);
			break;
		}

		/* CWDebugLog("bytes: %d/%d", (pm.offset-offsetTillMessages), controlVal.msgElemsLen); */
	}

	CWParseMessageElementEnd(&pm, controlVal.msgElemsLen);
	return CWParseTransportMessageEnd(&pm);
}
