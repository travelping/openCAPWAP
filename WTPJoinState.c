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

#include "CWWTP.h"

static CWBool gSuccessfulHandshake = CW_TRUE;
int gCWWaitJoin = CW_JOIN_INTERVAL_DEFAULT;

/*__________________________________________________________*/
/*  *******************___PROTOTYPES___*******************  */
void CWWTPWaitJoinExpired(CWTimerArg arg);
CWBool CWAssembleJoinRequest(CWProtocolMessage ** messagesPtr,
			     int *fragmentsNumPtr, int PMTU, int seqNum, CWList msgElemList);

CWBool CWParseJoinResponseMessage(unsigned char *msg, int len, int seqNum, CWProtocolJoinResponseValues * valuesPtr);

CWBool CWSaveJoinResponseMessage(CWProtocolJoinResponseValues * joinResponse);

/*_____________________________________________________*/
/*  *******************___FUNCTIONS___*******************  */

/*
 * Manage Join State.
 */
CWStateTransition CWWTPEnterJoin()
{
	CWTimerID waitJoinTimer;
	int seqNum;
	CWProtocolJoinResponseValues *values = NULL;

	CWLog("\n");
	CWLog("######### Join State #########");

	/* reset Join state */
	CWNetworkCloseSocket(gWTPSocket);
	CWNetworkCloseSocket(gWTPDataSocket);
#ifndef CW_NO_DTLS
	CWSecurityDestroySession(&gWTPSession);
	CWSecurityDestroyContext(&gWTPSecurityContext);
#endif

 cw_restart_join:
	ralloc_free(values);
	if (!(values = rzalloc(NULL, CWProtocolJoinResponseValues)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	/* Initialize gACInfoPtr */
	gACInfoPtr->ACIPv4ListInfo.ACIPv4ListCount = 0;
	gACInfoPtr->ACIPv4ListInfo.ACIPv4List = NULL;
	gACInfoPtr->ACIPv6ListInfo.ACIPv6ListCount = 0;
	gACInfoPtr->ACIPv6ListInfo.ACIPv6List = NULL;

	if ((waitJoinTimer = timer_add(gCWWaitJoin, 0, CWWTPWaitJoinExpired, NULL)) == -1)
		return CW_ENTER_DISCOVERY;

	if (gWTPForceACAddress != NULL) {
		if (!(gACInfoPtr = ralloc(NULL, CWACInfoValues)))
			return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

		CWNetworkGetAddressForHost(gWTPForceACAddress, &(gACInfoPtr->preferredAddress));
		gACInfoPtr->security = gWTPForceSecurity;
	}

	/* Init DTLS session */
	if (!CWErr(CWNetworkInitSocketClient(&gWTPSocket, &(gACInfoPtr->preferredAddress))))
		goto cw_join_err;

	if (!CWErr(CWNetworkInitSocketClientDataChannel(&gWTPDataSocket, &(gACInfoPtr->preferredAddress))))
		goto cw_join_err;

	CWLog("Initiate Data Channel");
	CWDebugLog("gWTPSocket:%d, gWTPDataSocket:%d", gWTPSocket, gWTPDataSocket);

#ifndef CW_NO_DTLS
	if (gACInfoPtr->security == CW_X509_CERTIFICATE) {
		if (!CWErr(CWSecurityInitContext(&gWTPSecurityContext,
						 "root.pem", "client.pem", "prova", CW_TRUE, NULL)))
			goto cw_join_err;
	} else {
		/* pre-shared keys */
		if (!CWErr(CWSecurityInitContext(&gWTPSecurityContext, NULL, NULL, NULL, CW_TRUE, NULL)))
			goto cw_join_err;
	}
#endif
	/* make sure we start with a fresh, empty list */
	CWLockSafeList(gPacketReceiveList);
	CWCleanSafeList(gPacketReceiveList, free);
	CWUnlockSafeList(gPacketReceiveList);

	CWThread thread_receiveFrame;
	if (!CWErr(CWCreateThread(&thread_receiveFrame, CWWTPReceiveDtlsPacket, (void *)(intptr_t)gWTPSocket))) {
		CWLog("Error starting Thread that receive DTLS packet");
		goto cw_join_err;
	}

	CWThread thread_receiveDataFrame;
	if (!CWErr(CWCreateThread(&thread_receiveDataFrame, CWWTPReceiveDataPacket, (void *)(intptr_t)gWTPDataSocket))) {
		CWLog("Error starting Thread that receive data packet");
		goto cw_join_err;
	}

#ifndef CW_NO_DTLS
	if (!CWErr(CWSecurityInitSessionClient(gWTPSocket,
					       &(gACInfoPtr->preferredAddress),
					       gPacketReceiveList, gWTPSecurityContext, &gWTPSession, &gWTPPathMTU)))
		goto cw_join_err;
#endif

	if (gCWForceMTU > 0)
		gWTPPathMTU = gCWForceMTU;

	CWDebugLog("Path MTU for this Session: %d", gWTPPathMTU);

	/* send Join Request */
	seqNum = CWGetSeqNum();

	if (!CWErr(CWWTPSendAcknowledgedPacket(seqNum,
					       NULL,
					       CWAssembleJoinRequest,
					       (void *)CWParseJoinResponseMessage,
					       (void *)CWSaveJoinResponseMessage, values)))
		goto cw_join_err;

	timer_rem(waitJoinTimer, NULL);
	if (!gSuccessfulHandshake)
		/* timer expired */
		goto cw_join_err;

	ralloc_free(values);

	CWLog("Join Completed");

	return CW_ENTER_CONFIGURE;

 cw_join_err:
	timer_rem(waitJoinTimer, NULL);
	CWNetworkCloseSocket(gWTPSocket);
	CWNetworkCloseSocket(gWTPDataSocket);
#ifndef CW_NO_DTLS
	CWSecurityDestroySession(&gWTPSession);
	CWSecurityDestroyContext(&gWTPSecurityContext);
#endif

	if (CWWTPPickAC())
		/* selected a new AC from the list */
		goto cw_restart_join;

	return CW_ENTER_DISCOVERY;

}

void CWWTPWaitJoinExpired(CWTimerArg arg)
{

	CWLog("WTP Wait Join Expired");
	CWDebugLog("gWTPSocket:%d, gWTPDataSocket:%d", gWTPSocket, gWTPDataSocket);
	gSuccessfulHandshake = CW_FALSE;

	CWNetworkCloseSocket(gWTPSocket);
	CWNetworkCloseSocket(gWTPDataSocket);
}

CWBool CWAssembleJoinRequest(CWProtocolMessage ** messagesPtr,
			     int *fragmentsNumPtr, int PMTU, int seqNum, CWList msgElemList)
{
	CWBool msgOK;
	CWProtocolMessage *msgElems = NULL;
	int msgElemCount = 9;
	CWProtocolMessage *msgElemsBinding = NULL;
	const int msgElemBindingCount = 0;
	int k = -1;

	if (messagesPtr == NULL || fragmentsNumPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	msgElems = CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElemCount, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
	    );

	CWLog("Sending Join Request...");

	/* Assemble Message Elements */
	msgOK = CWAssembleMsgElemLocationData(msgElems, &(msgElems[++k])) &&
		CWAssembleMsgElemWTPBoardData(msgElems, &(msgElems[++k])) &&
		CWAssembleMsgElemWTPDescriptor(msgElems, &(msgElems[++k])) &&
		CWAssembleMsgElemWTPIPv4Address(msgElems, &(msgElems[++k])) &&
		CWAssembleMsgElemWTPName(msgElems, &(msgElems[++k])) &&
		CWAssembleMsgElemSessionID(msgElems, &(msgElems[++k]), &gWTPSessionID[0]) &&
		CWAssembleMsgElemWTPFrameTunnelMode(msgElems, &(msgElems[++k])) &&
		CWAssembleMsgElemWTPMACType(msgElems, &(msgElems[++k])) &&
		CWAssembleMsgElemWTPRadioInformation(msgElems, &(msgElems[++k]));

	if (!msgOK) {
		CW_FREE_OBJECT(msgElems);
		/* error will be handled by the caller */
		return CW_FALSE;
	}

	return CWAssembleMessage(messagesPtr,
				 fragmentsNumPtr,
				 PMTU,
				 seqNum,
				 CW_MSG_TYPE_VALUE_JOIN_REQUEST,
				 msgElems, msgElemCount, msgElemsBinding, msgElemBindingCount);
}

/*
 * Parse Join Response and return informations in *valuesPtr.
 */
CWBool CWParseJoinResponseMessage(unsigned char *msg, int len, int seqNum, CWProtocolJoinResponseValues * valuesPtr)
{

	CWControlHeaderValues controlVal;
	CWProtocolMessage completeMsg;
	int offsetTillMessages;
	char tmp_ABGNTypes;
	if (msg == NULL || valuesPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CWDebugLog("Parsing Join Response...");

	completeMsg.msg = msg;
	completeMsg.offset = 0;

	/* error will be handled by the caller */
	if (!(CWParseControlHeader(&completeMsg, &controlVal)))
		return CW_FALSE;

	if (controlVal.messageTypeValue != CW_MSG_TYPE_VALUE_JOIN_RESPONSE)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Message is not Join Response as Expected");

	if (controlVal.seqNum != seqNum)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Different Sequence Number");

	/* skip timestamp */
	controlVal.msgElemsLen -= CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;

	offsetTillMessages = completeMsg.offset;

	/* Mauro */
	valuesPtr->ACInfoPtr.IPv4AddressesCount = 0;
	valuesPtr->ACInfoPtr.IPv6AddressesCount = 0;

	/* parse message elements */
	while ((completeMsg.offset - offsetTillMessages) < controlVal.msgElemsLen) {
		unsigned short int type = 0;
		unsigned short int len = 0;

		CWParseFormatMsgElem(&completeMsg, &type, &len);

		CWDebugLog("Parsing Message Element: %u, len: %u", type, len);
		/*
		   valuesPtr->ACInfoPtr.IPv4AddressesCount = 0;
		   valuesPtr->ACInfoPtr.IPv6AddressesCount = 0;
		 */
		valuesPtr->ACIPv4ListInfo.ACIPv4ListCount = 0;
		valuesPtr->ACIPv4ListInfo.ACIPv4List = NULL;
		valuesPtr->ACIPv6ListInfo.ACIPv6ListCount = 0;
		valuesPtr->ACIPv6ListInfo.ACIPv6List = NULL;

		switch (type) {
		case CW_MSG_ELEMENT_AC_DESCRIPTOR_CW_TYPE:
			/* will be handled by the caller */
			if (!(CWParseACDescriptor(valuesPtr, &completeMsg, len, &(valuesPtr->ACInfoPtr))))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_IEEE80211_WTP_RADIO_INFORMATION_CW_TYPE:
			/* will be handled by the caller */
			if (!CWParseWTPRadioInformation_FromAC(&completeMsg, len, &tmp_ABGNTypes))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_AC_IPV4_LIST_CW_TYPE:
			if (!(CWParseACIPv4List(valuesPtr, &completeMsg, len, &(valuesPtr->ACIPv4ListInfo))))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_AC_IPV6_LIST_CW_TYPE:
			if (!(CWParseACIPv6List(valuesPtr, &completeMsg, len, &(valuesPtr->ACIPv6ListInfo))))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_RESULT_CODE_CW_TYPE:
			if (!(CWParseResultCode(&completeMsg, len, &(valuesPtr->code))))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_AC_NAME_CW_TYPE:
			/* will be handled by the caller */
			if (!(CWParseACName(valuesPtr, &completeMsg, len, &(valuesPtr->ACInfoPtr.name))))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_CW_CONTROL_IPV4_ADDRESS_CW_TYPE:
			/*
			 * just count how many interfacess we
			 * have, so we can allocate the array
			 */
			valuesPtr->ACInfoPtr.IPv4AddressesCount++;
			completeMsg.offset += len;
			break;
		case CW_MSG_ELEMENT_CW_CONTROL_IPV6_ADDRESS_CW_TYPE:
			/*
			 * just count how many interfacess we
			 * have, so we can allocate the array
			 */
			valuesPtr->ACInfoPtr.IPv6AddressesCount++;
			completeMsg.offset += len;
			break;
			/*
			   case CW_MSG_ELEMENT_SESSION_ID_CW_TYPE:
			   if(!(CWParseSessionID(&completeMsg, len, valuesPtr))) return CW_FALSE;
			   break;
			 */
		default:
			return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Unrecognized Message Element");
		}

		/* CWDebugLog("bytes: %d/%d", (completeMsg.offset-offsetTillMessages), controlVal.msgElemsLen); */
	}

	if (completeMsg.offset != len)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");

	/* actually read each interface info */
	if (!(valuesPtr->ACInfoPtr.IPv4Addresses = ralloc_array(NULL, CWProtocolIPv4NetworkInterface,
								valuesPtr->ACInfoPtr.IPv4AddressesCount)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	if (valuesPtr->ACInfoPtr.IPv6AddressesCount > 0) {

		if (!(valuesPtr->ACInfoPtr.IPv6Addresses = ralloc_array(NULL, CWProtocolIPv6NetworkInterface,
									valuesPtr->ACInfoPtr.IPv6AddressesCount)))
			return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
	}

	int i = 0;
	int j = 0;

	completeMsg.offset = offsetTillMessages;
	while ((completeMsg.offset - offsetTillMessages) < controlVal.msgElemsLen) {
		unsigned short int type = 0;	/* = CWProtocolRetrieve32(&completeMsg); */
		unsigned short int len = 0;	/* = CWProtocolRetrieve16(&completeMsg); */

		CWParseFormatMsgElem(&completeMsg, &type, &len);

		switch (type) {
		case CW_MSG_ELEMENT_CW_CONTROL_IPV4_ADDRESS_CW_TYPE:
			/* will be handled by the caller */
			if (!(CWParseCWControlIPv4Addresses(&completeMsg,
							    len, &(valuesPtr->ACInfoPtr.IPv4Addresses[i]))))
				return CW_FALSE;
			i++;
			break;
		case CW_MSG_ELEMENT_CW_CONTROL_IPV6_ADDRESS_CW_TYPE:
			/* will be handled by the caller */
			if (!(CWParseCWControlIPv6Addresses(&completeMsg,
							    len, &(valuesPtr->ACInfoPtr.IPv6Addresses[j]))))
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

CWBool CWSaveJoinResponseMessage(CWProtocolJoinResponseValues * joinResponse)
{

	if (joinResponse == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if ((joinResponse->code == CW_PROTOCOL_SUCCESS) || (joinResponse->code == CW_PROTOCOL_SUCCESS_NAT)) {

		if (gACInfoPtr == NULL)
			return CWErrorRaise(CW_ERROR_NEED_RESOURCE, NULL);

		gACInfoPtr->stations = joinResponse->ACInfoPtr.stations;
		gACInfoPtr->limit = joinResponse->ACInfoPtr.limit;
		gACInfoPtr->activeWTPs = joinResponse->ACInfoPtr.activeWTPs;
		gACInfoPtr->maxWTPs = joinResponse->ACInfoPtr.maxWTPs;
		gACInfoPtr->security = joinResponse->ACInfoPtr.security;
		gACInfoPtr->RMACField = joinResponse->ACInfoPtr.RMACField;

		ralloc_steal(gACInfoPtr, joinResponse->ACInfoPtr.vendorInfos.vendorInfos);
		ralloc_free(gACInfoPtr->vendorInfos.vendorInfos);
		gACInfoPtr->vendorInfos.vendorInfos = joinResponse->ACInfoPtr.vendorInfos.vendorInfos;

		if (joinResponse->ACIPv4ListInfo.ACIPv4ListCount > 0) {
			gACInfoPtr->ACIPv4ListInfo.ACIPv4ListCount =
				joinResponse->ACIPv4ListInfo.ACIPv4ListCount;

			ralloc_steal(gACInfoPtr, joinResponse->ACIPv4ListInfo.ACIPv4List);
			ralloc_free(gACInfoPtr->ACIPv4ListInfo.ACIPv4List);
			gACInfoPtr->ACIPv4ListInfo.ACIPv4List = joinResponse->ACIPv4ListInfo.ACIPv4List;
		}

		if (joinResponse->ACIPv6ListInfo.ACIPv6ListCount > 0) {
			gACInfoPtr->ACIPv6ListInfo.ACIPv6ListCount =
				joinResponse->ACIPv6ListInfo.ACIPv6ListCount;

			ralloc_steal(gACInfoPtr, joinResponse->ACIPv6ListInfo.ACIPv6List);
			ralloc_free(gACInfoPtr->ACIPv6ListInfo.ACIPv6List);
			gACInfoPtr->ACIPv6ListInfo.ACIPv6List = joinResponse->ACIPv6ListInfo.ACIPv6List;
		}

		/*
		 * This field name was allocated for storing the AC name; however, it
		 * doesn't seem to be used and it is certainly lost when we exit
		 * CWWTPEnterJoin() as joinResponse is actually a local variable of that
		 * function.
		 *
		 * Thus, it seems good to free it now.
		 *
		 * BUG ML03
		 * 16/10/2009 - Donato Capitella
		 */
		CW_FREE_OBJECT(joinResponse->ACInfoPtr.name);
		/* BUG ML08 */
		CW_FREE_OBJECT(joinResponse->ACInfoPtr.IPv4Addresses);

		CWDebugLog("Join Response Saved");
		return CW_TRUE;
	} else {
		CWDebugLog("Join Response said \"Failure\"");
		return CW_FALSE;
	}
}
