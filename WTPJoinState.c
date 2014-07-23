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

#include "CWWTP.h"

static CWBool gSuccessfulHandshake = CW_TRUE;
int gCWWaitJoin = CW_JOIN_INTERVAL_DEFAULT;

/*__________________________________________________________*/
/*  *******************___PROTOTYPES___*******************  */
static void CWWTPWaitJoinExpired(CWTimerArg arg);
static CWBool CWAssembleJoinRequest(CWTransportMessage *tm, int PMTU, int seqNum, CWList msgElemList);
static CWBool CWParseJoinResponseMessage(CWProtocolMessage *pm, int seqNum, void *values);
static CWBool CWSaveJoinResponseMessage(void *values);

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
	gSuccessfulHandshake = CW_TRUE;

	ralloc_free(values);
	if (!(values = rzalloc(NULL, CWProtocolJoinResponseValues)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	/* Initialize gACInfoPtr */
	gACInfoPtr->ACIPv4ListInfo.ACIPv4ListCount = 0;
	gACInfoPtr->ACIPv4ListInfo.ACIPv4List = NULL;
	gACInfoPtr->ACIPv6ListInfo.ACIPv6ListCount = 0;
	gACInfoPtr->ACIPv6ListInfo.ACIPv6List = NULL;

	if ((waitJoinTimer = timer_add(gCWWaitJoin, 0, CWWTPWaitJoinExpired, NULL)) == -1) {
		ralloc_free(values);
		return CW_ENTER_DISCOVERY;
	}

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
	CWCleanSafeList(gPacketReceiveList, ralloc_free);
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
					       CWParseJoinResponseMessage,
					       CWSaveJoinResponseMessage, values)))
		goto cw_join_err;

	CWDebugLog("Join Handshake State: %d", gSuccessfulHandshake);
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

	ralloc_free(values);
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

CWBool CWAssembleJoinRequest(CWTransportMessage *tm, int PMTU, int seqNum, CWList msgElemList)
{
	CWProtocolMessage msg;

	assert(tm != NULL);

	CWLog("Sending Join Request...");

	/* Assemble Message Elements */
	if (!CWInitMessage(NULL, &msg, CW_MSG_TYPE_VALUE_JOIN_REQUEST, seqNum) ||
	    !CWAssembleMsgElemLocationData(NULL, &msg) ||
	    !CWAssembleMsgElemWTPBoardData(NULL, &msg) ||
	    !CWAssembleMsgElemWTPDescriptor(NULL, &msg) ||
	    !CWAssembleMsgElemWTPIPv4Address(NULL, &msg) ||
	    !CWAssembleMsgElemWTPName(NULL, &msg) ||
	    !CWAssembleMsgElemSessionID(NULL, &msg, &gWTPSessionID[0]) ||
	    !CWAssembleMsgElemWTPFrameTunnelMode(NULL, &msg) ||
	    !CWAssembleMsgElemWTPMACType(NULL, &msg) ||
	    !CWAssembleMsgElemWTPRadioInformation(NULL, &msg))
		goto cw_assemble_error;
	CWFinalizeMessage(&msg);

	if (!CWAssembleMessage(tm, PMTU, &msg))
		goto cw_assemble_error;

	return CW_TRUE;

 cw_assemble_error:
	CWReleaseMessage(&msg);
        return CW_FALSE;
}

/*
 * Parse Join Response and return informations in *valuesPtr.
 */
CWBool CWParseJoinResponseMessage(CWProtocolMessage *pm, int seqNum, void *values)
{
	CWProtocolJoinResponseValues *jr = (CWProtocolJoinResponseValues *)values;
	CWControlHeaderValues controlVal;
	char tmp_ABGNTypes;

	assert(pm != NULL);
	assert(values != NULL);

	CWDebugLog("Parsing Join Response...");

	/* error will be handled by the caller */
	if (!(CWParseControlHeader(pm, &controlVal)))
		return CW_FALSE;

	if (controlVal.messageTypeValue != CW_MSG_TYPE_VALUE_JOIN_RESPONSE)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Message is not Join Response as Expected");

	if (controlVal.seqNum != seqNum)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Different Sequence Number");

	/* skip timestamp */
	controlVal.msgElemsLen -= CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;

	jr->ACInfoPtr.IPv4AddressesCount = 0;
	jr->ACInfoPtr.IPv6AddressesCount = 0;

	jr->ACIPv4ListInfo.ACIPv4ListCount = 0;
	jr->ACIPv4ListInfo.ACIPv4List = NULL;
	jr->ACIPv6ListInfo.ACIPv6ListCount = 0;
	jr->ACIPv6ListInfo.ACIPv6List = NULL;

	CWParseMessageElementStart(pm);

	/* parse message elements */
	CWParseMessageElementWhile(pm, controlVal.msgElemsLen) {
		unsigned short int type = 0;
		unsigned short int len = 0;

		CWParseFormatMsgElem(pm, &type, &len);

		CWDebugLog("Parsing Message Element: %u, len: %u", type, len);

		switch (type) {
		case CW_MSG_ELEMENT_AC_DESCRIPTOR_CW_TYPE:
			/* will be handled by the caller */
			if (!(CWParseACDescriptor(jr, pm, len, &(jr->ACInfoPtr))))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_IEEE80211_WTP_RADIO_INFORMATION_CW_TYPE:
			/* will be handled by the caller */
			if (!CWParseWTPRadioInformation_FromAC(pm, len, &tmp_ABGNTypes))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_AC_IPV4_LIST_CW_TYPE:
			if (!(CWParseACIPv4List(jr, pm, len, &(jr->ACIPv4ListInfo))))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_AC_IPV6_LIST_CW_TYPE:
			if (!(CWParseACIPv6List(jr, pm, len, &(jr->ACIPv6ListInfo))))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_RESULT_CODE_CW_TYPE:
			if (!(CWParseResultCode(pm, len, &(jr->code))))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_AC_NAME_CW_TYPE:
			if (!(CWParseACName(jr, pm, len, &(jr->ACInfoPtr.name))))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_CW_CONTROL_IPV4_ADDRESS_CW_TYPE:
			if (!CWParseCWControlIPv4Addresses(jr, pm, len, &jr->ACInfoPtr))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_CW_CONTROL_IPV6_ADDRESS_CW_TYPE:
			if (!CWParseCWControlIPv6Addresses(jr, pm, len, &jr->ACInfoPtr))
				return CW_FALSE;
			break;
#if 0
		case CW_MSG_ELEMENT_SESSION_ID_CW_TYPE:
			if (!CWParseSessionID(pm, len, jr))
				return CW_FALSE;
			break;
#endif
		default:
			CWLog("unknown Message Element, Element; %u", type);

			/* ignore unknown IE */
			CWParseSkipElement(pm, len);
		}

		/* CWDebugLog("bytes: %d/%d", (pm.offset-offsetTillMessages), controlVal.msgElemsLen); */
	}

	CWParseMessageElementEnd(pm, controlVal.msgElemsLen);
	return CWParseTransportMessageEnd(pm);
}

CWBool CWSaveJoinResponseMessage(void *values)
{
	CWProtocolJoinResponseValues *jr = (CWProtocolJoinResponseValues *)values;

	assert(values != NULL);

	if ((jr->code == CW_PROTOCOL_SUCCESS) || (jr->code == CW_PROTOCOL_SUCCESS_NAT)) {
		if (gACInfoPtr == NULL)
			return CWErrorRaise(CW_ERROR_NEED_RESOURCE, NULL);

		gACInfoPtr->stations = jr->ACInfoPtr.stations;
		gACInfoPtr->limit = jr->ACInfoPtr.limit;
		gACInfoPtr->activeWTPs = jr->ACInfoPtr.activeWTPs;
		gACInfoPtr->maxWTPs = jr->ACInfoPtr.maxWTPs;
		gACInfoPtr->security = jr->ACInfoPtr.security;
		gACInfoPtr->RMACField = jr->ACInfoPtr.RMACField;

		ralloc_steal(gACInfoPtr, jr->ACInfoPtr.vendorInfos.vendorInfos);
		ralloc_free(gACInfoPtr->vendorInfos.vendorInfos);
		gACInfoPtr->vendorInfos.vendorInfos = jr->ACInfoPtr.vendorInfos.vendorInfos;

		if (jr->ACIPv4ListInfo.ACIPv4ListCount > 0) {
			gACInfoPtr->ACIPv4ListInfo.ACIPv4ListCount =
				jr->ACIPv4ListInfo.ACIPv4ListCount;

			ralloc_steal(gACInfoPtr, jr->ACIPv4ListInfo.ACIPv4List);
			ralloc_free(gACInfoPtr->ACIPv4ListInfo.ACIPv4List);
			gACInfoPtr->ACIPv4ListInfo.ACIPv4List = jr->ACIPv4ListInfo.ACIPv4List;
		}

		if (jr->ACIPv6ListInfo.ACIPv6ListCount > 0) {
			gACInfoPtr->ACIPv6ListInfo.ACIPv6ListCount =
				jr->ACIPv6ListInfo.ACIPv6ListCount;

			ralloc_steal(gACInfoPtr, jr->ACIPv6ListInfo.ACIPv6List);
			ralloc_free(gACInfoPtr->ACIPv6ListInfo.ACIPv6List);
			gACInfoPtr->ACIPv6ListInfo.ACIPv6List = jr->ACIPv6ListInfo.ACIPv6List;
		}

		/*
		 * This field name was allocated for storing the AC name; however, it
		 * doesn't seem to be used and it is certainly lost when we exit
		 * CWWTPEnterJoin() as v is actually a local variable of that
		 * function.
		 *
		 * Thus, it seems good to free it now.
		 *
		 * BUG ML03
		 * 16/10/2009 - Donato Capitella
		 */
		CW_FREE_OBJECT(jr->ACInfoPtr.name);
		/* BUG ML08 */
		CW_FREE_OBJECT(jr->ACInfoPtr.IPv4Addresses);

		CWDebugLog("Join Response Saved");
		return CW_TRUE;
	} else {
		CWDebugLog("Join Response said \"Failure\"");
		return CW_FALSE;
	}
}
