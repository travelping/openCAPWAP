/************************************************************************************************
 * Copyright (c) 2006-2009 Laboratorio di Sistemi di Elaborazione e Bioingegneria Informatica   *
 *                          Universita' Campus BioMedico - Italy                                *
 *                                                                                              *
 * This program is free software; you can redistribute it and/or modify it under the terms      *
 * of the GNU General Public License as published by the Free Software Foundation; either       *
 * version 2 of the License, or (at your option) any later version.                             *
 *                                                                                              *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY              *
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A         *
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.                     *
 *                                                                                              *
 * You should have received a copy of the GNU General Public License along with this            *
 * program; if not, write to the:                                                               *
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,                         *
 * MA  02111-1307, USA.                                                                         *
 *                                                                                              *
 * -------------------------------------------------------------------------------------------- *
 * Project:  Capwap                                                                             *
 *                                                                                              *
 * Authors : Ludovico Rossi (ludo@bluepixysw.com)                                               *
 *           Del Moro Andrea (andrea_delmoro@libero.it)                                         *
 *           Giovannini Federica (giovannini.federica@gmail.com)                                *
 *           Massimo Vellucci (m.vellucci@unicampus.it)                                         *
 *           Mauro Bisson (mauro.bis@gmail.com)                                                 *
 *           Antonio Davoli (antonio.davoli@gmail.com)                                          *
 ************************************************************************************************/
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>

#include "CWWTP.h"
#include "CWVendorPayloads.h"
#include "WTPipcHostapd.h"
#include "WTPmacFrameReceive.h"
#include "common.h"
#include "ieee802_11_defs.h"
#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

CWBool CWWTPManageGenericRunMessage(CWProtocolMessage * msgPtr);

CWBool CWWTPCheckForBindingFrame();

CWBool CWWTPCheckForWTPEventRequest();
CWBool CWParseWTPEventResponseMessage(unsigned char *msg, int len, int seqNum, void *values);

CWBool CWSaveWTPEventResponseMessage(void *WTPEventResp);

CWBool CWAssembleEchoRequest(CWProtocolMessage ** messagesPtr,
			     int *fragmentsNumPtr, int PMTU, int seqNum, CWList msgElemList);
CWBool CWParseEchoResponse(unsigned char *msg, int len);

CWBool CWParseConfigurationUpdateRequest(unsigned char *msg, int len,
					 CWProtocolConfigurationUpdateRequestValues * valuesPtr,
					 int *updateRequestType);

CWBool CWSaveConfigurationUpdateRequest(CWProtocolConfigurationUpdateRequestValues * valuesPtr,
					CWProtocolResultCode * resultCode, int *updateRequestType);

CWBool CWAssembleConfigurationUpdateResponse(CWProtocolMessage ** messagesPtr,
					     int *fragmentsNumPtr,
					     int PMTU,
					     int seqNum,
					     CWProtocolResultCode resultCode,
					     CWProtocolConfigurationUpdateRequestValues values);

CWBool CWSaveClearConfigurationRequest(CWProtocolResultCode * resultCode);

CWBool CWAssembleClearConfigurationResponse(CWProtocolMessage ** messagesPtr,
					    int *fragmentsNumPtr,
					    int PMTU, int seqNum, CWProtocolResultCode resultCode);

CWBool CWAssembleStationConfigurationResponse(CWProtocolMessage ** messagesPtr,
					      int *fragmentsNumPtr,
					      int PMTU, int seqNum, CWProtocolResultCode resultCode);
CWBool CWAssembleWLANConfigurationResponse(CWProtocolMessage ** messagesPtr,
					   int *fragmentsNumPtr, int PMTU, int seqNum, CWProtocolResultCode resultCode);

CWBool CWParseStationConfigurationRequest(unsigned char *msg, int len);
CWBool CWParseWLANConfigurationRequest(unsigned char *msg, int len);

void CWConfirmRunStateToACWithEchoRequest();

static void CWWTPHeartBeatTimerExpiredHandler(void *arg);
static void CWWTPKeepAliveDataTimerExpiredHandler(void *arg);
static void CWWTPNeighborDeadTimerExpired(void *arg);
static CWBool CWResetHeartbeatTimer();
static CWBool CWStopDataChannelKeepAlive();
static CWBool CWResetDataChannelKeepAlive();
static CWBool CWResetNeighborDeadTimer();

CWTimerID gCWHeartBeatTimerID;
CWTimerID gCWKeepAliveTimerID;
CWTimerID gCWNeighborDeadTimerID;
CWBool gNeighborDeadTimerSet = CW_FALSE;

struct timeval gEchoLatency = {0,0};

/* record the state of the control and data channel keep alives */
static enum tRunChannelState {
	CS_OK,
	CS_FAILED,
	CS_TIMEOUT
} lRunChannelState;
static void setRunChannelState(enum tRunChannelState newState);

/*
 * set the gRunChannelState and notify the run thread
 */
static void setRunChannelState(enum tRunChannelState newState)
{
	CWThreadMutexLock(&gInterfaceMutex);

	lRunChannelState = newState;

	CWSignalThreadCondition(&gInterfaceWait);
	CWThreadMutexUnlock(&gInterfaceMutex);
}

/*
 * Manage DTLS packets.
 */
CW_THREAD_RETURN_TYPE CWWTPReceiveDtlsPacket(void *arg)
{

	int readBytes;
	char buf[CW_BUFFER_SIZE];
	CWSocket sockDTLS = (intptr_t)arg;
	CWNetworkLev4Address addr;
	char *pData;

	CW_REPEAT_FOREVER {
		CWDebugLog("CWWTPReceiveDtlsPacket: recvfrom on DtlsSocket %d", sockDTLS);
		if (!CWErr(CWNetworkReceiveUnsafe(sockDTLS, buf, CW_BUFFER_SIZE - 1, 0, &addr, &readBytes))) {
			CWDebugLog("CWWTPReceiveDtlsPacket Error: %d", CWErrorGetLastErrorCode());
			if (CWErrorGetLastErrorCode() == CW_ERROR_INTERRUPTED)
				continue;

			break;
		}
		/* Clone data packet */
		pData = CW_CREATE_OBJECT_SIZE_ERR(readBytes, {
					  CWLog("Out Of Memory");
					  return NULL;
					  }
		);
		memcpy(pData, buf, readBytes);

		CWLockSafeList(gPacketReceiveList);
		CWAddElementToSafeListTailwitDataFlag(gPacketReceiveList, pData, readBytes, CW_FALSE);
		CWUnlockSafeList(gPacketReceiveList);

		if (readBytes == 0)
			/* no error, but no data == orderly shutdown
			 * the zero lenght payload packet signals the BIO read to terminate */
			break;
	}

	CWLog("CWWTPReceiveDtlsPacket:: exited");
	return NULL;
}

extern int gRawSock;
/*
 * Manage data packets.
 */

#define HLEN_80211  24
int isEAPOL_Frame(unsigned char *buf, unsigned int len)
{
	unsigned char rfc1042_header[6] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };
	int i;

	for (i = 0; i < 6; i++)
		if (rfc1042_header[i] != buf[i + HLEN_80211])
			return 0;
	return 1;
}

CW_THREAD_RETURN_TYPE CWWTPReceiveDataPacket(void *arg)
{
	int readBytes;
	unsigned char buf[CW_BUFFER_SIZE];
	struct sockaddr_ll rawSockaddr;
	CWNetworkLev4Address addr;
	CWList fragments = NULL;
	CWProtocolMessage msgPtr;
	CWBool dataFlag = CW_TRUE;

	memset(&rawSockaddr, 0, sizeof(rawSockaddr));

	rawSockaddr.sll_family = AF_PACKET;
	rawSockaddr.sll_protocol = htons(ETH_P_ALL);
	rawSockaddr.sll_ifindex = if_nametoindex(gRadioInterfaceName_0);
	rawSockaddr.sll_pkttype = PACKET_OTHERHOST;
	rawSockaddr.sll_halen = ETH_ALEN;

	CW_REPEAT_FOREVER {
		if (!CWErr(CWNetworkReceiveUnsafe(gWTPDataSocket, buf, CW_BUFFER_SIZE - 1, 0, &addr, &readBytes))) {

			if (CWErrorGetLastErrorCode() == CW_ERROR_INTERRUPTED)
				continue;

			break;
		}
		if (readBytes == 0)
			/* no error, but no data == orderly shutdown */
			break;

		msgPtr.msg = NULL;
		msgPtr.offset = 0;

		if (!CWProtocolParseFragment(buf, readBytes, &fragments, &msgPtr, &dataFlag, NULL)) {
			if (CWErrorGetLastErrorCode()) {
				CWErrorCode error;
				error = CWErrorGetLastErrorCode();
				switch (error) {
				case CW_ERROR_SUCCESS:{
						CWDebugLog("ERROR: Success");
						break;
					}
				case CW_ERROR_OUT_OF_MEMORY:{
						CWDebugLog("ERROR: Out of Memory");
						break;
					}
				case CW_ERROR_WRONG_ARG:{
						CWDebugLog("ERROR: Wrong Argument");
						break;
					}
				case CW_ERROR_INTERRUPTED:{
						CWDebugLog("ERROR: Interrupted");
						break;
					}
				case CW_ERROR_NEED_RESOURCE:{
						CWDebugLog("ERROR: Need Resource");
						break;
					}
				case CW_ERROR_COMUNICATING:{
						CWDebugLog("ERROR: Comunicating");
						break;
					}
				case CW_ERROR_CREATING:{
						CWDebugLog("ERROR: Creating");
						break;
					}
				case CW_ERROR_GENERAL:{
						CWDebugLog("ERROR: General");
						break;
					}
				case CW_ERROR_OPERATION_ABORTED:{
						CWDebugLog("ERROR: Operation Aborted");
						break;
					}
				case CW_ERROR_SENDING:{
						CWDebugLog("ERROR: Sending");
						break;
					}
				case CW_ERROR_RECEIVING:{
						CWDebugLog("ERROR: Receiving");
						break;
					}
				case CW_ERROR_INVALID_FORMAT:{
						CWDebugLog("ERROR: Invalid Format");
						break;
					}
				case CW_ERROR_TIME_EXPIRED:{
						CWDebugLog("ERROR: Time Expired");
						break;
					}
				case CW_ERROR_NONE:{
						CWDebugLog("ERROR: None");
						break;
					}
				}
			}
		} else {
			CWResetNeighborDeadTimer();

			switch (msgPtr.data_msgType) {
			case CW_DATA_MSG_KEEP_ALIVE_TYPE:
			{
				unsigned char *valPtr = NULL;

				unsigned short int elemType = 0;
				unsigned short int elemLen = 0;

				CWDebugLog("Got KeepAlive len:%d from AC", msgPtr.offset);
				msgPtr.offset = 0;
				CWParseFormatMsgElem(&msgPtr, &elemType, &elemLen);
				valPtr = CWParseSessionID(&msgPtr, elemLen);
				CW_FREE_OBJECT(valPtr);
				break;
			}

			case CW_IEEE_802_3_FRAME_TYPE:
			{
				CWDebugLog("Got 802.3 len:%d from AC", msgPtr.offset);

				/*MAC - begin */
				rawSockaddr.sll_addr[0] = msgPtr.msg[0];
				rawSockaddr.sll_addr[1] = msgPtr.msg[1];
				rawSockaddr.sll_addr[2] = msgPtr.msg[2];
				rawSockaddr.sll_addr[3] = msgPtr.msg[3];
				rawSockaddr.sll_addr[4] = msgPtr.msg[4];
				rawSockaddr.sll_addr[5] = msgPtr.msg[5];
				/*MAC - end */
				rawSockaddr.sll_addr[6] = 0x00;	/*not used */
				rawSockaddr.sll_addr[7] = 0x00;	/*not used */

				rawSockaddr.sll_hatype = htons(msgPtr.msg[12] << 8 | msgPtr.msg[13]);

				if (sendto(gRawSock, msgPtr.msg, msgPtr.offset, 0, (struct sockaddr *)&rawSockaddr,
					   sizeof(rawSockaddr)) < 0)
					CWLog("Sending a data packet failed with: %s", strerror(errno));
				break;
			}

			case CW_IEEE_802_11_FRAME_TYPE:
			{
				struct ieee80211_hdr *hdr;
				u16 fc;
				hdr = (struct ieee80211_hdr *)msgPtr.msg;
				fc = le_to_host16(hdr->frame_control);

				if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_MGMT
				    || isEAPOL_Frame(msgPtr.msg, msgPtr.offset)) {
					CWDebugLog("Got 802.11 Management Packet (stype=%d) from AC(hostapd) len:%d",
						   WLAN_FC_GET_STYPE(fc), msgPtr.offset);
					CWWTPsend_data_to_hostapd(msgPtr.msg, msgPtr.offset);

				} else if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_DATA) {

					if (WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_NULLFUNC) {

						CWDebugLog("Got 802.11 Data Packet (stype=%d) from AC(hostapd) len:%d",
							   WLAN_FC_GET_STYPE(fc), msgPtr.offset);
						CWWTPsend_data_to_hostapd(msgPtr.msg, msgPtr.offset);

					} else {

						CWDebugLog("Got 802.11 Data Packet (stype=%d) from AC(hostapd) len:%d",
							   WLAN_FC_GET_STYPE(fc), msgPtr.offset);
						CWWTPSendFrame(msgPtr.msg, msgPtr.offset);

					}

				} else {
					CWLog("Control/Unknow Type type=%d", WLAN_FC_GET_TYPE(fc));
				}
				break;
			}

			default:
				CWLog("Unknow data_msgType");
				break;
			}
			CW_FREE_PROTOCOL_MESSAGE(msgPtr);
		}
	}

	CWLog("CWWTPReceiveDataPacket:: exited");
	return NULL;
}

/*
 * Manage Run State.
 */

extern int gRawSock;
int wtpInRunState = 0;

CWStateTransition CWWTPEnterRun()
{
	int k;
	struct timespec timenow;

	CWLog("\n");
	CWLog("######### WTP enters in RUN State #########");

	lRunChannelState = CS_OK;

	gDataChannelKeepAliveInterval = gAggressiveDataChannelKeepAliveInterval;
	CWWTPKeepAliveDataTimerExpiredHandler(NULL);

	for (k = 0; k < MAX_PENDING_REQUEST_MSGS; k++)
		CWResetPendingMsgBox(gPendingRequestMsgs + k);

	if (!CWErr(CWStartHeartbeatTimer()))
		return CW_ENTER_RESET;
	if (!CWErr(CWStartNeighborDeadTimer()))
		return CW_ENTER_RESET;

	/* Wait packet */
	timenow.tv_sec = time(0) + gCWNeighborDeadInterval + gCWNeighborDeadRestartDelta;	/* greater than NeighborDeadInterval */
	timenow.tv_nsec = 0;

	wtpInRunState = 1;

	CW_REPEAT_FOREVER {
		CWBool bReceivePacket = CW_FALSE;
		CWBool bReveiveBinding = CW_FALSE;

		CWThreadMutexLock(&gInterfaceMutex);

		if (lRunChannelState != CS_OK) {
			CWDebugLog("WTP Channel State set to not OK (%d)", lRunChannelState);
			CWThreadMutexUnlock(&gInterfaceMutex);
			break;
		}

		/*
		 * if there are no frames from stations
		 * and no packets from AC...
		 */
		if ((CWGetCountElementFromSafeList(gPacketReceiveList) == 0)
		    && (CWGetCountElementFromSafeList(gFrameList) == 0)) {
			/*
			 * ...wait at most 4 mins for a frame or packet.
			 */
			if (!CWErr(CWWaitThreadConditionTimeout(&gInterfaceWait, &gInterfaceMutex, &timenow))) {

				CWThreadMutexUnlock(&gInterfaceMutex);

				if (CWErrorGetLastErrorCode() == CW_ERROR_TIME_EXPIRED) {

					CWLog("No Message from AC for a long time... restart Discovery State");
					break;
				}
				continue;
			}
		}

		bReceivePacket = ((CWGetCountElementFromSafeList(gPacketReceiveList) != 0) ? CW_TRUE : CW_FALSE);
		bReveiveBinding = ((CWGetCountElementFromSafeList(gFrameList) != 0) ? CW_TRUE : CW_FALSE);

		CWThreadMutexUnlock(&gInterfaceMutex);

		if (bReceivePacket) {

			CWProtocolMessage msg;

			msg.msg = NULL;
			msg.offset = 0;

			if (!(CWReceiveMessage(&msg))) {

				CW_FREE_PROTOCOL_MESSAGE(msg);
				CWLog("Failure Receiving Response");
				break;
			}
			if (!CWErr(CWWTPManageGenericRunMessage(&msg))) {

				if (CWErrorGetLastErrorCode() == CW_ERROR_INVALID_FORMAT) {

					/* Log and ignore message */
					CWErrorHandleLast();
					CWLog("--> Received something different from a valid Run Message");
				} else {
					CW_FREE_PROTOCOL_MESSAGE(msg);
					CWLog
					    ("--> Critical Error Managing Generic Run Message... we enter RESET State");
					break;
				}
			}

			/* Wait packet */
	        timenow.tv_sec = time(0) + gCWNeighborDeadInterval + gCWNeighborDeadRestartDelta;	/* greater than NeighborDeadInterval */
			timenow.tv_nsec = 0;
		}

		if (bReveiveBinding)
			CWWTPCheckForBindingFrame();

	}

	wtpInRunState = 0;
	CWStopHeartbeatTimer();
	CWStopDataChannelKeepAlive();
	CWStopNeighborDeadTimer();

	CWNetworkCloseSocket(gWTPSocket);
	CWNetworkCloseSocket(gWTPDataSocket);
#ifndef CW_NO_DTLS
	CWSecurityDestroySession(&gWTPSession);
	CWSecurityDestroyContext(&gWTPSecurityContext);
#endif

	/* shutdown wifi before leaving RUN state */
	unsigned char dummy_ssid[3] = {0,};
	CWWTPsend_command_to_hostapd_DEL_WLAN(dummy_ssid, sizeof(dummy_ssid));

	return CW_ENTER_RESET;
}

CWBool CWWTPManageGenericRunMessage(CWProtocolMessage * msgPtr)
{

	CWControlHeaderValues controlVal;

	if (msgPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	msgPtr->offset = 0;

	/* TODO:
	 * check to see if a time-out on session occure...
	 * In case it happens it should go back to CW_ENTER_RESET
	 */
	if (!CWResetHeartbeatTimer())
		return CW_FALSE;

	/* will be handled by the caller */
	if (!(CWParseControlHeader(msgPtr, &controlVal)))
		return CW_FALSE;

	int len = controlVal.msgElemsLen - CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;

	int pendingMsgIndex = 0;
	pendingMsgIndex = CWFindPendingRequestMsgsBox(gPendingRequestMsgs,
						      MAX_PENDING_REQUEST_MSGS,
						      controlVal.messageTypeValue, controlVal.seqNum);

	/* we have received a new Request or an Echo Response */
	if (pendingMsgIndex < 0) {
		CWProtocolMessage *messages = NULL;
		int fragmentsNum = 0;

		switch (controlVal.messageTypeValue) {

		case CW_MSG_TYPE_VALUE_CONFIGURE_UPDATE_REQUEST:{
				CWProtocolResultCode resultCode = CW_PROTOCOL_FAILURE;
				CWProtocolConfigurationUpdateRequestValues values;
				int updateRequestType;

				CWLog("Configuration Update Request received");

				/* assume AC has gone to Run state, reset Data Channel Keep Alive */
				gDataChannelKeepAliveInterval = gConfigDataChannelKeepAliveInterval;

			/************************************************************************************************
			 * Update 2009:                                                                                 *
			 *              These two function need an additional parameter (Pointer to updateRequestType)  *
			 *              for distinguish between all types of message elements.                          *
			 ************************************************************************************************/

				if (!CWParseConfigurationUpdateRequest
				    ((msgPtr->msg) + (msgPtr->offset), len, &values, &updateRequestType))
					return CW_FALSE;

				if (!CWSaveConfigurationUpdateRequest(&values, &resultCode, &updateRequestType))
					return CW_FALSE;

				/*
				   if ( updateRequestType == BINDING_MSG_ELEMENT_TYPE_OFDM_CONTROL )
				   break;
				 */

				/*Update 2009:
				   Added values (to return stuff with a conf update response) */
				if (!CWAssembleConfigurationUpdateResponse(&messages,
									   &fragmentsNum,
									   gWTPPathMTU,
									   controlVal.seqNum, resultCode, values))
					return CW_FALSE;

				break;
			}

		case CW_MSG_TYPE_VALUE_CLEAR_CONFIGURATION_REQUEST:{
				CWProtocolResultCode resultCode = CW_PROTOCOL_FAILURE;

				CWLog("Clear Configuration Request received");
				/*WTP RESET ITS CONFIGURAION TO MANUFACTURING DEFAULT} */
				if (!CWSaveClearConfigurationRequest(&resultCode))
					return CW_FALSE;
				if (!CWAssembleClearConfigurationResponse
				    (&messages, &fragmentsNum, gWTPPathMTU, controlVal.seqNum, resultCode))
					return CW_FALSE;

				break;
			}

		case CW_MSG_TYPE_VALUE_STATION_CONFIGURATION_REQUEST:{
				CWProtocolResultCode resultCode = CW_PROTOCOL_SUCCESS;

				//CWProtocolStationConfigurationRequestValues values;  --> da implementare
				CWLog("Station Configuration Request received");

				if (!CWParseStationConfigurationRequest((msgPtr->msg) + (msgPtr->offset), len))
					return CW_FALSE;
				if (!CWAssembleStationConfigurationResponse
				    (&messages, &fragmentsNum, gWTPPathMTU, controlVal.seqNum, resultCode))
					return CW_FALSE;

				break;
			}
		case CW_MSG_TYPE_VALUE_WLAN_CONFIGURATION_REQUEST:{
				CWProtocolResultCode resultCode = CW_PROTOCOL_SUCCESS;

				CWLog("WLAN Configuration Request received");

				/* assume AC has gone to Run state, reset Data Channel Keep Alive */
				gDataChannelKeepAliveInterval = gConfigDataChannelKeepAliveInterval;

				if (!CWParseWLANConfigurationRequest((msgPtr->msg) + (msgPtr->offset), len))
					return CW_FALSE;
				if (!CWAssembleWLANConfigurationResponse
				    (&messages, &fragmentsNum, gWTPPathMTU, controlVal.seqNum, resultCode))
					return CW_FALSE;

				break;

			}

		case CW_MSG_TYPE_VALUE_ECHO_RESPONSE: {
			CWLog("Echo Response received");

			if (!CWParseEchoResponse((msgPtr->msg) + (msgPtr->offset), len))
				return CW_FALSE;

			break;
		}
		default:
			/*
			 * We can't recognize the received Request so
			 * we have to send a corresponding response
			 * containing a failure result code
			 */
			CWLog("--> invalid Request %d (0x%04x) in Run State... we send a failure Response", controlVal.messageTypeValue, controlVal.messageTypeValue);

			if (!(CWAssembleUnrecognizedMessageResponse(&messages,
								    &fragmentsNum,
								    gWTPPathMTU,
								    controlVal.seqNum,
								    controlVal.messageTypeValue + 1)))
				return CW_FALSE;

			/* return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
			 *             "Received Message not valid in Run State");
			 */
		}

		if (fragmentsNum > 0) {
			int i;
			for (i = 0; i < fragmentsNum; i++) {
#ifdef CW_NO_DTLS
				if (!CWNetworkSendUnsafeConnected(gWTPSocket, messages[i].msg, messages[i].offset))
#else
				if (!CWSecuritySend(gWTPSession, messages[i].msg, messages[i].offset))
#endif
				{
					CWLog("Error sending message");
					CWFreeMessageFragments(messages, fragmentsNum);
					CW_FREE_OBJECT(messages);
					return CW_FALSE;
				}
			}

			CWLog("Message Sent\n");
			CWFreeMessageFragments(messages, fragmentsNum);
			CW_FREE_OBJECT(messages);

			/*
			 * Check if we have to exit due to an update commit request.
			 */
			if (WTPExitOnUpdateCommit)
				exit(EXIT_SUCCESS);
		}
	} else {		/* we have received a Response */
		switch (controlVal.messageTypeValue) {
		case CW_MSG_TYPE_VALUE_CHANGE_STATE_EVENT_RESPONSE:
			CWLog("Change State Event Response received");
			break;

		case CW_MSG_TYPE_VALUE_WTP_EVENT_RESPONSE:
			CWLog("WTP Event Response received");
			break;

		case CW_MSG_TYPE_VALUE_DATA_TRANSFER_RESPONSE:
			CWLog("Data Transfer Response received");
			break;

		default:
			/*
			 * We can't recognize the received Response: we
			 * ignore the message and log the event.
			 */
			return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Received Message not valid in Run State");
		}
		CWResetPendingMsgBox(&(gPendingRequestMsgs[pendingMsgIndex]));
	}
	CW_FREE_PROTOCOL_MESSAGE(*msgPtr);
	return CW_TRUE;
}

/*______________________________________________________________*/
/*  *******************___TIMER HANDLERS___*******************  */
void CWWTPHeartBeatTimerExpiredHandler(void *arg)
{

	CWList msgElemList = NULL;
	CWProtocolMessage *messages = NULL;
	int fragmentsNum = 0;
	int seqNum;

	CWLog("WTP HeartBeat Timer Expired... we send an ECHO Request");

	CWLog("\n");
	CWLog("#________ Echo Request Message (Run) ________#");

	/* Send WTP Event Request */
	seqNum = CWGetSeqNum();

	if (!CWAssembleEchoRequest(&messages, &fragmentsNum, gWTPPathMTU, seqNum, msgElemList)) {
		int i;

		CWDebugLog("Failure Assembling Echo Request");
		if (messages)
			for (i = 0; i < fragmentsNum; i++) {
				CW_FREE_PROTOCOL_MESSAGE(messages[i]);
			}
		CW_FREE_OBJECT(messages);
		return;
	}

	int i;
	for (i = 0; i < fragmentsNum; i++) {
#ifdef CW_NO_DTLS
		if (!CWNetworkSendUnsafeConnected(gWTPSocket, messages[i].msg, messages[i].offset)) {
#else
		if (!CWSecuritySend(gWTPSession, messages[i].msg, messages[i].offset)) {
#endif
			CWLog("Failure sending Request");
			int k;
			for (k = 0; k < fragmentsNum; k++) {
				CW_FREE_PROTOCOL_MESSAGE(messages[k]);
			}
			CW_FREE_OBJECT(messages);
			break;
		}
	}

	int k;
	for (k = 0; messages && k < fragmentsNum; k++) {
		CW_FREE_PROTOCOL_MESSAGE(messages[k]);
	}
	CW_FREE_OBJECT(messages);

	if (!CWStartHeartbeatTimer()) {
		return;
	}
}

void CWWTPKeepAliveDataTimerExpiredHandler(void *arg)
{
	int k;
	CWProtocolMessage *messages = NULL;
	CWProtocolMessage sessionIDmsgElem;
	int fragmentsNum = 0;


	CWLog("WTP KeepAliveDataTimer Expired... we send an Data Channel Keep-Alive");

	CWLog("\n");
	CWLog("#________ Keep-Alive Message (Run) ________#");

	if (!CWResetDataChannelKeepAlive()) {
		setRunChannelState(CS_FAILED);
		return;
	}

	CWAssembleMsgElemSessionID(&sessionIDmsgElem, &gWTPSessionID[0]);

	/* Send WTP Event Request */
	if (!CWAssembleDataMessage(&messages, &fragmentsNum, gWTPPathMTU, &sessionIDmsgElem, NULL, CW_PACKET_PLAIN, 1)) {
		CWDebugLog("Failure Assembling KeepAlive Message");
		setRunChannelState(CS_FAILED);
	} else {
		for (k = 0; k < fragmentsNum; k++) {
			if (!CWNetworkSendUnsafeConnected(gWTPDataSocket, messages[k].msg, messages[k].offset)) {
				CWLog("Failure sending  KeepAlive Message");
				setRunChannelState(CS_FAILED);
				break;
			}
		}
	}

	for (k = 0; messages && k < fragmentsNum; k++) {
		CW_FREE_PROTOCOL_MESSAGE(messages[k]);
	}
	CW_FREE_OBJECT(messages);
	CW_FREE_PROTOCOL_MESSAGE(sessionIDmsgElem);
}

void CWWTPNeighborDeadTimerExpired(void *arg)
{
	CWLog("WTP NeighborDead Timer Expired... we consider Peer Dead.");
	setRunChannelState(CS_TIMEOUT);

#ifdef DMALLOC
	dmalloc_shutdown();
#endif

	return;
}

CWBool CWStartHeartbeatTimer()
{
	gCWHeartBeatTimerID = timer_add(gEchoInterval, 0, &CWWTPHeartBeatTimerExpiredHandler, NULL);
	if (gCWHeartBeatTimerID == -1)
		return CW_FALSE;

	CWDebugLog("Echo Heartbeat Timer Started with %d seconds", gEchoInterval);
	return CW_TRUE;
}

CWBool CWStopHeartbeatTimer()
{
	timer_rem(gCWHeartBeatTimerID, NULL);

	CWDebugLog("Echo Heartbeat Timer Stopped");
	return CW_TRUE;
}

CWBool CWResetHeartbeatTimer()
{
	timer_rem(gCWHeartBeatTimerID, NULL);
	gCWHeartBeatTimerID = timer_add(gEchoInterval, 0, &CWWTPHeartBeatTimerExpiredHandler, NULL);
	if (gCWHeartBeatTimerID == -1)
		return CW_FALSE;

	CWDebugLog("Echo Heartbeat Timer Reset with %d seconds", gEchoInterval);
	return CW_TRUE;
}

CWBool CWStopDataChannelKeepAlive()
{
	timer_rem(gCWKeepAliveTimerID, NULL);

	CWDebugLog("DataChannelKeepAlive Timer Stopped");
	return CW_TRUE;
}


CWBool CWResetDataChannelKeepAlive()
{
	timer_rem(gCWKeepAliveTimerID, NULL);
	gCWKeepAliveTimerID = timer_add(gDataChannelKeepAliveInterval, 0, &CWWTPKeepAliveDataTimerExpiredHandler, NULL);
	if (gCWKeepAliveTimerID == -1)
		return CW_FALSE;

	CWDebugLog("DataChannelKeepAlive Timer Reset with %d seconds", gDataChannelKeepAliveInterval);
	return CW_TRUE;
}

CWBool CWStartNeighborDeadTimer()
{
	gCWNeighborDeadTimerID = timer_add(gCWNeighborDeadInterval, 0, &CWWTPNeighborDeadTimerExpired, NULL);
	if (gCWNeighborDeadTimerID == -1)
		return CW_FALSE;

	CWDebugLog("NeighborDead Timer Started with %d seconds", gCWNeighborDeadInterval);
	gNeighborDeadTimerSet = CW_TRUE;
	return CW_TRUE;
}

CWBool CWStopNeighborDeadTimer()
{
	timer_rem(gCWNeighborDeadTimerID, NULL);

	CWDebugLog("NeighborDead Timer Stopped");
	gNeighborDeadTimerSet = CW_FALSE;
	return CW_TRUE;
}

CWBool CWResetNeighborDeadTimer()
{
	timer_rem(gCWNeighborDeadTimerID, NULL);
	gCWNeighborDeadTimerID = timer_add(gCWNeighborDeadInterval, 0, &CWWTPNeighborDeadTimerExpired, NULL);
	if (gCWNeighborDeadTimerID == -1)
		return CW_FALSE;

	CWDebugLog("NeighborDead Timer Reset with %d seconds", gCWNeighborDeadInterval);
	gNeighborDeadTimerSet = CW_FALSE;
	return CW_TRUE;
}

/*__________________________________________________________________*/
/*  *******************___ASSEMBLE FUNCTIONS___*******************  */
CWBool CWAssembleEchoRequest(CWProtocolMessage ** messagesPtr,
			     int *fragmentsNumPtr, int PMTU, int seqNum, CWList msgElemList)
{
	struct timeval tv;
	CWProtocolMessage *msgElems = NULL;
	const int msgElemCount = 1;
	CWProtocolMessage *msgElemsBinding = NULL;
	const int msgElemBindingCount = 0;

	if (messagesPtr == NULL || fragmentsNumPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	gettimeofday(&tv, NULL);

	CWLog("Assembling Echo Request...");

        CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, msgElemCount, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
            );

	if (!CWAssembleMsgElemVendorTPWTPTimestamp(&(msgElems[0]), &tv) ||
	    !CWAssembleMessage(messagesPtr,
			       fragmentsNumPtr,
			       PMTU,
			       seqNum,
			       CW_MSG_TYPE_VALUE_ECHO_REQUEST,
			       msgElems, msgElemCount, msgElemsBinding, msgElemBindingCount))
		return CW_FALSE;

	CWLog("Echo Request Assembled");

	return CW_TRUE;
}

CWBool CWAssembleWTPDataTransferRequest(CWProtocolMessage ** messagesPtr, int *fragmentsNumPtr, int PMTU, int seqNum,
					CWList msgElemList)
{
	CWProtocolMessage *msgElems = NULL;
	int msgElemCount = 0;
	CWProtocolMessage *msgElemsBinding = NULL;
	const int msgElemBindingCount = 0;
	int i;
	CWListElement *current;
	int k = -1;

	if (messagesPtr == NULL || fragmentsNumPtr == NULL || msgElemList == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	msgElemCount = CWCountElementInList(msgElemList);

	if (msgElemCount > 0) {
		CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, msgElemCount,
						 return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
		    );
	} else
		msgElems = NULL;

	CWLog("Assembling WTP Data Transfer Request...");

	current = msgElemList;
	for (i = 0; i < msgElemCount; i++) {
		switch (((CWMsgElemData *) current->data)->type) {
		case CW_MSG_ELEMENT_DATA_TRANSFER_DATA_CW_TYPE:
			if (!
			    (CWAssembleMsgElemDataTransferData
			     (&(msgElems[++k]), ((CWMsgElemData *) current->data)->value)))
				goto cw_assemble_error;
			break;
			/*case CW_MSG_ELEMENT_DATA_TRANSFER_MODE_CW_TYPE:
			   if (!(CWAssembleMsgElemDataTansferMode(&(msgElems[++k]))))
			   goto cw_assemble_error;
			   break; */

		default:
			goto cw_assemble_error;
			break;
		}

		current = current->next;
	}

	if (!(CWAssembleMessage(messagesPtr,
				fragmentsNumPtr,
				PMTU,
				seqNum,
				CW_MSG_TYPE_VALUE_DATA_TRANSFER_REQUEST,
				msgElems, msgElemCount, msgElemsBinding, msgElemBindingCount)))
		return CW_FALSE;

	CWLog("WTP Data Transfer Request Assembled");

	return CW_TRUE;

 cw_assemble_error:{
		int i;
		for (i = 0; i <= k; i++) {
			CW_FREE_PROTOCOL_MESSAGE(msgElems[i]);
		}
		CW_FREE_OBJECT(msgElems);
		return CW_FALSE;	// error will be handled by the caller
	}
}

CWBool CWAssembleWTPEventRequest(CWProtocolMessage ** messagesPtr,
				 int *fragmentsNumPtr, int PMTU, int seqNum, CWList msgElemList)
{

	CWProtocolMessage *msgElems = NULL;
	int msgElemCount = 0;
	CWProtocolMessage *msgElemsBinding = NULL;
	const int msgElemBindingCount = 0;
	int i;
	CWListElement *current;
	int k = -1;

	if (messagesPtr == NULL || fragmentsNumPtr == NULL || msgElemList == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	msgElemCount = CWCountElementInList(msgElemList);

	if (msgElemCount > 0) {

		CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems,
						 msgElemCount, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
		    );
	} else
		msgElems = NULL;

	CWLog("Assembling WTP Event Request...");

	current = msgElemList;
	for (i = 0; i < msgElemCount; i++) {

		switch (((CWMsgElemData *) current->data)->type) {

		case CW_MSG_ELEMENT_CW_DECRYPT_ER_REPORT_CW_TYPE:
			if (!
			    (CWAssembleMsgElemDecryptErrorReport
			     (&(msgElems[++k]), ((CWMsgElemData *) current->data)->value)))
				goto cw_assemble_error;
			break;
		case CW_MSG_ELEMENT_DUPLICATE_IPV4_ADDRESS_CW_TYPE:
			if (!(CWAssembleMsgElemDuplicateIPv4Address(&(msgElems[++k]))))
				goto cw_assemble_error;
			break;
		case CW_MSG_ELEMENT_DUPLICATE_IPV6_ADDRESS_CW_TYPE:
			if (!(CWAssembleMsgElemDuplicateIPv6Address(&(msgElems[++k]))))
				goto cw_assemble_error;
			break;
		case CW_MSG_ELEMENT_WTP_OPERAT_STATISTICS_CW_TYPE:
			if (!
			    (CWAssembleMsgElemWTPOperationalStatistics
			     (&(msgElems[++k]), ((CWMsgElemData *) current->data)->value)))
				goto cw_assemble_error;
			break;
		case CW_MSG_ELEMENT_WTP_RADIO_STATISTICS_CW_TYPE:
			if (!
			    (CWAssembleMsgElemWTPRadioStatistics
			     (&(msgElems[++k]), ((CWMsgElemData *) current->data)->value)))
				goto cw_assemble_error;
			break;
		case CW_MSG_ELEMENT_WTP_REBOOT_STATISTICS_CW_TYPE:
			if (!(CWAssembleMsgElemWTPRebootStatistics(&(msgElems[++k]))))
				goto cw_assemble_error;
			break;
		default:
			goto cw_assemble_error;
			break;
		}
		current = current->next;
	}

	if (!(CWAssembleMessage(messagesPtr,
				fragmentsNumPtr,
				PMTU,
				seqNum,
				CW_MSG_TYPE_VALUE_WTP_EVENT_REQUEST,
				msgElems, msgElemCount, msgElemsBinding, msgElemBindingCount)))
		return CW_FALSE;

	CWLog("WTP Event Request Assembled");

	return CW_TRUE;

 cw_assemble_error:{
		int i;
		for (i = 0; i <= k; i++) {
			CW_FREE_PROTOCOL_MESSAGE(msgElems[i]);
		}
		CW_FREE_OBJECT(msgElems);
		return CW_FALSE;	// error will be handled by the caller
	}
}

/*Update 2009:
    Added values to args... values is used to determine if we have some
    payload (in this case only vendor and only UCI) to send back with the
    configuration update response*/
CWBool CWAssembleConfigurationUpdateResponse(CWProtocolMessage ** messagesPtr,
					     int *fragmentsNumPtr,
					     int PMTU,
					     int seqNum,
					     CWProtocolResultCode resultCode,
					     CWProtocolConfigurationUpdateRequestValues values)
{

	CWProtocolMessage *msgElems = NULL;
	const int msgElemCount = 1;
	CWProtocolMessage *msgElemsBinding = NULL;
	const int msgElemBindingCount = 0;
	CWProtocolVendorSpecificValues *protoValues = NULL;

	/*Get protocol data if we have it */
	if (values.protocolValues)
		protoValues = (CWProtocolVendorSpecificValues *) values.protocolValues;

	if (messagesPtr == NULL || fragmentsNumPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CWLog("Assembling Configuration Update Response...");

	msgElems = CW_CREATE_OBJECT_ERR(CWProtocolMessage, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
	    );

	if (protoValues) {
		switch (protoValues->vendorPayloadType) {
		case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_UCI:
		case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_WUM:
			if (!(CWAssembleVendorMsgElemResultCodeWithPayload(msgElems, resultCode, protoValues))) {
				CW_FREE_OBJECT(msgElems);
				return CW_FALSE;
			}

			break;

		default:
			/*Result Code only */
			if (!(CWAssembleMsgElemResultCode(msgElems, resultCode))) {
				CW_FREE_OBJECT(msgElems);
				return CW_FALSE;
			}
		}
	} else {
		/*Result Code only */
		if (!(CWAssembleMsgElemResultCode(msgElems, resultCode))) {
			CW_FREE_OBJECT(msgElems);
			return CW_FALSE;
		}
	}

	if (!(CWAssembleMessage(messagesPtr,
				fragmentsNumPtr,
				PMTU,
				seqNum,
				CW_MSG_TYPE_VALUE_CONFIGURE_UPDATE_RESPONSE,
				msgElems, msgElemCount, msgElemsBinding, msgElemBindingCount)))
		return CW_FALSE;

	CWLog("Configuration Update Response Assembled");

	return CW_TRUE;
}

CWBool CWAssembleClearConfigurationResponse(CWProtocolMessage ** messagesPtr, int *fragmentsNumPtr, int PMTU,
					    int seqNum, CWProtocolResultCode resultCode)
{
	CWProtocolMessage *msgElems = NULL;
	const int msgElemCount = 1;
	CWProtocolMessage *msgElemsBinding = NULL;
	const int msgElemBindingCount = 0;

	if (messagesPtr == NULL || fragmentsNumPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CWLog("Assembling Clear Configuration Response...");

	msgElems = CW_CREATE_OBJECT_ERR(CWProtocolMessage, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
	    );

	if (!(CWAssembleMsgElemResultCode(msgElems, resultCode))) {
		CW_FREE_OBJECT(msgElems);
		return CW_FALSE;
	}

	if (!(CWAssembleMessage(messagesPtr,
				fragmentsNumPtr,
				PMTU,
				seqNum,
				CW_MSG_TYPE_VALUE_CLEAR_CONFIGURATION_RESPONSE,
				msgElems, msgElemCount, msgElemsBinding, msgElemBindingCount)))
		return CW_FALSE;

	CWLog("Clear Configuration Response Assembled");

	return CW_TRUE;
}

CWBool CWAssembleStationConfigurationResponse(CWProtocolMessage ** messagesPtr, int *fragmentsNumPtr, int PMTU,
					      int seqNum, CWProtocolResultCode resultCode)
{

	CWProtocolMessage *msgElems = NULL;
	const int msgElemCount = 1;
	CWProtocolMessage *msgElemsBinding = NULL;
	const int msgElemBindingCount = 0;

	if (messagesPtr == NULL || fragmentsNumPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CWLog("Assembling Sattion Configuration Response...");

	msgElems = CW_CREATE_OBJECT_ERR(CWProtocolMessage, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
	    );

	if (!(CWAssembleMsgElemResultCode(msgElems, resultCode))) {
		CW_FREE_OBJECT(msgElems);
		return CW_FALSE;
	}

	if (!(CWAssembleMessage(messagesPtr,
				fragmentsNumPtr,
				PMTU,
				seqNum,
				CW_MSG_TYPE_VALUE_STATION_CONFIGURATION_RESPONSE,
				msgElems, msgElemCount, msgElemsBinding, msgElemBindingCount)))
		return CW_FALSE;

	CWLog("Station Configuration Response Assembled");

	return CW_TRUE;
}

CWBool CWAssembleWLANConfigurationResponse(CWProtocolMessage ** messagesPtr, int *fragmentsNumPtr, int PMTU, int seqNum,
					   CWProtocolResultCode resultCode)
{

	CWProtocolMessage *msgElems = NULL;
	const int msgElemCount = 2;
	CWProtocolMessage *msgElemsBinding = NULL;
	const int msgElemBindingCount = 0;
	int k = -1;
	if (messagesPtr == NULL || fragmentsNumPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CWLog("Assembling WLAN Configuration Response...");

	//msgElems = CW_CREATE_OBJECT_ERR(CWProtocolMessage, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, msgElemCount, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
	    );

	if (!(CWAssembleMsgElemResultCode((&(msgElems[++k])), resultCode))) {
		CW_FREE_OBJECT(msgElems);
		return CW_FALSE;
	}
	if (!(CWAssembleMsgElemVendorSpecificPayload((&(msgElems[++k]))))) {
		CW_FREE_OBJECT(msgElems);
		return CW_FALSE;
	}

	if (!(CWAssembleMessage(messagesPtr,
				fragmentsNumPtr,
				PMTU,
				seqNum,
				CW_MSG_TYPE_VALUE_WLAN_CONFIGURATION_RESPONSE,
				msgElems, msgElemCount, msgElemsBinding, msgElemBindingCount)))
		return CW_FALSE;

	CWLog("WLAN Configuration Response Assembled");

	return CW_TRUE;
}

/*_______________________________________________________________*/
/*  *******************___PARSE FUNCTIONS___*******************  */
/*Update 2009:
    Function that parses vendor payload,
    filling in valuesPtr*/
CWBool CWParseVendorMessage(unsigned char *msg, int len, void **valuesPtr)
{
	CWProtocolMessage completeMsg;
	unsigned short int GlobalElemType = 0;	// = CWProtocolRetrieve32(&completeMsg);

	if (msg == NULL || valuesPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CWLog("Parsing Vendor Specific Message...");

	completeMsg.msg = msg;
	completeMsg.offset = 0;

	CWProtocolVendorSpecificValues *vendPtr = NULL;

	// parse message elements
	while (completeMsg.offset < len) {
		unsigned short int elemType = 0;	// = CWProtocolRetrieve32(&completeMsg);
		unsigned short int elemLen = 0;	// = CWProtocolRetrieve16(&completeMsg);

		CWParseFormatMsgElem(&completeMsg, &elemType, &elemLen);

		GlobalElemType = elemType;

		//CWDebugLog("Parsing Message Element: %u, elemLen: %u", elemType, elemLen);

		switch (elemType) {
		case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE:
			completeMsg.offset += elemLen;
			break;
		default:
			if (elemType == CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE) {
				CW_FREE_OBJECT(valuesPtr);
				return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Unrecognized Message Element");
			} else {
				completeMsg.offset += elemLen;
				break;
			}
		}
	}

	if (completeMsg.offset != len)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");

	switch (GlobalElemType) {
	case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE:
		vendPtr = CW_CREATE_OBJECT_ERR(CWProtocolVendorSpecificValues,
				     return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
		    );
		/*Allocate various other vendor specific fields */
		break;
	}

	completeMsg.offset = 0;
	while (completeMsg.offset < len) {
		unsigned short int type = 0;
		unsigned short int elemLen = 0;

		CWParseFormatMsgElem(&completeMsg, &type, &elemLen);

		switch (type) {
			/*Once we know it is a vendor specific payload... */
		case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE:{
				if (!
				    (CWParseVendorPayload
				     (&completeMsg, elemLen, (CWProtocolVendorSpecificValues *) vendPtr))) {
					CW_FREE_OBJECT(vendPtr);
					return CW_FALSE;	// will be handled by the caller
				}
			}
			break;
		default:
			completeMsg.offset += elemLen;
			break;
		}
	}

	*valuesPtr = (void *)vendPtr;
	CWLog("Vendor Message Parsed");

	return CW_TRUE;
}

CWBool CWParseConfigurationUpdateRequest(unsigned char *msg, int len,
					 CWProtocolConfigurationUpdateRequestValues * valuesPtr, int *updateRequestType)
{

	CWBool bindingMsgElemFound = CW_FALSE;
	CWBool vendorMsgElemFound = CW_FALSE;
	CWBool acAddressWithPrioFound = CW_FALSE;
	CWProtocolMessage completeMsg;
	unsigned short int GlobalElementType = 0;

	if (msg == NULL || valuesPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CWLog("Parsing Configuration Update Request...");

	completeMsg.msg = msg;
	completeMsg.offset = 0;

	memset(valuesPtr, 0, sizeof(CWProtocolConfigurationUpdateRequestValues));

	/* parse message elements */
	while (completeMsg.offset < len) {

		unsigned short int elemType = 0;	/* = CWProtocolRetrieve32(&completeMsg); */
		unsigned short int elemLen = 0;	/* = CWProtocolRetrieve16(&completeMsg); */

		CWParseFormatMsgElem(&completeMsg, &elemType, &elemLen);

		GlobalElementType = elemType;

		/* CWDebugLog("Parsing Message Element: %u, elemLen: %u", elemType, elemLen); */
		CWLog("Parsing Message Element: %u, elemLen: %u", elemType, elemLen);

		if (CWBindingCheckType(elemType)) {

			bindingMsgElemFound = CW_TRUE;
			completeMsg.offset += elemLen;
			continue;
		}
		switch (elemType) {
			/*Update 2009:
			   Added case for vendor specific payload
			   (Used mainly to parse UCI messages)... */

		case CW_MSG_ELEMENT_TIMESTAMP_CW_TYPE:
			valuesPtr->timeStamp = CWProtocolRetrieve32(&completeMsg);
			break;

		case CW_MSG_ELEMENT_CW_TIMERS_CW_TYPE:
			CWParseCWTimers(&completeMsg, elemLen, &valuesPtr->CWTimers);
			break;

		case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_BW_CW_TYPE: {
			unsigned int vendorId = CWProtocolRetrieve32(&completeMsg);
			unsigned short int vendorElemType = CWProtocolRetrieve16(&completeMsg);
			elemLen -= 6;

			CWDebugLog("Parsing Vendor Message Element, Vendor: %u, Element: %u", vendorId, vendorElemType);
			switch (vendorId) {
			case CW_IANA_ENTERPRISE_NUMBER_VENDOR_TRAVELPING: {
				CWDebugLog("Parsing TP Vendor Message Element: %u", vendorElemType);
				switch (vendorElemType) {
				case CW_MSG_ELEMENT_TRAVELPING_IEEE_80211_WLAN_HOLD_TIME:
					CWParseTPIEEE80211WLanHoldTime(&completeMsg, elemLen, &valuesPtr->vendorTP_IEEE80211WLanHoldTime);
					break;

				case CW_MSG_ELEMENT_TRAVELPING_DATA_CHANNEL_DEAD_INTERVAL:
					CWParseTPDataChannelDeadInterval(&completeMsg, elemLen, &valuesPtr->vendorTP_DataChannelDeadInterval);
					break;

				case CW_MSG_ELEMENT_TRAVELPING_AC_JOIN_TIMEOUT:
					CWParseTPACJoinTimeout(&completeMsg, elemLen, &valuesPtr->vendorTP_ACJoinTimeout);
					break;

                                case CW_MSG_ELEMENT_TRAVELPING_AC_ADDRESS_LIST_WITH_PRIORITY:
					if (acAddressWithPrioFound != CW_TRUE) {
						CWResetDiscoveredACAddresses();
						acAddressWithPrioFound = CW_TRUE;
					}
					if (!(CWParseACAddressListWithPrio(&completeMsg, len)))
						return CW_FALSE;
					break;

				default:
					CWLog("unknown TP Vendor Message Element: %u", vendorElemType);

					/* ignore unknown vendor extensions */
					completeMsg.offset += elemLen;
					break;
				}
				break;

			default:
				CWLog("unknown Vendor Message Element, Vendor: %u, Element: %u", vendorId, vendorElemType);

				/* ignore unknown vendor extensions */
				completeMsg.offset += elemLen;
				break;
			}
			}

			break;
		}

		case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE:
			vendorMsgElemFound = CW_TRUE;
			completeMsg.offset += elemLen;
			break;

		default:
			return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Unrecognized Message Element");
		}
	}

	if (completeMsg.offset != len)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");

	/*Update 2009:
	   deal with vendor specific messages */
	if (vendorMsgElemFound) {
		/* For the knownledge of SaveConfiguration */
		*updateRequestType = GlobalElementType;

		if (!(CWParseVendorMessage(msg, len, &(valuesPtr->protocolValues)))) {

			return CW_FALSE;
		}
	}

	if (bindingMsgElemFound) {
		/* For the knownledge of SaveConfiguration */
		*updateRequestType = GlobalElementType;

		if (!(CWBindingParseConfigurationUpdateRequest(msg, len, &(valuesPtr->bindingValues)))) {

			return CW_FALSE;
		}
	}

	CWLog("Configure Update Request Parsed");

	return CW_TRUE;
}

CWBool CWParseWLANConfigurationRequest(unsigned char *msg, int len)
{

	CWProtocolMessage completeMsg;

	if (msg == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CWLog("Parsing WLAN Configuration Request...");

	completeMsg.msg = msg;
	completeMsg.offset = 0;

	// parse message elements
	while (completeMsg.offset < len) {
		unsigned short int elemType = 0;
		unsigned short int elemLen = 0;

		CWParseFormatMsgElem(&completeMsg, &elemType, &elemLen);

		switch (elemType) {

		case CW_MSG_ELEMENT_IEEE80211_ADD_WLAN_CW_TYPE:

			if (!(CWParseAddWLAN(&completeMsg, elemLen)))
				return CW_FALSE;
			break;

		case CW_MSG_ELEMENT_IEEE80211_DELETE_WLAN_CW_TYPE:

			if (!(CWParseDeleteWLAN(&completeMsg, elemLen)))
				return CW_FALSE;
			break;

		default:
			return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Unrecognized Message Element");
		}
	}

	if (completeMsg.offset != len)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");

	CWLog("Station WLAN Request Parsed");

	return CW_TRUE;
}

CWBool CWParseStationConfigurationRequest(unsigned char *msg, int len)
{
	//CWBool bindingMsgElemFound=CW_FALSE;
	CWProtocolMessage completeMsg;

	if (msg == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CWLog("Parsing Station Configuration Request...");

	completeMsg.msg = msg;
	completeMsg.offset = 0;

	//valuesPtr->bindingValues = NULL;

	// parse message elements
	while (completeMsg.offset < len) {
		unsigned short int elemType = 0;
		unsigned short int elemLen = 0;

		CWParseFormatMsgElem(&completeMsg, &elemType, &elemLen);

		//CWDebugLog("Parsing Message Element: %u, elemLen: %u", elemType, elemLen);

		/*if(CWBindingCheckType(elemType))
		   {
		   bindingMsgElemFound=CW_TRUE;
		   completeMsg.offset += elemLen;
		   continue;
		   } */

		switch (elemType) {

		case CW_MSG_ELEMENT_ADD_STATION_CW_TYPE:

			if (!(CWParseAddStation(&completeMsg, elemLen)))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_DELETE_STATION_CW_TYPE:

			if (!(CWParseDeleteStation(&completeMsg, elemLen)))
				return CW_FALSE;
			break;
		default:
			return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Unrecognized Message Element");
		}
	}

	if (completeMsg.offset != len)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");
	/*
	   if(bindingMsgElemFound)
	   {
	   if(!(CWBindingParseConfigurationUpdateRequest (msg, len, &(valuesPtr->bindingValues))))
	   {
	   return CW_FALSE;
	   }
	   } */

	CWLog("Station Configuration Request Parsed");

	return CW_TRUE;
}

CWBool CWParseWTPEventResponseMessage(unsigned char *msg, int len, int seqNum, void *values)
{

	CWControlHeaderValues controlVal;
	CWProtocolMessage completeMsg;

	if (msg == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CWLog("Parsing WTP Event Response...");

	completeMsg.msg = msg;
	completeMsg.offset = 0;

	/* error will be handled by the caller */
	if (!(CWParseControlHeader(&completeMsg, &controlVal)))
		return CW_FALSE;

	/* different type */
	if (controlVal.messageTypeValue != CW_MSG_TYPE_VALUE_WTP_EVENT_RESPONSE)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Message is not WTP Event Response as Expected");

	if (controlVal.seqNum != seqNum)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Different Sequence Number");

	/* skip timestamp */
	controlVal.msgElemsLen -= CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;

	if (controlVal.msgElemsLen != 0)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "WTP Event Response must carry no message element");

	CWLog("WTP Event Response Parsed...");

	return CW_TRUE;
}


CWBool CWParseEchoResponse(unsigned char *msg, int len)
{
	CWProtocolMessage completeMsg;

	if (msg == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CWLog("Parsing Echo Response...");

	completeMsg.msg = msg;
	completeMsg.offset = 0;

	/* parse message elements */
	while (completeMsg.offset < len) {

		unsigned short int elemType = 0;  /* = CWProtocolRetrieve32(&completeMsg); */
		unsigned short int elemLen = 0;	  /* = CWProtocolRetrieve16(&completeMsg); */

		CWParseFormatMsgElem(&completeMsg, &elemType, &elemLen);

		CWLog("Parsing Message Element: %u, elemLen: %u", elemType, elemLen);

		switch (elemType) {
		case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_BW_CW_TYPE: {
			unsigned int vendorId = CWProtocolRetrieve32(&completeMsg);
			unsigned short int vendorElemType = CWProtocolRetrieve16(&completeMsg);
			elemLen -= 6;

			CWDebugLog("Parsing Vendor Message Element, Vendor: %u, Element: %u", vendorId, vendorElemType);
			switch (vendorId) {
			case CW_IANA_ENTERPRISE_NUMBER_VENDOR_TRAVELPING: {
				elemLen -= 2;

				CWDebugLog("Parsing TP Vendor Message Element: %u", vendorElemType);
				switch (vendorElemType) {

				case CW_MSG_ELEMENT_TRAVELPING_WTP_TIMESTAMP: {
					struct timeval tv, now;

					if (!CWParseVendorTPWTPTimestamp(&completeMsg, elemLen, &tv))
						return CW_FALSE;

					gettimeofday(&now, NULL);
					timersub(&now, &tv, &gEchoLatency);

					CWLog("Echo Latency: %ld.%03ld ms", gEchoLatency.tv_sec * 1000 + gEchoLatency.tv_usec / 1000, gEchoLatency.tv_usec % 1000);
					break;
				}

				default:
					CWLog("ignore TP Vendor Message Element: %u", vendorElemType);

					/* ignore unknown vendor extensions */
					completeMsg.offset += elemLen;
					break;
				}
				break;

			default:
				CWLog("ignore Vendor Message Element, Vendor: %u, Element: %u", vendorId, vendorElemType);

				/* ignore unknown vendor extensions */
				completeMsg.offset += elemLen;
				break;
			}
			}

			break;
		}

		default:
			CWLog("ignore Message Element %u", elemType);
			completeMsg.offset += elemLen;
			break;
		}
	}

	if (completeMsg.offset != len)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");

	CWLog("Echo Response Parsed");

	return CW_TRUE;
}

/*______________________________________________________________*/
/*  *******************___SAVE FUNCTIONS___*******************  */
CWBool CWSaveWTPEventResponseMessage(void *WTPEventResp)
{

	CWDebugLog("Saving WTP Event Response...");
	CWDebugLog("WTP Response Saved");
	return CW_TRUE;
}

/*Update 2009:
    Save a vendor message (mainly UCI configuration messages)*/
CWBool CWSaveVendorMessage(void *protocolValuesPtr, CWProtocolResultCode * resultCode)
{
	if (protocolValuesPtr == NULL) {
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	}
	*resultCode = CW_PROTOCOL_SUCCESS;

	CWProtocolVendorSpecificValues *vendorPtr = (CWProtocolVendorSpecificValues *) protocolValuesPtr;

	/*Find out which custom vendor paylod really is... */
	switch (vendorPtr->vendorPayloadType) {
	case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_UCI:
		if (!CWWTPSaveUCIValues((CWVendorUciValues *) (vendorPtr->payload), resultCode)) {
			CW_FREE_OBJECT(((CWVendorUciValues *) vendorPtr->payload)->commandArgs);
			CW_FREE_OBJECT(vendorPtr->payload);
			CW_FREE_OBJECT(vendorPtr);
			return CW_FALSE;
		}
		break;

	case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_WUM:
		if (!CWWTPSaveWUMValues((CWVendorWumValues *) (vendorPtr->payload), resultCode)) {
			CW_FREE_OBJECT(vendorPtr->payload);
			CW_FREE_OBJECT(vendorPtr);
			return CW_FALSE;
		}
		break;
	}

	return CW_TRUE;
}

CWBool CWSaveConfigurationUpdateRequest(CWProtocolConfigurationUpdateRequestValues * valuesPtr,
					CWProtocolResultCode * resultCode, int *updateRequestType)
{

	*resultCode = CW_TRUE;

	if (valuesPtr == NULL) {
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	}

	if (valuesPtr->bindingValues != NULL) {

		if (!CWBindingSaveConfigurationUpdateRequest(valuesPtr->bindingValues, resultCode, updateRequestType))
			return CW_FALSE;
	}
	if (valuesPtr->protocolValues != NULL) {
		/*Update 2009:
		   We have a msg which is not a
		   binding specific message... */
		if (!CWSaveVendorMessage(valuesPtr->protocolValues, resultCode))
			return CW_FALSE;
	}

	*resultCode = CW_PROTOCOL_SUCCESS;

	if (valuesPtr->timeStamp != 0) {
		struct timeval tv;

		CWLog("Setting WTP Time");

		tv.tv_sec = (valuesPtr->timeStamp & 0x80000000) ?
			valuesPtr->timeStamp - 2208988800 : (time_t)2085978496 + valuesPtr->timeStamp;
		tv.tv_usec = 0;
		settimeofday(&tv, NULL);
	}

	if (valuesPtr->vendorTP_DataChannelDeadInterval != 0)
		gCWNeighborDeadInterval = valuesPtr->vendorTP_DataChannelDeadInterval;

	if (valuesPtr->vendorTP_ACJoinTimeout != 0)
		gCWWaitJoin = valuesPtr->vendorTP_ACJoinTimeout;

	if (valuesPtr->CWTimers.discoveryTimer != 0)
		gCWMaxDiscoveryInterval = valuesPtr->CWTimers.discoveryTimer;

	if (valuesPtr->CWTimers.echoRequestTimer != 0)
		gEchoInterval = valuesPtr->CWTimers.echoRequestTimer;

	return CW_TRUE;
}

CWBool CWSaveClearConfigurationRequest(CWProtocolResultCode * resultCode)
{
	*resultCode = CW_TRUE;

	/*Back to manufacturing default configuration */

	if (!CWErr(CWWTPLoadConfiguration()) || !CWErr(CWWTPInitConfiguration())) {
		CWLog("Can't restore default configuration...");
		return CW_FALSE;
	}

	*resultCode = CW_TRUE;
	return CW_TRUE;
}

/*
CWBool CWWTPManageACRunRequest(char *msg, int len)
{
    CWControlHeaderValues controlVal;
    CWProtocolMessage completeMsg;

    if(msg == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

    completeMsg.msg = msg;
    completeMsg.offset = 0;

    if(!(CWParseControlHeader(&completeMsg, &controlVal))) return CW_FALSE; // error will be handled by the caller

    switch(controlVal.messageTypeValue) {
        case CW_MSG_TYPE_VALUE_CONFIGURE_UPDATE_REQUEST:
            break;
        case CW_MSG_TYPE_VALUE_ECHO_REQUEST:
            break;
        case CW_MSG_TYPE_VALUE_CLEAR_CONFIGURATION_REQUEST:
            break;
        case CW_MSG_TYPE_VALUE_STATION_CONFIGURATION_REQUEST:
            break;
        default:
            return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Message is not Change State Event Response as Expected");
    }

    //if(controlVal.seqNum != seqNum) return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Different Sequence Number");

    controlVal.msgElemsLen -= CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS; // skip timestamp

    if(controlVal.msgElemsLen != 0 ) return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Change State Event Response must carry no message elements");

    CWDebugLog("Change State Event Response Parsed");

    CWDebugLog("#########################");
    CWDebugLog("###### STO DENTRO #######");
    CWDebugLog("#########################");

    return CW_TRUE;
}
*/

void CWConfirmRunStateToACWithEchoRequest()
{

	CWList msgElemList = NULL;
	CWProtocolMessage *messages = NULL;
	int fragmentsNum = 0;
	int seqNum;

	CWLog("\n");
	CWLog("#________ Echo Request Message (Confirm Run) ________#");

	/* Send WTP Event Request */
	seqNum = CWGetSeqNum();

	if (!CWAssembleEchoRequest(&messages, &fragmentsNum, gWTPPathMTU, seqNum, msgElemList)) {
		int i;

		CWDebugLog("Failure Assembling Echo Request");
		if (messages)
			for (i = 0; i < fragmentsNum; i++) {
				CW_FREE_PROTOCOL_MESSAGE(messages[i]);
			}
		CW_FREE_OBJECT(messages);
		return;
	}

	int i;
	for (i = 0; i < fragmentsNum; i++) {
#ifdef CW_NO_DTLS
		if (!CWNetworkSendUnsafeConnected(gWTPSocket, messages[i].msg, messages[i].offset)) {
#else
		if (!CWSecuritySend(gWTPSession, messages[i].msg, messages[i].offset)) {
#endif
			CWLog("Failure sending Request");
			int k;
			for (k = 0; k < fragmentsNum; k++) {
				CW_FREE_PROTOCOL_MESSAGE(messages[k]);
			}
			CW_FREE_OBJECT(messages);
			break;
		}
	}

	int k;
	for (k = 0; messages && k < fragmentsNum; k++) {
		CW_FREE_PROTOCOL_MESSAGE(messages[k]);
	}
	CW_FREE_OBJECT(messages);

}
