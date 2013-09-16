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

static CWBool CWWTPManageGenericRunMessage(CWProtocolMessage *pm);
CWBool CWWTPCheckForWTPEventRequest();
#if 0
static CWBool CWParseWTPEventResponseMessage(unsigned char *msg, int len, int seqNum, void *values);
static CWBool CWSaveWTPEventResponseMessage(void *WTPEventResp);
#endif
static CWBool CWAssembleEchoRequest(CWTransportMessage *tm, int PMTU, int seqNum, CWList msgElemList);
static CWBool CWParseEchoResponse(CWProtocolMessage *pm, int len);
static CWBool CWParseConfigurationUpdateRequest(CWProtocolMessage *pm, int len,
					 CWProtocolConfigurationUpdateRequestValues * valuesPtr,
					 int *updateRequestType);
static CWBool CWSaveConfigurationUpdateRequest(CWProtocolConfigurationUpdateRequestValues * valuesPtr,
					CWProtocolResultCode * resultCode, int *updateRequestType);
static CWBool CWAssembleConfigurationUpdateResponse(CWTransportMessage *tm, int PMTU, int seqNum, CWProtocolResultCode resultCode,
					     CWProtocolConfigurationUpdateRequestValues values);
static CWBool CWSaveClearConfigurationRequest(CWProtocolResultCode * resultCode);
static CWBool CWAssembleClearConfigurationResponse(CWTransportMessage *tm, int PMTU, int seqNum, CWProtocolResultCode resultCode);
static CWBool CWAssembleStationConfigurationResponse(CWTransportMessage *tm, int PMTU, int seqNum, CWProtocolResultCode resultCode);
static CWBool CWAssembleWLANConfigurationResponse(CWTransportMessage *tm, int PMTU, int seqNum, CWProtocolResultCode resultCode);
static CWBool CWParseStationConfigurationRequest(CWProtocolMessage *pm, int len);
static CWBool CWParseWLANConfigurationRequest(CWProtocolMessage *pm, int len);

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
		if (!(pData = ralloc_memdup(NULL, buf, readBytes))) {
			CWLog("Out Of Memory");
			return NULL;
		}

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
static
int isEAPOL_Frame(unsigned char *buf, unsigned int len)
{
	static const unsigned char rfc1042_header[6] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };

	return (memcmp(rfc1042_header, buf + HLEN_80211, sizeof(rfc1042_header)) == 0);
}

CW_THREAD_RETURN_TYPE CWWTPReceiveDataPacket(void *arg)
{
	int readBytes;
	unsigned char buf[CW_BUFFER_SIZE];
	struct sockaddr_ll rawSockaddr;
	CWNetworkLev4Address addr;
	CWProtocolMessage pm;
	CWProtocolMessage msg;
	CWFragmentBufferList frag_buffer;

	memset(&rawSockaddr, 0, sizeof(rawSockaddr));

	rawSockaddr.sll_family = AF_PACKET;
	rawSockaddr.sll_protocol = htons(ETH_P_ALL);
	rawSockaddr.sll_ifindex = if_nametoindex(gRadioInterfaceName_0);
	rawSockaddr.sll_pkttype = PACKET_OTHERHOST;
	rawSockaddr.sll_halen = ETH_ALEN;

	CW_REPEAT_FOREVER {
		if (!CWErr(CWNetworkReceiveUnsafe(gWTPDataSocket, buf, CW_BUFFER_SIZE, 0, &addr, &readBytes))) {
			if (CWErrorGetLastErrorCode() == CW_ERROR_INTERRUPTED)
				continue;

			break;
		}
		if (readBytes == 0)
			/* no error, but no data == orderly shutdown */
			break;

		CWInitTransportMessage(&msg, buf, readBytes, 1);
		if (!CWProtocolParseFragment(&msg, &frag_buffer, &pm)) {
			CWDebugErrorLog();
			CWReleaseMessage(&msg);
			continue;
		}

		CWProtocolTransportHeaderValues transportHeader;
		unsigned char radioMAC[6];

		CWResetNeighborDeadTimer();

		CWParseTransportHeader(&pm, &transportHeader, radioMAC);

		if (CWTransportHeaderIsKeepAlive(&pm)) {
			unsigned char *valPtr = NULL;
			unsigned short int elemType = 0;
			unsigned short int elemLen = 0;

			CWDebugLog("Got KeepAlive len: %zd from AC", pm.space);
			CWParseFormatMsgElem(&pm, &elemType, &elemLen);
			/* WARNING: this is not correct, a Data Channel Keep-Alive can contain
			 *          more Message Elements, see RFC-5415, Sect. 4.4.1
			 */
			valPtr = CWParseSessionID(&pm, elemLen);
			CW_FREE_OBJECT(valPtr);
		}
		else switch (CWTransportBinding(&pm)) {
			case BINDING_IEEE_802_3:
			{
				unsigned char *data = CWProtocolRetrievePtr(&pm);
				unsigned int length = CWProtocolLength(&pm);

				CWDebugLog("Got 802.3 len: %d from AC", length);

				/*MAC - begin */
				memcpy(&rawSockaddr.sll_addr, data, 6);

				/*MAC - end */
				rawSockaddr.sll_addr[6] = 0x00;	/*not used */
				rawSockaddr.sll_addr[7] = 0x00;	/*not used */

				rawSockaddr.sll_hatype = htons(data[12] << 8 | data[13]);

				if (sendto(gRawSock, data, length, 0, (struct sockaddr *)&rawSockaddr,
					   sizeof(rawSockaddr)) < 0)
					CWLog("Sending a data packet failed with: %s", strerror(errno));
				break;
			}

			case BINDING_IEEE_802_11:
			{
				unsigned char *data = CWProtocolRetrievePtr(&pm);
				unsigned int length = CWProtocolLength(&pm);

				struct ieee80211_hdr *hdr;
				u16 fc;
				hdr = (struct ieee80211_hdr *)data;
				fc = le_to_host16(hdr->frame_control);

				if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_MGMT
				    || isEAPOL_Frame(data, length))
				{
					CWDebugLog("Got 802.11 Management Packet (stype=%d) from AC(hostapd) len: %d",
						   WLAN_FC_GET_STYPE(fc), length);
					CWWTPsend_data_to_hostapd(data, length);
				}
				else if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_DATA) {
					if (WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_NULLFUNC) {
						CWDebugLog("Got 802.11 Data Packet (stype=%d) from AC(hostapd) len: %d",
							   WLAN_FC_GET_STYPE(fc), length);
						CWWTPsend_data_to_hostapd(data, length);
					} else {
						CWDebugLog("Got 802.11 Data Packet (stype=%d) from AC(hostapd) len: %d",
							   WLAN_FC_GET_STYPE(fc), length);
						CWWTPSendFrame(data, length);
					}
				} else
					CWLog("Control/Unknow Type type=%d", WLAN_FC_GET_TYPE(fc));
				break;
			}

			default:
				CWLog("Unknow transport binding");
				break;
			}
		CWReleaseMessage(&pm);
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

			CWProtocolMessage pm;
			CWProtocolTransportHeaderValues transportHeader;
/*
			msg.data = NULL;
			msg.space = msg.pos = 0;
*/
			if (!(CWReceiveMessage(&pm))) {
				CWReleaseMessage(&pm);
				CWLog("Failure Receiving Response");
				break;
			}

			CWParseTransportHeader(&pm, &transportHeader, NULL);

			if (!CWErr(CWWTPManageGenericRunMessage(&pm))) {
				if (CWErrorGetLastErrorCode() == CW_ERROR_INVALID_FORMAT) {
					/* Log and ignore message */
					CWErrorHandleLast();
					CWLog("--> Received something different from a valid Run Message");
				} else {
					CWReleaseMessage(&pm);
					CWLog("--> Critical Error Managing Generic Run Message... we enter RESET State");
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

CWBool CWWTPManageGenericRunMessage(CWProtocolMessage *pm)
{
	CWControlHeaderValues controlVal;

	assert(pm != NULL);

	/* TODO:
	 * check to see if a time-out on session occure...
	 * In case it happens it should go back to CW_ENTER_RESET
	 */
	if (!CWResetHeartbeatTimer())
		return CW_FALSE;

	/* will be handled by the caller */
	if (!(CWParseControlHeader(pm, &controlVal)))
		return CW_FALSE;

	int len = controlVal.msgElemsLen - CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;

	int pendingMsgIndex = 0;
	pendingMsgIndex = CWFindPendingRequestMsgsBox(gPendingRequestMsgs,
						      MAX_PENDING_REQUEST_MSGS,
						      controlVal.messageTypeValue, controlVal.seqNum);

	/* we have received a new Request or an Echo Response */
	if (pendingMsgIndex < 0) {
		CWTransportMessage tm;

		CW_ZERO_MEMORY(&tm, sizeof(tm));

		switch (controlVal.messageTypeValue) {
		case CW_MSG_TYPE_VALUE_CONFIGURE_UPDATE_REQUEST:
		{
			CWProtocolResultCode resultCode = CW_PROTOCOL_FAILURE;
			CWProtocolConfigurationUpdateRequestValues values;
			int updateRequestType;

			CWLog("Configuration Update Request received");

			/* assume AC has gone to Run state, reset Data Channel Keep Alive */
			gDataChannelKeepAliveInterval = gConfigDataChannelKeepAliveInterval;

			if (!CWParseConfigurationUpdateRequest(pm, len, &values, &updateRequestType))
				return CW_FALSE;

			if (!CWSaveConfigurationUpdateRequest(&values, &resultCode, &updateRequestType))
				return CW_FALSE;

			/*
			  if ( updateRequestType == BINDING_MSG_ELEMENT_TYPE_OFDM_CONTROL )
			  break;
			*/

			if (!CWAssembleConfigurationUpdateResponse(&tm, gWTPPathMTU, controlVal.seqNum, resultCode, values))
				return CW_FALSE;

			break;
		}

		case CW_MSG_TYPE_VALUE_CLEAR_CONFIGURATION_REQUEST:
		{
			CWProtocolResultCode resultCode = CW_PROTOCOL_FAILURE;

			CWLog("Clear Configuration Request received");
			/*WTP RESET ITS CONFIGURAION TO MANUFACTURING DEFAULT} */
			if (!CWSaveClearConfigurationRequest(&resultCode))
				return CW_FALSE;
			if (!CWAssembleClearConfigurationResponse(&tm, gWTPPathMTU, controlVal.seqNum, resultCode))
				return CW_FALSE;

			break;
		}

		case CW_MSG_TYPE_VALUE_STATION_CONFIGURATION_REQUEST:
		{
			CWProtocolResultCode resultCode = CW_PROTOCOL_SUCCESS;

			//CWProtocolStationConfigurationRequestValues values;  --> da implementare
			CWLog("Station Configuration Request received");

			if (!CWParseStationConfigurationRequest(pm, len))
				return CW_FALSE;
			    if (!CWAssembleStationConfigurationResponse(&tm, gWTPPathMTU, controlVal.seqNum, resultCode))
				return CW_FALSE;

			break;
		}

		case CW_MSG_TYPE_VALUE_WLAN_CONFIGURATION_REQUEST:
		{
			CWProtocolResultCode resultCode = CW_PROTOCOL_SUCCESS;

			CWLog("WLAN Configuration Request received");

			/* assume AC has gone to Run state, reset Data Channel Keep Alive */
			gDataChannelKeepAliveInterval = gConfigDataChannelKeepAliveInterval;

			if (!CWParseWLANConfigurationRequest(pm, len))
				return CW_FALSE;
			if (!CWAssembleWLANConfigurationResponse(&tm, gWTPPathMTU, controlVal.seqNum, resultCode))
				return CW_FALSE;

			break;
		}

		case CW_MSG_TYPE_VALUE_ECHO_RESPONSE:
			CWLog("Echo Response received");

			if (!CWParseEchoResponse(pm, len))
				return CW_FALSE;

			break;

		default:
			/*
			 * We can't recognize the received Request so
			 * we have to send a corresponding response
			 * containing a failure result code
			 */
			CWLog("--> invalid Request %d (0x%04x) in Run State... we send a failure Response",
			      controlVal.messageTypeValue, controlVal.messageTypeValue);

			if (!CWAssembleUnrecognizedMessageResponse(&tm, gWTPPathMTU, controlVal.seqNum, controlVal.messageTypeValue + 1))
				return CW_FALSE;

			/* return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
			 *             "Received Message not valid in Run State");
			 */
		}

		if (tm.count > 0) {
			int i;
			for (i = 0; i < tm.count; i++) {
#ifdef CW_NO_DTLS
				if (!CWNetworkSendUnsafeConnected(gWTPSocket, tm.parts[i].data, tm.parts[i].pos))
#else
				if (!CWSecuritySend(gWTPSession, tm.parts[i].data, tm.parts[i].pos))
#endif
				{
					CWLog("Error sending message");
					CWReleaseTransportMessage(&tm);
					return CW_FALSE;
				}
			}

			CWLog("Message Sent\n");
			CWReleaseTransportMessage(&tm);

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
		CWResetPendingMsgBox(gPendingRequestMsgs + pendingMsgIndex);
	}

	CWReleaseMessage(pm);
	return CW_TRUE;
}

/*______________________________________________________________*/
/*  *******************___TIMER HANDLERS___*******************  */
void CWWTPHeartBeatTimerExpiredHandler(void *arg)
{

	CWList msgElemList = NULL;
	CWTransportMessage tm;
	int seqNum;

	CWLog("WTP HeartBeat Timer Expired... we send an ECHO Request");

	CWLog("\n");
	CWLog("#________ Echo Request Message (Run) ________#");

	/* Send WTP Event Request */
	seqNum = CWGetSeqNum();

	if (!CWAssembleEchoRequest(&tm, gWTPPathMTU, seqNum, msgElemList)) {
		CWDebugLog("Failure Assembling Echo Request");
		CWReleaseTransportMessage(&tm);
		return;
	}

	int i;
	for (i = 0; i < tm.count; i++) {
#ifdef CW_NO_DTLS
		if (!CWNetworkSendUnsafeConnected(gWTPSocket, tm.parts[i].data, tm.parts[i].pos))
#else
		if (!CWSecuritySend(gWTPSession, tm.parts[i].data, tm.parts[i].pos))
#endif
		{
			CWLog("Failure sending Request");
			CWReleaseTransportMessage(&tm);
			break;
		}
	}

	CWReleaseTransportMessage(&tm);

	if (!CWStartHeartbeatTimer())
		return;
}

void CWWTPKeepAliveDataTimerExpiredHandler(void *arg)
{
	int k;
	CWTransportMessage tm;
	CWProtocolMessage sessionIDmsgElem;

	CWLog("WTP KeepAliveDataTimer Expired... we send an Data Channel Keep-Alive");

	CWLog("\n");
	CWLog("#________ Keep-Alive Message (Run) ________#");

	if (!CWResetDataChannelKeepAlive()) {
		setRunChannelState(CS_FAILED);
		return;
	}

	CW_ZERO_MEMORY(&sessionIDmsgElem, sizeof(CWProtocolMessage));
	CWAssembleMsgElemSessionID(NULL, &sessionIDmsgElem, &gWTPSessionID[0]);

	/* Send WTP Event Request */
	if (!CWAssembleDataMessage(&tm, gWTPPathMTU, 1, BINDING_IEEE_802_3, CW_TRUE, CW_FALSE, NULL, NULL, &sessionIDmsgElem)) {
		CWDebugLog("Failure Assembling KeepAlive Message");
		CWReleaseMessage(&sessionIDmsgElem);

		setRunChannelState(CS_FAILED);
		return;
	}

	for (k = 0; k < tm.count; k++) {
		if (!CWNetworkSendUnsafeConnected(gWTPDataSocket, tm.parts[k].data, tm.parts[k].pos)) {
			CWLog("Failure sending KeepAlive Message");
			setRunChannelState(CS_FAILED);
			break;
		}
	}

	CWReleaseTransportMessage(&tm);
}

void CWWTPNeighborDeadTimerExpired(void *arg)
{
	CWLog("WTP NeighborDead Timer Expired... we consider Peer Dead.");
	setRunChannelState(CS_TIMEOUT);
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
CWBool CWAssembleEchoRequest(CWTransportMessage *tm, int PMTU, int seqNum, CWList msgElemList)
{
	struct timeval tv;
	CWProtocolMessage msg;

	assert(tm != NULL);

	gettimeofday(&tv, NULL);

	CWLog("Assembling Echo Request...");
	if (!CWInitMessage(NULL, &msg, CW_MSG_TYPE_VALUE_ECHO_REQUEST, seqNum) ||
	    !CWAssembleMsgElemVendorTPWTPTimestamp(NULL, &msg, &tv))
		goto cw_assemble_error;
	CWFinalizeMessage(&msg);

	if (!CWAssembleMessage(tm, PMTU, &msg))
		goto cw_assemble_error;

	CWLog("Echo Request Assembled");
	return CW_TRUE;

 cw_assemble_error:
	CWReleaseMessage(&msg);
        return CW_FALSE;
}

CWBool CWAssembleWTPDataTransferRequest(CWTransportMessage *tm, int PMTU, int seqNum, CWList msgElemList)
{
	CWProtocolMessage msg;
	CWListElement *current;

	assert(tm != NULL);
	assert(msgElemList != NULL);

	CWLog("Assembling WTP Data Transfer Request...");
	if (!CWInitMessage(NULL, &msg, CW_MSG_TYPE_VALUE_DATA_TRANSFER_REQUEST, seqNum))
		goto cw_assemble_error;

	CWListForeach(msgElemList, current) {
		switch (((CWMsgElemData *) current->data)->type) {
		case CW_MSG_ELEMENT_DATA_TRANSFER_DATA_CW_TYPE:
			if (!CWAssembleMsgElemDataTransferData
			    (NULL, &msg, ((CWMsgElemData *) current->data)->value))
				goto cw_assemble_error;
			break;

#if 0
		case CW_MSG_ELEMENT_DATA_TRANSFER_MODE_CW_TYPE:
			if (!CWAssembleMsgElemDataTansferMode(NULL, &msg))
				goto cw_assemble_error;
			break;
#endif

		default:
			goto cw_assemble_error;
			break;
		}
	}
	CWFinalizeMessage(&msg);

	if (!CWAssembleMessage(tm, PMTU, &msg))
		goto cw_assemble_error;

	CWLog("WTP Data Transfer Request Assembled");
	return CW_TRUE;

 cw_assemble_error:
	CWReleaseMessage(&msg);
	return CW_FALSE;	// error will be handled by the caller
}

CWBool CWAssembleWTPEventRequest(CWTransportMessage *tm, int PMTU, int seqNum, CWList msgElemList)
{

	CWProtocolMessage msg;
	CWListElement *current;

	assert(tm != NULL);
	assert(msgElemList != NULL);

	CWLog("Assembling WTP Event Request...");
	if (!CWInitMessage(NULL, &msg, CW_MSG_TYPE_VALUE_WTP_EVENT_REQUEST, seqNum))
		goto cw_assemble_error;

	CWListForeach(msgElemList, current) {
		switch (((CWMsgElemData *) current->data)->type) {

		case CW_MSG_ELEMENT_CW_DECRYPT_ER_REPORT_CW_TYPE:
			if (!CWAssembleMsgElemDecryptErrorReport
			     (NULL, &msg, ((CWMsgElemData *) current->data)->value))
				goto cw_assemble_error;
			break;
		case CW_MSG_ELEMENT_DUPLICATE_IPV4_ADDRESS_CW_TYPE:
			if (!CWAssembleMsgElemDuplicateIPv4Address(NULL, &msg))
				goto cw_assemble_error;
			break;
		case CW_MSG_ELEMENT_DUPLICATE_IPV6_ADDRESS_CW_TYPE:
			if (!CWAssembleMsgElemDuplicateIPv6Address(NULL, &msg))
				goto cw_assemble_error;
			break;
		case CW_MSG_ELEMENT_WTP_OPERAT_STATISTICS_CW_TYPE:
			if (!CWAssembleMsgElemWTPOperationalStatistics
			     (NULL, &msg, ((CWMsgElemData *) current->data)->value))
				goto cw_assemble_error;
			break;
		case CW_MSG_ELEMENT_WTP_RADIO_STATISTICS_CW_TYPE:
			if (!CWAssembleMsgElemWTPRadioStatistics
			     (NULL, &msg, ((CWMsgElemData *) current->data)->value))
				goto cw_assemble_error;
			break;
		case CW_MSG_ELEMENT_WTP_REBOOT_STATISTICS_CW_TYPE:
			if (!CWAssembleMsgElemWTPRebootStatistics(NULL, &msg))
				goto cw_assemble_error;
			break;
		default:
			goto cw_assemble_error;
			break;
		}
	}
	CWFinalizeMessage(&msg);

	if (!CWAssembleMessage(tm, PMTU, &msg))
		goto cw_assemble_error;

	CWLog("WTP Event Request Assembled");
	return CW_TRUE;

 cw_assemble_error:
	CWReleaseMessage(&msg);
	return CW_FALSE;
}

CWBool CWAssembleConfigurationUpdateResponse(CWTransportMessage *tm, int PMTU, int seqNum,
					     CWProtocolResultCode resultCode,
					     CWProtocolConfigurationUpdateRequestValues values)
{
	CWProtocolMessage msg;
	CWProtocolVendorSpecificValues *protoValues = NULL;

	assert(tm != NULL);

	/*Get protocol data if we have it */
	if (values.protocolValues)
		protoValues = (CWProtocolVendorSpecificValues *) values.protocolValues;

	CWLog("Assembling Configuration Update Response...");
	if (!CWInitMessage(NULL, &msg, CW_MSG_TYPE_VALUE_CONFIGURE_UPDATE_RESPONSE, seqNum))
		goto cw_assemble_error;

	if (protoValues) {
		switch (protoValues->vendorPayloadType) {
		case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_UCI:
		case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_WUM:
			if (!CWAssembleVendorMsgElemResultCodeWithPayload(NULL, &msg, resultCode, protoValues))
				goto cw_assemble_error;
			break;

		default:
			/*Result Code only */
			if (!CWAssembleMsgElemResultCode(NULL, &msg, resultCode))
				goto cw_assemble_error;
			break;
		}
	} else {
		/*Result Code only */
		if (!CWAssembleMsgElemResultCode(NULL, &msg, resultCode))
			goto cw_assemble_error;
	}
	CWFinalizeMessage(&msg);

	if (!CWAssembleMessage(tm, PMTU, &msg))
		goto cw_assemble_error;

	CWLog("Configuration Update Response Assembled");
	return CW_TRUE;

 cw_assemble_error:
	CWReleaseMessage(&msg);
        return CW_FALSE;
}

CWBool CWAssembleClearConfigurationResponse(CWTransportMessage *tm, int PMTU,
					    int seqNum, CWProtocolResultCode resultCode)
{
	CWProtocolMessage msg;

	assert(tm != NULL);

	CWLog("Assembling Clear Configuration Response...");
	if (!CWInitMessage(NULL, &msg, CW_MSG_TYPE_VALUE_CLEAR_CONFIGURATION_RESPONSE, seqNum) ||
	    !CWAssembleMsgElemResultCode(NULL, &msg, resultCode))
		goto cw_assemble_error;
	CWFinalizeMessage(&msg);

	if (!CWAssembleMessage(tm, PMTU, &msg))
		goto cw_assemble_error;

	CWLog("Clear Configuration Response Assembled");
	return CW_TRUE;

 cw_assemble_error:
	CWReleaseMessage(&msg);
        return CW_FALSE;
}

CWBool CWAssembleStationConfigurationResponse(CWTransportMessage *tm, int PMTU,
					      int seqNum, CWProtocolResultCode resultCode)
{

	CWProtocolMessage msg;

	assert(tm != NULL);

	CWLog("Assembling Sattion Configuration Response...");

	if (!CWInitMessage(NULL, &msg, CW_MSG_TYPE_VALUE_STATION_CONFIGURATION_RESPONSE, seqNum) ||
	    !CWAssembleMsgElemResultCode(NULL, &msg, resultCode))
		goto cw_assemble_error;
	CWFinalizeMessage(&msg);

	if (!CWAssembleMessage(tm, PMTU, &msg))
		goto cw_assemble_error;

	CWLog("Station Configuration Response Assembled");
	return CW_TRUE;

 cw_assemble_error:
	CWReleaseMessage(&msg);
        return CW_FALSE;
}

CWBool CWAssembleWLANConfigurationResponse(CWTransportMessage *tm, int PMTU, int seqNum,
					   CWProtocolResultCode resultCode)
{
	CWProtocolMessage msg;

	assert(tm != NULL);

	CWLog("Assembling WLAN Configuration Response...");

	if (!CWInitMessage(NULL, &msg, CW_MSG_TYPE_VALUE_WLAN_CONFIGURATION_RESPONSE, seqNum) ||
	    !CWAssembleMsgElemResultCode(NULL, &msg, resultCode) ||
	    !CWAssembleMsgElemVendorSpecificPayload(NULL, &msg))
		goto cw_assemble_error;
	CWFinalizeMessage(&msg);

	if (!CWAssembleMessage(tm, PMTU, &msg))
		goto cw_assemble_error;

	CWLog("WLAN Configuration Response Assembled");
	return CW_TRUE;

 cw_assemble_error:
	CWReleaseMessage(&msg);
        return CW_FALSE;
}

/*_______________________________________________________________*/
/*  *******************___PARSE FUNCTIONS___*******************  */
CWBool CWParseConfigurationUpdateRequest(CWProtocolMessage *pm, int len,
					 CWProtocolConfigurationUpdateRequestValues * valuesPtr, int *updateRequestType)
{

	CWBool acAddressWithPrioFound = CW_FALSE;

	assert(pm != NULL);

	CWLog("Parsing Configuration Update Request...");

	CW_ZERO_MEMORY(valuesPtr, sizeof(CWProtocolConfigurationUpdateRequestValues));

	CWParseMessageElementStart(pm);

	/* parse message elements */
	CWParseMessageElementWhile(pm, len) {
		unsigned short int elemType = 0;
		unsigned short int elemLen = 0;

		CWParseFormatMsgElem(pm, &elemType, &elemLen);

		/* CWDebugLog("Parsing Message Element: %u, elemLen: %u", elemType, elemLen); */
		CWLog("Parsing Message Element: %u, elemLen: %u", elemType, elemLen);

		switch (elemType) {
		case CW_MSG_ELEMENT_TIMESTAMP_CW_TYPE:
			valuesPtr->timeStamp = CWProtocolRetrieve32(pm);
			break;

		case CW_MSG_ELEMENT_CW_TIMERS_CW_TYPE:
			CWParseCWTimers(pm, elemLen, &valuesPtr->CWTimers);
			break;

		case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_BW_CW_TYPE: {
			unsigned int vendorId = CWProtocolRetrieve32(pm);
			unsigned short int vendorElemType = CWProtocolRetrieve16(pm);
			elemLen -= 6;

			CWDebugLog("Parsing Vendor Message Element, Vendor: %u, Element: %u", vendorId, vendorElemType);
			switch (vendorId) {
			case CW_IANA_ENTERPRISE_NUMBER_VENDOR_TRAVELPING: {
				CWDebugLog("Parsing TP Vendor Message Element: %u", vendorElemType);
				switch (vendorElemType) {
				case CW_MSG_ELEMENT_TRAVELPING_IEEE_80211_WLAN_HOLD_TIME:
					CWParseTPIEEE80211WLanHoldTime(pm, elemLen, &valuesPtr->vendorTP_IEEE80211WLanHoldTime);
					break;

				case CW_MSG_ELEMENT_TRAVELPING_DATA_CHANNEL_DEAD_INTERVAL:
					CWParseTPDataChannelDeadInterval(pm, elemLen, &valuesPtr->vendorTP_DataChannelDeadInterval);
					break;

				case CW_MSG_ELEMENT_TRAVELPING_AC_JOIN_TIMEOUT:
					CWParseTPACJoinTimeout(pm, elemLen, &valuesPtr->vendorTP_ACJoinTimeout);
					break;

                                case CW_MSG_ELEMENT_TRAVELPING_AC_ADDRESS_LIST_WITH_PRIORITY:
					if (acAddressWithPrioFound != CW_TRUE) {
						CWResetDiscoveredACAddresses();
						acAddressWithPrioFound = CW_TRUE;
					}
					if (!CWParseACAddressListWithPrio(pm, len))
						return CW_FALSE;
					break;

				default:
					CWLog("unknown TP Vendor Message Element: %u", vendorElemType);

					/* ignore unknown vendor extensions */
					CWParseSkipElement(pm, len);
					break;
				}
				break;

			default:
				CWLog("unknown Vendor Message Element, Vendor: %u, Element: %u", vendorId, vendorElemType);

				/* ignore unknown vendor extensions */
				CWParseSkipElement(pm, len);
				break;
			}
			}

			break;
		}

		case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE:
			if (!CWParseVendorPayload(valuesPtr, pm, elemLen, &valuesPtr->protocolValues))
				return CW_FALSE;
			break;

		case BINDING_MIN_ELEM_TYPE...BINDING_MAX_ELEM_TYPE:
			if (!CWBindingParseConfigurationUpdateRequestElement(valuesPtr, pm, elemType, elemLen, &valuesPtr->bindingValues))
				return CW_FALSE;
			*updateRequestType = elemType;
			break;

		default:
			CWLog("unknown Message Element, Element; %u", elemType);

			/* ignore unknown IE */
			CWParseSkipElement(pm, len);
		}
	}
	CWParseMessageElementEnd(pm, len);

	CWLog("Configure Update Request Parsed");
	return CW_TRUE;
}

CWBool CWParseWLANConfigurationRequest(CWProtocolMessage *pm, int len)
{
	assert(pm != NULL);

	CWParseMessageElementStart(pm);

	/* parse message elements */
	CWParseMessageElementWhile(pm, len) {
		unsigned short int elemType = 0;
		unsigned short int elemLen = 0;

		CWParseFormatMsgElem(pm, &elemType, &elemLen);

		switch (elemType) {
		case CW_MSG_ELEMENT_IEEE80211_ADD_WLAN_CW_TYPE:
			if (!CWParseAddWLAN(pm, elemLen))
				return CW_FALSE;
			break;

		case CW_MSG_ELEMENT_IEEE80211_DELETE_WLAN_CW_TYPE:
			if (!CWParseDeleteWLAN(pm, elemLen))
				return CW_FALSE;
			break;

		default:
			CWLog("unknown Message Element, Element; %u", elemType);

			/* ignore unknown IE */
			CWParseSkipElement(pm, len);
		}
	}
	CWParseMessageElementEnd(pm, len);

	CWLog("Station WLAN Request Parsed");
	return CW_TRUE;
}

CWBool CWParseStationConfigurationRequest(CWProtocolMessage *pm, int len)
{
	assert(pm != NULL);

	CWParseMessageElementStart(pm);

	/* parse message elements */
	CWParseMessageElementWhile(pm, len) {
		unsigned short int elemType = 0;
		unsigned short int elemLen = 0;

		CWParseFormatMsgElem(pm, &elemType, &elemLen);

		switch (elemType) {
		case CW_MSG_ELEMENT_ADD_STATION_CW_TYPE:
			if (!CWParseAddStation(pm, elemLen))
				return CW_FALSE;
			break;

		case CW_MSG_ELEMENT_DELETE_STATION_CW_TYPE:
			if (!CWParseDeleteStation(pm, elemLen))
				return CW_FALSE;
			break;

		default:
			CWLog("unknown Message Element, Element; %u", elemType);

			/* ignore unknown IE */
			CWParseSkipElement(pm, len);
		}
	}

	CWParseMessageElementEnd(pm, len);

	CWLog("Station Configuration Request Parsed");
	return CW_TRUE;
}

#if 0
CWBool CWParseWTPEventResponseMessage(unsigned char *msg, int len, int seqNum, void *values)
{

	CWControlHeaderValues controlVal;
	CWProtocolMessage pm;

	if (msg == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CWLog("Parsing WTP Event Response...");

	CWInitTransportMessage(&pm, msg, len);

	/* error will be handled by the caller */
	if (!(CWParseControlHeader(&pm, &controlVal)))
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

	CWParseTransportMessageEnd(&pm);

	CWLog("WTP Event Response Parsed...");
	return CW_TRUE;
}
#endif

CWBool CWParseEchoResponse(CWProtocolMessage *pm, int len)
{
	assert(pm != NULL);

	CWLog("Parsing Echo Response...");
	CWParseMessageElementStart(pm);

	/* parse message elements */
	CWParseMessageElementWhile(pm, len) {
		unsigned short int elemType = 0;
		unsigned short int elemLen = 0;

		CWParseFormatMsgElem(pm, &elemType, &elemLen);
		CWLog("Parsing Message Element: %u, elemLen: %u", elemType, elemLen);

		switch (elemType) {
		case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_BW_CW_TYPE: {
			unsigned int vendorId = CWProtocolRetrieve32(pm);
			unsigned short int vendorElemType = CWProtocolRetrieve16(pm);
			elemLen -= 6;

			CWDebugLog("Parsing Vendor Message Element, Vendor: %u, Element: %u", vendorId, vendorElemType);
			switch (vendorId) {
			case CW_IANA_ENTERPRISE_NUMBER_VENDOR_TRAVELPING: {
				CWDebugLog("Parsing TP Vendor Message Element: %u", vendorElemType);
				switch (vendorElemType) {
				case CW_MSG_ELEMENT_TRAVELPING_WTP_TIMESTAMP: {
					struct timeval tv, now;

					if (!CWParseVendorTPWTPTimestamp(pm, elemLen, &tv))
						return CW_FALSE;

					gettimeofday(&now, NULL);
					timersub(&now, &tv, &gEchoLatency);

					CWLog("Echo Latency: %ld.%03ld ms", gEchoLatency.tv_sec * 1000 + gEchoLatency.tv_usec / 1000, gEchoLatency.tv_usec % 1000);
					break;
				}

				default:
					CWLog("ignore TP Vendor Message Element: %u", vendorElemType);

					/* ignore unknown vendor extensions */
					CWParseSkipElement(pm, len);
					break;
				}
				break;

			default:
				CWLog("ignore Vendor Message Element, Vendor: %u, Element: %u", vendorId, vendorElemType);

				/* ignore unknown vendor extensions */
				CWParseSkipElement(pm, len);
				break;
			}
			}

			break;
		}

		default:
			CWLog("unknown Message Element, Element; %u", elemType);

			/* ignore unknown IE */
			CWParseSkipElement(pm, len);
			break;
		}
	}
	CWParseMessageElementEnd(pm, len);

	CWLog("Echo Response Parsed");
	return CW_TRUE;
}

/*______________________________________________________________*/
/*  *******************___SAVE FUNCTIONS___*******************  */
#if 0
CWBool CWSaveWTPEventResponseMessage(void *WTPEventResp)
{
	CWDebugLog("Saving WTP Event Response...");
	CWDebugLog("WTP Response Saved");
	return CW_TRUE;
}
#endif

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
