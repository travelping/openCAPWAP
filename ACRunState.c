/************************************************************************************************
 * Copyright (c) 2006-2009 Laboratorio di Sistemi di Elaborazione e Bioingegneria Informatica   *
 *                          Universita' Campus BioMedico - Italy                                *
 *                                                                                              *
 * This program is free software; you can redistribute it and/or modify it under the terms      *
 * of the GNU General Public License as published by the Free Software Foundation; either       *
 * version 2 of the License, or (at your option) any later version.                             *
 *                                                                                              *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY              *
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A              *
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.                     *
 *                                                                                              *
 * You should have received a copy of the GNU General Public License along with this            *
 * program; if not, write to the:                                                               *
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,                         *
 * MA  02111-1307, USA.                                                                         *
 *                                                                                              *
 * In addition, as a special exception, the copyright holders give permission to link the       *
 * code of portions of this program with the OpenSSL library under certain conditions as        *
 * described in each individual source file, and distribute linked combinations including       *
 * the two. You must obey the GNU General Public License in all respects for all of the         *
 * code used other than OpenSSL.  If you modify file(s) with this exception, you may            *
 * extend this exception to your version of the file(s), but you are not obligated to do        *
 * so.  If you do not wish to do so, delete this exception statement from your version.         *
 * If you delete this exception statement from all source files in the program, then also       *
 * delete it here.                                                                              *
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

#include "CWAC.h"
#include "ACipcHostapd.h"
#include "CWVendorPayloads.h"
#include "CWFreqPayloads.h"
#include "WUM.h"
#include "common.h"
#include "ieee802_11_defs.h"

static CWBool CWACParseGenericRunMessage(int WTPIndex, CWProtocolMessage * msg, CWControlHeaderValues * controlVal);
static CWBool CWParseConfigurationUpdateResponseMessage(CWProtocolMessage *pm, int len,
							CWProtocolResultCode * resultCode,
							CWProtocolVendorSpecificValues ** protocolValues);
static CWBool CWSaveConfigurationUpdateResponseMessage(CWProtocolResultCode resultCode,
						       int WTPIndex, CWProtocolVendorSpecificValues * protocolValues);
static CWBool CWParseClearConfigurationResponseMessage(CWProtocolMessage *pm, int len, CWProtocolResultCode * resultCode);
static CWBool CWParseWLANConfigurationResponseMessage(CWProtocolMessage *pm, int len, CWProtocolResultCode * resultCode);
static CWBool CWParseStationConfigurationResponseMessage(CWProtocolMessage *pm,
							 int len, CWProtocolResultCode * resultCode);
static CWBool CWParseWTPDataTransferRequestMessage(CWProtocolMessage *pm,
						   int len, CWProtocolWTPDataTransferRequestValues * valuesPtr);
static CWBool CWAssembleWTPDataTransferResponse(CWTransportMessage *tm, int PMTU, int seqNum);
static CWBool CWParseWTPEventRequestMessage(CWProtocolMessage *pm, int len, CWProtocolWTPEventRequestValues * valuesPtr);
static CWBool CWSaveWTPEventRequestMessage(CWProtocolWTPEventRequestValues * WTPEventRequest,
					   CWWTPProtocolManager * WTPProtocolManager);
static CWBool CWAssembleWTPEventResponse(CWTransportMessage *tm, int PMTU, int seqNum);
static CWBool CWParseChangeStateEventRequestMessage2(CWProtocolMessage *pm,
						     int len, CWProtocolChangeStateEventRequestValues ** valuesPtr);
static CWBool CWParseEchoRequestMessage(CWProtocolMessage *pm, int len);
static CWBool CWAssembleEchoResponse(CWTransportMessage *tm, int PMTU, int seqNum);
static CWBool CWStartNeighborDeadTimer(int WTPIndex);
static CWBool CWStopNeighborDeadTimer(int WTPIndex);
static CWBool CWRestartNeighborDeadTimer(int WTPIndex);

#if 0
static CWBool CWRestartNeighborDeadTimerForEcho(int WTPIndex);
#endif

int flush_pcap(u_char * buf, int len, char *filename)
{

	FILE *file;
	file = fopen(filename, "a+");
	u_char index = 0x00;
	int cnt = 0;
	int i;
	int giro = 0;
	for (i = 0; cnt < len; i++) {
		fprintf(file, "0%02X0   ", index);
		for (; cnt < len;) {
			fprintf(file, "%02X ", buf[cnt]);
			cnt++;
			if (giro == 15) {
				giro = 0;
				break;
			}
			giro++;
		}
		fprintf(file, "\n");
		index++;
	}

	fprintf(file, "\n");
	fclose(file);
	return 0;
}

#define HLEN_80211 24
int isEAPOL_Frame(unsigned char *buf, int len)
{
	unsigned char rfc1042_header[6] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };
	int i;

	for (i = 0; i < 6; i++)
		if (rfc1042_header[i] != buf[i + HLEN_80211])
			return 0;
	return 1;
}

CWBool ACEnterRun(int WTPIndex, CWProtocolMessage *pm, CWBool dataFlag)
{
	int i;
	CWBool timerSet = CW_TRUE;
	CWControlHeaderValues controlVal;
	CWTransportMessage tm;
	unsigned char StationMacAddr[MAC_ADDR_LEN];
	char string[10];
	char socketctl_path_name[50];
	char socketserv_path_name[50];
	int msglen = pm->pos;

	pm->pos = 0;
	if (dataFlag) {
		/* We have received a Data Message... now just log this event and do actions by the dataType */

		CWDebugLog("--> Received a DATA Message");

		switch (pm->data_msgType) {
		case CW_DATA_MSG_FRAME_TYPE:
			/*Retrive mac address station from msg */
			memset(StationMacAddr, 0, MAC_ADDR_LEN);
			memcpy(StationMacAddr, pm->data + SOURCE_ADDR_START, MAC_ADDR_LEN);

			int seqNum = CWGetSeqNum();

			//Send a Station Configuration Request
			if (CWAssembleStationConfigurationRequest(&gWTPs[WTPIndex].messages, gWTPs[WTPIndex].pathMTU,
								  seqNum, StationMacAddr, CW_MSG_ELEMENT_ADD_STATION_CW_TYPE)) {
				if (CWACSendAcknowledgedPacket(WTPIndex, CW_MSG_TYPE_VALUE_STATION_CONFIGURATION_RESPONSE, seqNum))
					return CW_TRUE;
				else
					CWACStopRetransmission(WTPIndex);
				CWDebugLog("Send a Station Configuration Request");
			}
			break;

		case CW_DATA_MSG_KEEP_ALIVE_TYPE:
		{
			unsigned char *valPtr = NULL;
			CWProtocolMessage sessionIDmsgElem;
			int i;
			int dataSocket = 0;
			unsigned short int elemType = 0;
			unsigned short int elemLen = 0;
			CWNetworkLev4Address address;

			CWParseFormatMsgElem(pm, &elemType, &elemLen);
			valPtr = CWParseSessionID(pm, elemLen);

			CW_ZERO_MEMORY(&sessionIDmsgElem, sizeof(CWProtocolMessage));
			CWAssembleMsgElemSessionID(NULL, &sessionIDmsgElem, valPtr);

			if (!CWAssembleDataMessage(&tm, gWTPs[WTPIndex].pathMTU, 1, BINDING_IEEE_802_11, CW_TRUE, CW_FALSE, NULL, NULL, &sessionIDmsgElem)) {
				CWLog("Failure Assembling KeepAlive Request");
				CWReleaseTransportMessage(&tm);
				CWReleaseMessage(&sessionIDmsgElem);
				return CW_FALSE;
			}

			for (i = 0; i < gACSocket.count; i++) {
				if (gACSocket.interfaces[i].sock == gWTPs[WTPIndex].socket) {
					dataSocket = gACSocket.interfaces[i].dataSock;
					CW_COPY_NET_ADDR_PTR(&address, &(gWTPs[WTPIndex].address));
					break;
				}
			}

			if (dataSocket == 0) {
				CWLog("data socket of WTP %d isn't ready.", WTPIndex);
				return CW_FALSE;
			}

			/* Set port and address of data tunnel */
			sock_set_port_cw((struct sockaddr *)&(address), htons(CW_DATA_PORT));

			for (i = 0; i < tm.count; i++) {
				if (!CWNetworkSendUnsafeUnconnected(dataSocket,
								    &(address), tm.parts[i].data, tm.parts[i].pos)) {
					CWLog("Failure sending  KeepAlive Request");
					CWReleaseTransportMessage(&tm);
					break;
				}
			}

			CWReleaseTransportMessage(&tm);
			CWReleaseMessage(&sessionIDmsgElem);
			break;
		}

		case CW_IEEE_802_3_FRAME_TYPE:
			CWDebugLog("Write 802.3 data to TAP[%d], len:%d", gWTPs[WTPIndex].tap_fd, msglen);
			if (write(gWTPs[WTPIndex].tap_fd, pm->data, msglen) < 0)
				CWLog("Sending a data packet to the tap if failed with: %s", strerror(errno));
			break;

		case CW_IEEE_802_11_FRAME_TYPE:
		{
			struct ieee80211_hdr *hdr;
			u16 fc;
			hdr = (struct ieee80211_hdr *)pm->data;
			fc = le_to_host16(hdr->frame_control);

			if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_MGMT || isEAPOL_Frame(pm->data, msglen)) {

				CWACsend_data_to_hostapd(WTPIndex, pm->data, msglen);

			} else if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_DATA) {

				if (WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_NULLFUNC) {

					CWACsend_data_to_hostapd(WTPIndex, pm->data, msglen);

				} else {

					int write_bytes =
					    write(gWTPs[WTPIndex].tap_fd, pm->data + HLEN_80211,
						  msglen - HLEN_80211);

					if (write_bytes != (msglen - 24)) {
						CWLog("%02X %02X %02X %02X %02X %02X ",
						      pm->data[0], pm->data[1], pm->data[2],
						      pm->data[3], pm->data[4], pm->data[5]);

						CWLog("Error:. RecvByte:%d, write_Byte:%d ", msglen - 24, write_bytes);
					}

				}

			} else {
				if (write(gWTPs[WTPIndex].tap_fd, pm->data + HLEN_80211, msglen - HLEN_80211) < 0)
					CWLog("Sending a data packet to the tap if failed with: %s", strerror(errno));

				CWDebugLog("Control Frame !!!\n");
			}

			//flush_pcap(pm->data, msglen, "cap_wtp_to_ac.txt");
			break;
		}

		case CW_DATA_MSG_FREQ_STATS_TYPE:
		{
			int cells;	/* How many cell are heard */
			int isAck;
			char *freqPayload;
			int socketIndex, indexToSend = htonl(WTPIndex);

			int sizeofAckInfoUnit = CW_FREQ_ACK_SIZE;
			int sizeofFreqInfoUnit = CW_FREQ_CELL_INFO_PAYLOAD_SIZE;
			int sizeOfPayload = 0, payload_offset = 0;

			CWDebugLog("Manage special data packets with frequency - Stats");

			/*-----------------------------------------------------------------------------------------------
			 *  Payload Management ( infos for frequency application) :
			 *      Ack       Structure : |  WTPIndex  |   Ack Value  |
			 *      Freq Info Structure : |  WTPIndex  |  Number of cells  |  Frequecies Info Payload |
			 *-----------------------------------------------------------------------------------------------*/

			memcpy(&isAck, pm->data, sizeof(int));

			isAck = ntohl(isAck);

			if (isAck == 0) {	/* isnt an ack message */
				memcpy(&cells, pm->data + sizeof(int), sizeof(int));
				cells = ntohl(cells);
				sizeOfPayload = (cells * sizeofFreqInfoUnit) + (2 * sizeof(int));
			} else {
				sizeOfPayload = sizeofAckInfoUnit;
			}

			if ((freqPayload = malloc(sizeOfPayload)) != NULL) {

				memset(freqPayload, 0, sizeOfPayload);
				memcpy(freqPayload, &indexToSend, sizeof(int));
				payload_offset += sizeof(int);

				if (isAck == 0) {
					memcpy(freqPayload + payload_offset, pm->data + sizeof(int),
					       sizeOfPayload - payload_offset);
				} else {
					memcpy(freqPayload + payload_offset, pm->data + sizeof(int),
					       sizeOfPayload - payload_offset);
				}

				socketIndex = gWTPs[WTPIndex].applicationIndex;

				/****************************************************
				 *      Forward payload to correct application      *
				 ****************************************************/

				if (!CWErr(CWThreadMutexLock(&appsManager.socketMutex[socketIndex]))) {
					CWLog("[ACrunState]:: Error locking socket Application Mutex");
					free(freqPayload);
					return CW_FALSE;
				}

				if (Writen(appsManager.appSocket[socketIndex], freqPayload, sizeOfPayload) < 0) {
					CWThreadMutexUnlock(&appsManager.socketMutex[socketIndex]);
					free(freqPayload);
					CWLog("[ACrunState]:: Error writing Message To Application");
					return CW_FALSE;
				}

				CWThreadMutexUnlock(&appsManager.socketMutex[socketIndex]);
				free(freqPayload);
			} else
				CWLog("[ACrunState]:: Malloc error (payload to frequency application");

			break;
		}

		case CW_DATA_MSG_STATS_TYPE:
			if (!UnixSocksArray[WTPIndex].data_stats_sock) {
				//Init Socket only the first time when the function is called
				if ((UnixSocksArray[WTPIndex].data_stats_sock =
				     socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
					CWDebugLog("Error creating socket for data send");
					return CW_FALSE;
				}

				memset(&(UnixSocksArray[WTPIndex].clntaddr), 0,
				       sizeof(UnixSocksArray[WTPIndex].clntaddr));
				UnixSocksArray[WTPIndex].clntaddr.sun_family = AF_UNIX;

				//make unix socket client path name by index i
				snprintf(string, sizeof(string), "%d", WTPIndex);
				string[sizeof(string) - 1] = 0;
				strcpy(socketctl_path_name, SOCKET_PATH_AC);
				strcat(socketctl_path_name, string);
				strcpy(UnixSocksArray[WTPIndex].clntaddr.sun_path, socketctl_path_name);

				unlink(socketctl_path_name);

				memset(&(UnixSocksArray[WTPIndex].servaddr), 0,
				       sizeof(UnixSocksArray[WTPIndex].servaddr));
				UnixSocksArray[WTPIndex].servaddr.sun_family = AF_UNIX;

				//make unix socket server path name by index i
				strcpy(socketserv_path_name, SOCKET_PATH_RECV_AGENT);
				strcat(socketserv_path_name, string);
				strcpy(UnixSocksArray[WTPIndex].servaddr.sun_path, socketserv_path_name);
				printf("\n%s\t%s", socketserv_path_name, socketctl_path_name);
				fflush(stdout);
			}

			int nbytes;
			int pDataLen = 656;	//len of Monitoring Data

			//Send data stats from AC thread to monitor client over unix socket
			nbytes = sendto(UnixSocksArray[WTPIndex].data_stats_sock, pm->data, pDataLen, 0,
					(struct sockaddr *)&(UnixSocksArray[WTPIndex].servaddr),
					sizeof(UnixSocksArray[WTPIndex].servaddr));
			if (nbytes < 0) {
				CWDebugLog("Error sending data over socket");
				return CW_FALSE;
			}
			break;
		}

		return CW_TRUE;
	}

	if (!(CWACParseGenericRunMessage(WTPIndex, pm, &controlVal))) {
		/* Two possible errors: WRONG_ARG and INVALID_FORMAT
		 * In the second case we have an unexpected response: ignore the
		 * message and log the event.
		 */
		return CW_FALSE;
	}

	switch (controlVal.messageTypeValue) {
	case CW_MSG_TYPE_VALUE_CONFIGURE_UPDATE_RESPONSE:
	{
		CWProtocolResultCode resultCode = 0;
		CWProtocolVendorSpecificValues *protocolValues = NULL;

		if (!CWParseConfigurationUpdateResponseMessage
		    (pm, controlVal.msgElemsLen, &resultCode, &protocolValues))
			return CW_FALSE;

		CWACStopRetransmission(WTPIndex);

		if (timerSet) {
			if (!CWRestartNeighborDeadTimer(WTPIndex)) {
				CWCloseThread();
			}
		} else {
			if (!CWStartNeighborDeadTimer(WTPIndex)) {
				CWCloseThread();
			}
		}

		CWSaveConfigurationUpdateResponseMessage(resultCode, WTPIndex, protocolValues);

		if (gWTPs[WTPIndex].interfaceCommandProgress == CW_TRUE) {

			CWThreadMutexLock(&gWTPs[WTPIndex].interfaceMutex);

			gWTPs[WTPIndex].interfaceResult = 1;
			gWTPs[WTPIndex].interfaceCommandProgress = CW_FALSE;
			CWSignalThreadCondition(&gWTPs[WTPIndex].interfaceComplete);

			CWThreadMutexUnlock(&gWTPs[WTPIndex].interfaceMutex);
		}

		break;
	}

	case CW_MSG_TYPE_VALUE_CHANGE_STATE_EVENT_REQUEST:
	{
		CWProtocolChangeStateEventRequestValues *valuesPtr;

		if (!(CWParseChangeStateEventRequestMessage2(pm, controlVal.msgElemsLen, &valuesPtr)))
			return CW_FALSE;
		if (timerSet) {
			if (!CWRestartNeighborDeadTimer(WTPIndex)) {
				CWCloseThread();
			}
		} else {
			if (!CWStartNeighborDeadTimer(WTPIndex)) {
				CWCloseThread();
			}
		}
		if (!(CWSaveChangeStateEventRequestMessage(valuesPtr, &(gWTPs[WTPIndex].WTPProtocolManager))))
			return CW_FALSE;
		if (!(CWAssembleChangeStateEventResponse(&tm, gWTPs[WTPIndex].pathMTU, controlVal.seqNum)))
			return CW_FALSE;
		break;
	}

	case CW_MSG_TYPE_VALUE_ECHO_REQUEST:
	{
		if (!(CWParseEchoRequestMessage(pm, controlVal.msgElemsLen)))
			return CW_FALSE;
		if (timerSet) {
			if (!CWRestartNeighborDeadTimer(WTPIndex)) {
				CWCloseThread();
			}
		} else {
			if (!CWStartNeighborDeadTimer(WTPIndex)) {
					CWCloseThread();
			}
		}

		if (!(CWAssembleEchoResponse(&tm, gWTPs[WTPIndex].pathMTU, controlVal.seqNum)))
			return CW_FALSE;
		break;
	}

	case CW_MSG_TYPE_VALUE_STATION_CONFIGURATION_RESPONSE:
	{
		CWProtocolResultCode resultCode;
		if (!(CWParseStationConfigurationResponseMessage(pm, controlVal.msgElemsLen, &resultCode)))
			return CW_FALSE;
		CWACStopRetransmission(WTPIndex);
		if (timerSet) {
			if (!CWRestartNeighborDeadTimer(WTPIndex)) {
				CWCloseThread();
			}
		} else {
			if (!CWStartNeighborDeadTimer(WTPIndex)) {
				CWCloseThread();
			}
		}
		//CWSaveStationConfigurationResponseMessage(resultCode, WTPIndex);  <-- Must be Implemented ????

		break;
	}

	case CW_MSG_TYPE_VALUE_CLEAR_CONFIGURATION_RESPONSE:
	{
		CWProtocolResultCode resultCode;
		if (!(CWParseClearConfigurationResponseMessage(pm, controlVal.msgElemsLen, &resultCode)))
			return CW_FALSE;
		CWACStopRetransmission(WTPIndex);
		if (timerSet) {
			if (!CWRestartNeighborDeadTimer(WTPIndex)) {
				CWCloseThread();
			}
		} else {
			if (!CWStartNeighborDeadTimer(WTPIndex)) {
				CWCloseThread();
			}
		}

		if (gWTPs[WTPIndex].interfaceCommandProgress == CW_TRUE) {
			CWThreadMutexLock(&gWTPs[WTPIndex].interfaceMutex);

			gWTPs[WTPIndex].interfaceResult = 1;
			gWTPs[WTPIndex].interfaceCommandProgress = CW_FALSE;
			CWSignalThreadCondition(&gWTPs[WTPIndex].interfaceComplete);

			CWThreadMutexUnlock(&gWTPs[WTPIndex].interfaceMutex);
		}

		break;
	}

	case CW_MSG_TYPE_VALUE_WLAN_CONFIGURATION_RESPONSE:
	{
		CWProtocolResultCode resultCode;
		if (!(CWParseWLANConfigurationResponseMessage(pm, controlVal.msgElemsLen, &resultCode)))
			return CW_FALSE;
		CWACStopRetransmission(WTPIndex);
		if (timerSet) {
			if (!CWRestartNeighborDeadTimer(WTPIndex)) {
				CWCloseThread();
			}
		} else {
			if (!CWStartNeighborDeadTimer(WTPIndex)) {
				CWCloseThread();
			}
		}

		if (gWTPs[WTPIndex].interfaceCommandProgress == CW_TRUE) {
			CWThreadMutexLock(&gWTPs[WTPIndex].interfaceMutex);

			gWTPs[WTPIndex].interfaceResult = 1;
			gWTPs[WTPIndex].interfaceCommandProgress = CW_FALSE;
			CWSignalThreadCondition(&gWTPs[WTPIndex].interfaceComplete);

			CWThreadMutexUnlock(&gWTPs[WTPIndex].interfaceMutex);
		}

		break;
	}

	case CW_MSG_TYPE_VALUE_DATA_TRANSFER_REQUEST:
	{
		CWProtocolWTPDataTransferRequestValues valuesPtr;

		if (!(CWParseWTPDataTransferRequestMessage(pm, controlVal.msgElemsLen, &valuesPtr)))
			return CW_FALSE;
		if (timerSet) {
			if (!CWRestartNeighborDeadTimer(WTPIndex)) {
				CWCloseThread();
			}
		} else {
			if (!CWStartNeighborDeadTimer(WTPIndex)) {
				CWCloseThread();
			}
		}
		if (!
		    (CWAssembleWTPDataTransferResponse(&tm, gWTPs[WTPIndex].pathMTU, controlVal.seqNum)))
			return CW_FALSE;
		break;
	}

	case CW_MSG_TYPE_VALUE_WTP_EVENT_REQUEST:
	{
		CWProtocolWTPEventRequestValues valuesPtr;

		if (!(CWParseWTPEventRequestMessage(pm, controlVal.msgElemsLen, &valuesPtr)))
			return CW_FALSE;
		if (timerSet) {
			if (!CWRestartNeighborDeadTimer(WTPIndex)) {
				CWCloseThread();
			}
		} else {
			if (!CWStartNeighborDeadTimer(WTPIndex)) {
				CWCloseThread();
			}
		}
		if (!(CWSaveWTPEventRequestMessage(&valuesPtr, &(gWTPs[WTPIndex].WTPProtocolManager))))
			return CW_FALSE;

		if (!(CWAssembleWTPEventResponse(&tm, gWTPs[WTPIndex].pathMTU, controlVal.seqNum)))
			return CW_FALSE;
		break;
	}

	default:
		/*
		 * We have an unexpected request and we have to send
		 * a corresponding response containing a failure result code
		 */
		CWDebugLog("--> Not valid Request in Run State... we send a failure Response");

		if (!(CWAssembleUnrecognizedMessageResponse(&tm, gWTPs[WTPIndex].pathMTU,
							    controlVal.seqNum, controlVal.messageTypeValue + 1)))
			return CW_FALSE;

		break;
		/*return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Message not valid in Run State"); */
	}

	if (tm.count > 0) {
		for (i = 0; i < tm.count; i++) {
#ifdef CW_NO_DTLS
			if (!CWNetworkSendUnsafeUnconnected(gWTPs[WTPIndex].socket,
							    &gWTPs[WTPIndex].address,
							    tm.parts[i].data, tm.parts[i].pos)) {
#else
			if (!(CWSecuritySend(gWTPs[WTPIndex].session, tm.parts[i].data, tm.parts[i].pos))) {
#endif
				return CW_FALSE;
			}
		}
		CWReleaseTransportMessage(&tm);
	}
	gWTPs[WTPIndex].currentState = CW_ENTER_RUN;
	gWTPs[WTPIndex].subState = CW_WAITING_REQUEST;

	return CW_TRUE;
}

CWBool CWACParseGenericRunMessage(int WTPIndex, CWProtocolMessage *pm, CWControlHeaderValues * controlVal)
{
	assert(pm);
	assert(controlVal);

	if (!(CWParseControlHeader(pm, controlVal)))
		/* will be handled by the caller */
		return CW_FALSE;

	/* skip timestamp */
	controlVal->msgElemsLen -= CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;

	/* Check if it is a request */
	if (controlVal->messageTypeValue % 2 == 1)
		return CW_TRUE;

	if ((gWTPs[WTPIndex].responseSeqNum != controlVal->seqNum) ||
	    (gWTPs[WTPIndex].responseType != controlVal->messageTypeValue)) {

		CWDebugLog("gWTPs: %d\n", gWTPs[WTPIndex].responseSeqNum);
		CWDebugLog("controlVal: %d\n", controlVal->seqNum);
		CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Seq Num or Msg Type not valid!");
		return CW_FALSE;
	}

	return CW_TRUE;
}

/*Update 2009:
    Added vendValues to include a response payload (to pass response data)*/
CWBool CWParseConfigurationUpdateResponseMessage(CWProtocolMessage *pm,
						 int len,
						 CWProtocolResultCode * resultCode,
						 CWProtocolVendorSpecificValues ** vendValues)
{
	int offsetTillMessages;

	assert(pm != NULL);
	assert(resultCode != NULL);

	offsetTillMessages = pm->pos;

	CWLog("Parsing Configuration Update Response...");

	/* parse message elements */
	while ((pm->pos - offsetTillMessages) < len) {

		unsigned short int elemType = 0;
		unsigned short int elemLen = 0;

		CWParseFormatMsgElem(pm, &elemType, &elemLen);

		switch (elemType) {
		case CW_MSG_ELEMENT_RESULT_CODE_CW_TYPE:
			*resultCode = CWProtocolRetrieve32(pm);
			break;

			/*Update 2009:
			   Added case to implement conf update response with payload */
		case CW_MSG_ELEMENT_RESULT_CODE_CW_TYPE_WITH_PAYLOAD:{
				int payloadSize = 0;
				if (!(*vendValues = ralloc(NULL, CWProtocolVendorSpecificValues)))
					return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

				*resultCode = CWProtocolRetrieve32(pm);

				if (CWProtocolRetrieve16(pm) != CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE)
					/*For now, we only have UCI payloads, so we will accept only vendor payloads for protocol data */
					return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
							    "Unrecognized Message Element in Configuration Update Response");

				(*vendValues)->vendorPayloadType = CWProtocolRetrieve16(pm);

				switch ((*vendValues)->vendorPayloadType) {
				case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_UCI:
					payloadSize = CWProtocolRetrieve32(pm);
					if (payloadSize != 0) {
						(*vendValues)->payload =
						    (void *)CWProtocolRetrieveStr(NULL, pm, payloadSize);
					} else
						(*vendValues)->payload = NULL;
					break;
				case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_WUM:
					payloadSize = CWProtocolRetrieve32(pm);

					if (payloadSize <= 0) {
						/* Payload can't be zero here,
						 * at least the message type must be specified */
						return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
								    "Unrecognized Message Element in Configuration Update Response");
					}
					(*vendValues)->payload =
					    (void *)CWProtocolRetrieveRawBytes(NULL, pm, payloadSize);
					break;
				default:
					return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
							    "Unrecognized Message Element in Configuration Update Response");
					break;
				}
			}
			break;
		default:
			return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
					    "Unrecognized Message Element in Configuration Update Response");
			break;
		}
	}

	if ((pm->pos - offsetTillMessages) != len)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");

	CWLog("Configuration Update Response Parsed");

	return CW_TRUE;
}

CWBool CWParseWLANConfigurationResponseMessage(CWProtocolMessage *pm, int len, CWProtocolResultCode * resultCode)
{
	int offsetTillMessages;

	assert(pm != NULL);
	assert(resultCode != NULL);

	offsetTillMessages = pm->pos;

	CWLog("Parsing WLAN Configuration Response...");

	// parse message elements
	while ((pm->pos - offsetTillMessages) < len) {
		unsigned short int elemType = 0;
		unsigned short int elemLen = 0;

		CWParseFormatMsgElem(pm, &elemType, &elemLen);

		switch (elemType) {
		case CW_MSG_ELEMENT_RESULT_CODE_CW_TYPE:
			*resultCode = CWProtocolRetrieve32(pm);
			break;
		default:
			return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
					    "Unrecognized Message Element in Configuration WLAN Response");
			break;
		}
	}

	if ((pm->pos - offsetTillMessages) != len)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");

	CWLog("WLAN Configuration Response Parsed");

	return CW_TRUE;
}

CWBool CWParseClearConfigurationResponseMessage(CWProtocolMessage *pm, int len, CWProtocolResultCode * resultCode)
{
	int offsetTillMessages;

	assert(pm != NULL);
	assert(resultCode != NULL);

	offsetTillMessages = pm->pos;

	CWLog("Parsing Clear Configuration Response...");

	// parse message elements
	while ((pm->pos - offsetTillMessages) < len) {
		unsigned short int elemType = 0;
		unsigned short int elemLen = 0;

		CWParseFormatMsgElem(pm, &elemType, &elemLen);

		switch (elemType) {
		case CW_MSG_ELEMENT_RESULT_CODE_CW_TYPE:
			*resultCode = CWProtocolRetrieve32(pm);
			break;
		default:
			return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
					    "Unrecognized Message Element in Configuration Update Response");
			break;
		}
	}

	if ((pm->pos - offsetTillMessages) != len)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");

	CWLog("Clear Configuration Response Parsed");

	return CW_TRUE;
}

CWBool CWParseStationConfigurationResponseMessage(CWProtocolMessage *pm, int len,
						  CWProtocolResultCode * resultCode)
{
	int offsetTillMessages;

	assert(pm != NULL);
	assert(resultCode != NULL);

	offsetTillMessages = pm->pos;

	CWLog("Parsing Station Configuration Response...");

	// parse message elements
	while ((pm->pos - offsetTillMessages) < len) {
		unsigned short int elemType = 0;
		unsigned short int elemLen = 0;

		CWParseFormatMsgElem(pm, &elemType, &elemLen);

		switch (elemType) {
		case CW_MSG_ELEMENT_RESULT_CODE_CW_TYPE:
			*resultCode = CWProtocolRetrieve32(pm);
			break;
		default:
			return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
					    "Unrecognized Message Element in Station Configuration Response");
			break;
		}
	}

	if ((pm->pos - offsetTillMessages) != len)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");

	CWLog("Station Configuration Response Parsed");

	return CW_TRUE;
}

CWBool CWSaveConfigurationUpdateResponseMessage(CWProtocolResultCode resultCode,
						int WTPIndex, CWProtocolVendorSpecificValues * vendValues)
{
	char *wumPayloadBytes = NULL;
	int closeWTPManager = CW_FALSE;

	if (vendValues != NULL) {
		char *responseBuffer;
		int socketIndex, payloadSize = 0, headerSize, netWTPIndex, netresultCode, netpayloadSize;

		/********************************
		 *Payload Management        *
		 ********************************/

		headerSize = 3 * sizeof(int);

		switch (vendValues->vendorPayloadType) {
		case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_UCI:
			if (vendValues->payload != NULL)
				payloadSize = strlen((char *)vendValues->payload);
			else
				payloadSize = 0;
			break;
		case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_WUM:
			wumPayloadBytes = vendValues->payload;
			payloadSize = 1;

			/*
			 * When dealing with WUM responses, the dafault size
			 * is 1 bytes, which is used for the type.
			 *
			 * The only response message with a bigger payload is the
			 * WTP_VERSION_RESPONSE (4 bytes), as it carries the WTP version
			 * together with the response type.
			 */
			if (wumPayloadBytes[0] == WTP_VERSION_RESPONSE)
				payloadSize = 4;

			/*
			 * If we received a positive WTP_COMMIT_ACK, we need to terminate
			 * the WTP Manager Thread.
			 */
			if (wumPayloadBytes[0] == WTP_COMMIT_ACK && resultCode == CW_PROTOCOL_SUCCESS)
				closeWTPManager = CW_TRUE;
			break;
		}

		if ((responseBuffer = malloc(headerSize + payloadSize)) != NULL) {

			netWTPIndex = htonl(WTPIndex);
			memcpy(responseBuffer, &netWTPIndex, sizeof(int));

			netresultCode = htonl(resultCode);
			memcpy(responseBuffer + sizeof(int), &netresultCode, sizeof(int));

			netpayloadSize = htonl(payloadSize);
			memcpy(responseBuffer + (2 * sizeof(int)), &netpayloadSize, sizeof(int));

			if (payloadSize > 0) {
				memcpy(responseBuffer + headerSize, (char *)vendValues->payload, payloadSize);
				if (vendValues->vendorPayloadType == CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_UCI)
					((char *)vendValues->payload)[payloadSize] = '\0';
			}

			socketIndex = gWTPs[WTPIndex].applicationIndex;

			/****************************************************
			     * Forward payload to correct application       *
			 ****************************************************/

			if (!CWErr(CWThreadMutexLock(&appsManager.socketMutex[socketIndex]))) {
				CWLog("Error locking numSocketFree Mutex");
				return CW_FALSE;
			}

			if (Writen(appsManager.appSocket[socketIndex], responseBuffer, headerSize + payloadSize) < 0) {
				CWThreadMutexUnlock(&appsManager.socketMutex[socketIndex]);
				CWLog("Error locking numSocketFree Mutex");
				return CW_FALSE;
			}

			CWThreadMutexUnlock(&appsManager.socketMutex[socketIndex]);

		}
		free(responseBuffer);
		CW_FREE_OBJECT(vendValues->payload);
		CW_FREE_OBJECT(vendValues);

	} else if (!CWBindingSaveConfigurationUpdateResponse(resultCode, WTPIndex)) {

		return CW_FALSE;
	}

	/*
	 * On a positive WTP_COMMIT_ACK, we need to close the WTP Manager.
	 */
	if (closeWTPManager) {
		gWTPs[WTPIndex].isRequestClose = CW_TRUE;
		CWSignalThreadCondition(&gWTPs[WTPIndex].interfaceWait);
	}

	CWDebugLog("Configuration Update Response Saved");
	return CW_TRUE;
}

CWBool CWParseWTPDataTransferRequestMessage(CWProtocolMessage *pm, int len,
					    CWProtocolWTPDataTransferRequestValues * valuesPtr)
{
	int offsetTillMessages;

	assert(pm != NULL);
	assert(valuesPtr != NULL);

	offsetTillMessages = pm->pos;

	CWLog("#");
	CWLog("#________ WTP Data Transfer (Run) ________#");
	CWLog("Parsing WTP Data Transfer Request...");

	// parse message elements
	while ((pm->pos - offsetTillMessages) < len) {
		unsigned short int elemType = 0;
		unsigned short int elemLen = 0;

		CWParseFormatMsgElem(pm, &elemType, &elemLen);

		switch (elemType) {
		case CW_MSG_ELEMENT_DATA_TRANSFER_DATA_CW_TYPE:{
				if (!(CWParseMsgElemDataTransferData(pm, elemLen, valuesPtr)))
					return CW_FALSE;
				CWDebugLog("----- %s --------\n", valuesPtr->debug_info);
				break;
			}
		default:
			return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
					    "Unrecognized Message Element in WTP Data Transfer Request");
			break;
		}
	}

	if ((pm->pos - offsetTillMessages) != len)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");

	return CW_TRUE;
}

CWBool CWParseWTPEventRequestMessage(CWProtocolMessage *pm, int len, CWProtocolWTPEventRequestValues * valuesPtr)
{

	int offsetTillMessages;
	int i = 0, k = 0;

	assert(pm != NULL);
	assert(valuesPtr != NULL);

	/*
	if (!(valuesPtr = ralloc(NULL, CWProtocolWTPEventRequestValues)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
	 */
	offsetTillMessages = pm->pos;

	CWLog("#");
	CWLog("#________ WTP Event (Run) ________#");
	CWLog("Parsing WTP Event Request...");

	valuesPtr->errorReportCount = 0;
	valuesPtr->errorReport = NULL;
	valuesPtr->duplicateIPv4 = NULL;
	valuesPtr->duplicateIPv6 = NULL;
	valuesPtr->WTPOperationalStatisticsCount = 0;
	valuesPtr->WTPOperationalStatistics = NULL;
	valuesPtr->WTPRadioStatisticsCount = 0;
	valuesPtr->WTPRadioStatistics = NULL;
	valuesPtr->WTPRebootStatistics = NULL;

	/* parse message elements */
	while ((pm->pos - offsetTillMessages) < len) {

		unsigned short int elemType = 0;
		unsigned short int elemLen = 0;

		CWParseFormatMsgElem(pm, &elemType, &elemLen);

		switch (elemType) {
		case CW_MSG_ELEMENT_CW_DECRYPT_ER_REPORT_CW_TYPE:
			if (!(valuesPtr->errorReport = ralloc(NULL, CWDecryptErrorReportValues)))
				return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

			if (!(CWParseMsgElemDecryptErrorReport(pm, elemLen, valuesPtr->errorReport)))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_DUPLICATE_IPV4_ADDRESS_CW_TYPE:
			if (!(valuesPtr->duplicateIPv4 = ralloc(NULL, WTPDuplicateIPv4)))
				return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

			if (!((valuesPtr->duplicateIPv4)->MACoffendingDevice_forIpv4 =
			      ralloc_array(NULL, unsigned char, 6)))
				return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

			if (!(CWParseMsgElemDuplicateIPv4Address(pm, elemLen, valuesPtr->duplicateIPv4)))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_DUPLICATE_IPV6_ADDRESS_CW_TYPE:
			if (!(valuesPtr->duplicateIPv6 = ralloc(NULL, WTPDuplicateIPv6)))
				return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

			if (!((valuesPtr->duplicateIPv6)->MACoffendingDevice_forIpv6 =
			      ralloc_array(NULL, unsigned char, 6)))
				return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

			if (!(CWParseMsgElemDuplicateIPv6Address(pm, elemLen, valuesPtr->duplicateIPv6)))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_WTP_OPERAT_STATISTICS_CW_TYPE:
			valuesPtr->WTPOperationalStatisticsCount++;
			pm->pos += elemLen;
			break;
		case CW_MSG_ELEMENT_WTP_RADIO_STATISTICS_CW_TYPE:
			valuesPtr->WTPRadioStatisticsCount++;
			pm->pos += elemLen;
			break;
		case CW_MSG_ELEMENT_WTP_REBOOT_STATISTICS_CW_TYPE:
			if (!(valuesPtr->WTPRebootStatistics = ralloc(NULL, WTPRebootStatisticsInfo)))
				return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

			if (!(CWParseWTPRebootStatistics(pm, elemLen, valuesPtr->WTPRebootStatistics)))
				return CW_FALSE;
			break;
		default:
			return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
					    "Unrecognized Message Element in WTP Event Request");
			break;
		}
	}

	if ((pm->pos - offsetTillMessages) != len)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");

	if (!(valuesPtr->WTPOperationalStatistics =
	      ralloc_array(NULL, WTPOperationalStatisticsValues, valuesPtr->WTPOperationalStatisticsCount)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	if (!(valuesPtr->WTPRadioStatistics =
	      ralloc_array(NULL, WTPRadioStatisticsValues, valuesPtr->WTPRadioStatisticsCount)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	pm->pos = offsetTillMessages;

	while ((pm->pos - offsetTillMessages) < len) {

		unsigned short int elemType = 0;
		unsigned short int elemLen = 0;

		CWParseFormatMsgElem(pm, &elemType, &elemLen);

		switch (elemType) {
		case CW_MSG_ELEMENT_WTP_OPERAT_STATISTICS_CW_TYPE:
			if (!(CWParseWTPOperationalStatistics(pm,
							      elemLen, &(valuesPtr->WTPOperationalStatistics[k++]))))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_WTP_RADIO_STATISTICS_CW_TYPE:
			if (!(CWParseWTPRadioStatistics(pm, elemLen, &(valuesPtr->WTPRadioStatistics[i++]))))
				return CW_FALSE;
			break;
		default:
			pm->pos += elemLen;
			break;
		}
	}
	CWLog("WTP Event Request Parsed");
	return CW_TRUE;
}

CWBool CWSaveWTPEventRequestMessage(CWProtocolWTPEventRequestValues * WTPEventRequest,
				    CWWTPProtocolManager * WTPProtocolManager)
{

	if (WTPEventRequest == NULL || WTPProtocolManager == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if (WTPEventRequest->WTPRebootStatistics) {

		CW_FREE_OBJECT(WTPProtocolManager->WTPRebootStatistics);
		WTPProtocolManager->WTPRebootStatistics = WTPEventRequest->WTPRebootStatistics;
	}

	if ((WTPEventRequest->WTPOperationalStatisticsCount) > 0) {

		int i, k;
		__attribute__ ((unused)) CWBool found = CW_FALSE;		/* TODO: non-functional code, needs cleanup */

		for (i = 0; i < (WTPEventRequest->WTPOperationalStatisticsCount); i++) {

			found = CW_FALSE;
			for (k = 0; k < (WTPProtocolManager->radiosInfo).radioCount; k++) {

				if ((WTPProtocolManager->radiosInfo).radiosInfo[k].radioID ==
				    (WTPEventRequest->WTPOperationalStatistics[i]).radioID) {

					found = CW_TRUE;
					(WTPProtocolManager->radiosInfo).radiosInfo[k].TxQueueLevel =
					    (WTPEventRequest->WTPOperationalStatistics[i]).TxQueueLevel;
					(WTPProtocolManager->radiosInfo).radiosInfo[k].wirelessLinkFramesPerSec =
					    (WTPEventRequest->WTPOperationalStatistics[i]).wirelessLinkFramesPerSec;
				}
			}
			/*if(!found)
			   {
			   for(k=0; k<(WTPProtocolManager->radiosInfo).radioCount; k++)
			   {
			   if((WTPProtocolManager->radiosInfo).radiosInfo[k].radioID == UNUSED_RADIO_ID);
			   {
			   (WTPProtocolManager->radiosInfo).radiosInfo[k].radioID = (WTPEventRequest->WTPOperationalStatistics[i]).radioID;
			   (WTPProtocolManager->radiosInfo).radiosInfo[k].TxQueueLevel = (WTPEventRequest->WTPOperationalStatistics[i]).TxQueueLevel;
			   (WTPProtocolManager->radiosInfo).radiosInfo[k].wirelessLinkFramesPerSec = (WTPEventRequest->WTPOperationalStatistics[i]).wirelessLinkFramesPerSec;
			   }
			   }
			   } */
		}
	}

	if ((WTPEventRequest->WTPRadioStatisticsCount) > 0) {

		int i, k;
		__attribute__ ((unused)) CWBool found = CW_FALSE;		/* TODO: non-functional code, needs cleanup */

		for (i = 0; i < (WTPEventRequest->WTPRadioStatisticsCount); i++) {
			found = CW_FALSE;
			for (k = 0; k < (WTPProtocolManager->radiosInfo).radioCount; k++) {

				if ((WTPProtocolManager->radiosInfo).radiosInfo[k].radioID ==
				    (WTPEventRequest->WTPOperationalStatistics[i]).radioID) {

					found = CW_TRUE;
					(WTPProtocolManager->radiosInfo).radiosInfo[k].statistics =
					    (WTPEventRequest->WTPRadioStatistics[i]).WTPRadioStatistics;
				}
			}
			/*if(!found)
			   {
			   for(k=0; k<(WTPProtocolManager->radiosInfo).radioCount; k++)
			   {
			   if((WTPProtocolManager->radiosInfo).radiosInfo[k].radioID == UNUSED_RADIO_ID);
			   {
			   (WTPProtocolManager->radiosInfo).radiosInfo[k].radioID = (WTPEventRequest->WTPOperationalStatistics[i]).radioID;
			   (WTPProtocolManager->radiosInfo).radiosInfo[k].statistics = (WTPEventRequest->WTPRadioStatistics[i]).WTPRadioStatistics;
			   }
			   }
			   } */
		}
	}
	/*
	   CW_FREE_OBJECT((WTPEventRequest->WTPOperationalStatistics), (WTPEventRequest->WTPOperationalStatisticsCount));
	   CW_FREE_OBJECTS_ARRAY((WTPEventRequest->WTPRadioStatistics), (WTPEventRequest->WTPRadioStatisticsCount));
	   Da controllare!!!!!!!
	 */
	CW_FREE_OBJECT(WTPEventRequest->WTPOperationalStatistics);
	CW_FREE_OBJECT(WTPEventRequest->WTPRadioStatistics);
	/*CW_FREE_OBJECT(WTPEventRequest); */

	return CW_TRUE;
}

CWBool CWAssembleWTPDataTransferResponse(CWTransportMessage *tm, int PMTU, int seqNum)
{
	CWProtocolMessage msg;

	assert(tm != NULL);

	CWLog("Assembling WTP Data Transfer Response...");
	if (!CWInitMessage(NULL, &msg, CW_MSG_TYPE_VALUE_DATA_TRANSFER_RESPONSE, seqNum))
		goto cw_assemble_error;
	CWFinalizeMessage(&msg);

	if (!CWAssembleMessage(tm, PMTU, &msg))
		goto cw_assemble_error;

	CWLog("WTP Data Transfer Response Assembled");
	return CW_TRUE;

 cw_assemble_error:
	CWReleaseMessage(&msg);
        return CW_FALSE;
}


CWBool CWAssembleWTPEventResponse(CWTransportMessage *tm, int PMTU, int seqNum)
{
	CWProtocolMessage msg;

	assert(tm != NULL);

	CWLog("Assembling WTP Event Response...");
	if (!CWInitMessage(NULL, &msg, CW_MSG_TYPE_VALUE_WTP_EVENT_RESPONSE, seqNum))
		goto cw_assemble_error;
	CWFinalizeMessage(&msg);

	if (!CWAssembleMessage(tm, PMTU, &msg))
		goto cw_assemble_error;

	CWLog("WTP Event Response Assembled");
	return CW_TRUE;

 cw_assemble_error:
	CWReleaseMessage(&msg);
        return CW_FALSE;
}

CWBool CWParseChangeStateEventRequestMessage2(CWProtocolMessage *pm,
					      int len, CWProtocolChangeStateEventRequestValues ** valuesPtr)
{

	int offsetTillMessages;
	int i = 0;

	assert(pm != NULL);

	if (!(*valuesPtr = ralloc(NULL, CWProtocolChangeStateEventRequestValues)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	offsetTillMessages = pm->pos;

	CWLog("#");
	CWLog("#________ WTP Change State Event (Run) ________#");

	(*valuesPtr)->radioOperationalInfo.radiosCount = 0;
	(*valuesPtr)->radioOperationalInfo.radios = NULL;

	/* parse message elements */
	while ((pm->pos - offsetTillMessages) < len) {
		unsigned short int elemType = 0;	/* = CWProtocolRetrieve32(&completeMsg); */
		unsigned short int elemLen = 0;	/* = CWProtocolRetrieve16(&completeMsg); */

		CWParseFormatMsgElem(pm, &elemType, &elemLen);

		/*CWDebugLog("Parsing Message Element: %u, elemLen: %u", elemType, elemLen); */

		switch (elemType) {
		case CW_MSG_ELEMENT_RADIO_OPERAT_STATE_CW_TYPE:
			/* just count how many radios we have, so we
			 * can allocate the array
			 */
			((*valuesPtr)->radioOperationalInfo.radiosCount)++;
			pm->pos += elemLen;
			break;
		case CW_MSG_ELEMENT_RESULT_CODE_CW_TYPE:
			if (!(CWParseResultCode(pm, elemLen, &((*valuesPtr)->resultCode))))
				return CW_FALSE;
			break;
		default:
			return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
					    "Unrecognized Message Element in Change State Event Request");
		}
	}

	if ((pm->pos - offsetTillMessages) != len)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");

	if (!((*valuesPtr)->radioOperationalInfo.radios =
	      ralloc_array(NULL, CWRadioOperationalInfoValues, (*valuesPtr)->radioOperationalInfo.radiosCount)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	pm->pos = offsetTillMessages;

	i = 0;

	while (pm->pos - offsetTillMessages < len) {
		unsigned short int type = 0;	/* = CWProtocolRetrieve32(&completeMsg); */
		unsigned short int len = 0;	/* = CWProtocolRetrieve16(&completeMsg); */

		CWParseFormatMsgElem(pm, &type, &len);

		switch (type) {
		case CW_MSG_ELEMENT_RADIO_OPERAT_STATE_CW_TYPE:
			/* will be handled by the caller */
			if (!
			    (CWParseWTPRadioOperationalState
			     (pm, len, &((*valuesPtr)->radioOperationalInfo.radios[i]))))
				return CW_FALSE;
			i++;
			break;
		default:
			pm->pos += len;
			break;
		}
	}
	CWLog("Change State Event Request Parsed");
	return CW_TRUE;
}

CWBool CWSaveChangeStateEventRequestMessage(CWProtocolChangeStateEventRequestValues * valuesPtr,
					    CWWTPProtocolManager * WTPProtocolManager)
{

	CWBool found;
	CWBool retValue = CW_TRUE;

	assert(valuesPtr != NULL);
	assert(WTPProtocolManager != NULL);

	if ((valuesPtr->radioOperationalInfo.radiosCount) > 0) {

		int i, k;
		for (i = 0; i < (valuesPtr->radioOperationalInfo.radiosCount); i++) {

			found = CW_FALSE;
			for (k = 0; k < (WTPProtocolManager->radiosInfo).radioCount; k++) {

				if ((WTPProtocolManager->radiosInfo).radiosInfo[k].radioID ==
				    (valuesPtr->radioOperationalInfo.radios[i]).ID) {

					found = CW_TRUE;
					(WTPProtocolManager->radiosInfo).radiosInfo[k].operationalState =
					    (valuesPtr->radioOperationalInfo.radios[i]).state;
					(WTPProtocolManager->radiosInfo).radiosInfo[k].operationalCause =
					    (valuesPtr->radioOperationalInfo.radios[i]).cause;
				}
				if (!found)
					retValue = CW_FALSE;
			}
		}
	}

	CW_FREE_OBJECT(valuesPtr->radioOperationalInfo.radios);
	CW_FREE_OBJECT(valuesPtr);

	return retValue;
}

CWBool CWParseEchoRequestMessage(CWProtocolMessage *pm, int len)
{

	int offsetTillMessages;

	assert(pm != NULL);

	offsetTillMessages = pm->pos;

	CWLog("#");
	CWLog("#________ Echo Request (Run) ________#");

	/* parse message elements */
	while ((pm->pos - offsetTillMessages) < len) {
		unsigned short int elemType = 0;	/* = CWProtocolRetrieve32(&completeMsg); */
		unsigned short int elemLen = 0;	/* = CWProtocolRetrieve16(&completeMsg); */

		CWParseFormatMsgElem(pm, &elemType, &elemLen);

		/*CWDebugLog("Parsing Message Element: %u, elemLen: %u", elemType, elemLen); */

		switch (elemType) {
		default:
			return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Echo Request must carry no message elements");
		}
	}

	if ((pm->pos - offsetTillMessages) != len)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");

	CWLog("Echo Request Parsed");

	return CW_TRUE;
}

CWBool CWAssembleEchoResponse(CWTransportMessage *tm, int PMTU, int seqNum)
{

	CWProtocolMessage msg;

	assert(tm != NULL);

	CWLog("Assembling Echo Response...");
	if (!CWInitMessage(NULL, &msg, CW_MSG_TYPE_VALUE_ECHO_RESPONSE, seqNum))
		goto cw_assemble_error;
	CWFinalizeMessage(&msg);

	if (!CWAssembleMessage(tm, PMTU, &msg))
		goto cw_assemble_error;

	CWLog("Echo Response Assembled");
	return CW_TRUE;

 cw_assemble_error:
	CWReleaseMessage(&msg);
        return CW_FALSE;
}

CWBool CWAssembleConfigurationUpdateRequest(CWTransportMessage *tm, int PMTU, int seqNum, int msgElement)
{
	CWProtocolMessage msg;

	assert(tm != NULL);

	CWLog("Assembling Configuration Update Request...");
	if (!CWInitMessage(NULL, &msg, CW_MSG_TYPE_VALUE_CONFIGURE_UPDATE_REQUEST, seqNum))
		goto cw_assemble_error;

	switch (msgElement) {
	case CONFIG_UPDATE_REQ_QOS_ELEMENT_TYPE:
		if (!CWBindingAssembleConfigurationUpdateRequest(&msg, BINDING_MSG_ELEMENT_TYPE_WTP_QOS))
			goto cw_assemble_error;
		break;

	case CONFIG_UPDATE_REQ_OFDM_ELEMENT_TYPE:
		if (!CWBindingAssembleConfigurationUpdateRequest(&msg, BINDING_MSG_ELEMENT_TYPE_OFDM_CONTROL))
			goto cw_assemble_error;
		break;

	case CONFIG_UPDATE_REQ_VENDOR_UCI_ELEMENT_TYPE:
		CWLog("Assembling UCI Conf Update Request");
		if (!CWProtocolAssembleConfigurationUpdateRequest(&msg, CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_UCI))
			goto cw_assemble_error;
		break;

	case CONFIG_UPDATE_REQ_VENDOR_WUM_ELEMENT_TYPE:
		CWLog("Assembling WUM Conf Update Request");
		if (!CWProtocolAssembleConfigurationUpdateRequest(&msg, CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_WUM))
			goto cw_assemble_error;
		break;
	}
	CWFinalizeMessage(&msg);

	if (!CWAssembleMessage(tm, PMTU, &msg))
		goto cw_assemble_error;

	CWLog("Configuration Update Request Assembled");
	return CW_TRUE;

 cw_assemble_error:
	CWReleaseMessage(&msg);
        return CW_FALSE;
}

CWBool CWAssembleClearConfigurationRequest(CWTransportMessage *tm, int PMTU, int seqNum)
{
	CWProtocolMessage msg;

	assert(tm != NULL);

	CWLog("Assembling Clear Configuration Request...");
	if (!CWInitMessage(NULL, &msg, CW_MSG_TYPE_VALUE_CLEAR_CONFIGURATION_REQUEST, seqNum))
		goto cw_assemble_error;
	CWFinalizeMessage(&msg);

	if (!CWAssembleMessage(tm, PMTU, &msg))
		goto cw_assemble_error;

	CWLog("Clear Configuration Request Assembled");

	return CW_TRUE;

 cw_assemble_error:
	CWReleaseMessage(&msg);
        return CW_FALSE;
}

CWBool CWAssembleWLANConfigurationRequest(CWTransportMessage *tm, int PMTU, int seqNum,
					  unsigned char *recv_packet, int Operation, int len_packet)
{
	CWProtocolMessage msg;

	assert(tm != NULL);

	CWLog("Assembling WLAN 802.11 Configuration Request...");
	if (!CWInitMessage(NULL, &msg, CW_MSG_TYPE_VALUE_WLAN_CONFIGURATION_REQUEST, seqNum))

	switch (Operation) {
	case CW_MSG_ELEMENT_IEEE80211_ADD_WLAN_CW_TYPE:
		if (!CWAssembleMsgElemAddWLAN(NULL, 0, &msg, recv_packet, len_packet))		//radioID = 0 -valore predefinito-
			goto cw_assemble_error;
		break;

	case CW_MSG_ELEMENT_IEEE80211_DELETE_WLAN_CW_TYPE:
		if (!CWAssembleMsgElemDeleteWLAN(NULL, 0, &msg, recv_packet, len_packet))	//radioID = 0 -valore predefinito-
			goto cw_assemble_error;
		break;

	default:
		return CW_FALSE;
	}

#if 0
	/*
	 * to be implemented in a case of Binding with appropriate messages elements -- see draft capwap-spec && capwap-binding
	 */
	if (!CWBindingAssembleConfigurationUpdateRequest(&msg))
		goto cw_assemble_error;
#endif

	CWFinalizeMessage(&msg);

	if (!CWAssembleMessage(tm, PMTU, &msg))
		goto cw_assemble_error;

	CWLog("Station WLAN 802.11 Configuration Request Assembled");
	return CW_TRUE;

 cw_assemble_error:
	CWReleaseMessage(&msg);
        return CW_FALSE;
}

CWBool CWAssembleStationConfigurationRequest(CWTransportMessage *tm, int PMTU, int seqNum,
					     unsigned char *StationMacAddr, int Operation)
{
	CWProtocolMessage msg;

	assert(tm != NULL);

	CWLog("Assembling Station Configuration Request...");
	if (!CWInitMessage(NULL, &msg, CW_MSG_TYPE_VALUE_STATION_CONFIGURATION_REQUEST, seqNum))
		goto cw_assemble_error;

	switch (Operation) {
	case CW_MSG_ELEMENT_ADD_STATION_CW_TYPE:
		if (!CWAssembleMsgElemAddStation(NULL, 0, &msg, StationMacAddr))		//radioID = 0 -valore predefinito-
			goto cw_assemble_error;
		break;

	case CW_MSG_ELEMENT_DELETE_STATION_CW_TYPE:
		if (!CWAssembleMsgElemDeleteStation(NULL, 0, &msg, StationMacAddr))		//radioID = 0 -valore predefinito-
			goto cw_assemble_error;
		break;

	default:
		goto cw_assemble_error;
	}

#if 0
	/*
	 * to be implemented in a case of Binding with appropriate messages elements -- see draft capwap-spec && capwap-binding
	 */
	if (!CWBindingAssembleConfigurationUpdateRequest(&msg))
		goto cw_assemble_error;
#endif

	CWFinalizeMessage(&msg);

	if (!CWAssembleMessage(tm, PMTU, &msg))
		goto cw_assemble_error;

	CWLog("Station Configuration Request Assembled");
	return CW_TRUE;

 cw_assemble_error:
	CWReleaseMessage(&msg);
        return CW_FALSE;
}

CWBool CWStartNeighborDeadTimer(int WTPIndex)
{
	/* start NeighborDeadInterval timer */
	if (!CWErr(CWTimerRequest(gCWNeighborDeadInterval,
				  &(gWTPs[WTPIndex].thread),
				  &(gWTPs[WTPIndex].currentTimer), CW_CRITICAL_TIMER_EXPIRED_SIGNAL))) {
		return CW_FALSE;
	}
	return CW_TRUE;
}

CWBool CWStartNeighborDeadTimerForEcho(int WTPIndex)
{
	int echoInterval;

	/* start NeighborDeadInterval timer */
	CWACGetEchoRequestTimer(&echoInterval);
	if (!CWErr(CWTimerRequest(echoInterval,
				  &(gWTPs[WTPIndex].thread),
				  &(gWTPs[WTPIndex].currentTimer), CW_CRITICAL_TIMER_EXPIRED_SIGNAL))) {
		return CW_FALSE;
	}
	return CW_TRUE;
}

CWBool CWStopNeighborDeadTimer(int WTPIndex)
{
	if (!CWTimerCancel(&(gWTPs[WTPIndex].currentTimer))) {

		return CW_FALSE;
	}
	return CW_TRUE;
}

CWBool CWRestartNeighborDeadTimer(int WTPIndex)
{
	CWThreadSetSignals(SIG_BLOCK, 1, CW_SOFT_TIMER_EXPIRED_SIGNAL);

	if (!CWStopNeighborDeadTimer(WTPIndex))
		return CW_FALSE;
	if (!CWStartNeighborDeadTimer(WTPIndex))
		return CW_FALSE;

	CWThreadSetSignals(SIG_UNBLOCK, 1, CW_SOFT_TIMER_EXPIRED_SIGNAL);

	CWDebugLog("NeighborDeadTimer restarted");
	return CW_TRUE;
}

#if 0
CWBool CWRestartNeighborDeadTimerForEcho(int WTPIndex)
{
	CWThreadSetSignals(SIG_BLOCK, 1, CW_SOFT_TIMER_EXPIRED_SIGNAL);

	if (!CWStopNeighborDeadTimer(WTPIndex))
		return CW_FALSE;
	if (!CWStartNeighborDeadTimerForEcho(WTPIndex))
		return CW_FALSE;

	CWThreadSetSignals(SIG_UNBLOCK, 1, CW_SOFT_TIMER_EXPIRED_SIGNAL);

	CWDebugLog("NeighborDeadTimer restarted for Echo interval");
	return CW_TRUE;
}
#endif
