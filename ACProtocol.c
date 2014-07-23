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
 *
 * --------------------------------------------------------------------------------------- *
 * Project:  Capwap                                                                        *
 *                                                                                         *
 * Author :  Ludovico Rossi (ludo@bluepixysw.com)                                          *
 *           Del Moro Andrea (andrea_delmoro@libero.it)                                    *
 *           Giovannini Federica (giovannini.federica@gmail.com)                           *
 *           Massimo Vellucci (m.vellucci@unicampus.it)                                    *
 *           Mauro Bisson (mauro.bis@gmail.com)                                            *
 *******************************************************************************************/

#include "CWAC.h"
#include "CWVendorPayloads.h"

unsigned char WTPRadioInformationType;

/*____________________________________________________________________________*/
/*  *****************************___ASSEMBLE___*****************************  */
/*Update 2009:
    Assemble protocol Configuration update request.
    Mainly added to  manage vendor specific packets*/
CWBool CWProtocolAssembleConfigurationUpdateRequest(CWProtocolMessage *msg, int MsgElementType)
{
	int *iPtr;

	if (msg == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if ((iPtr = ((int *)CWThreadGetSpecific(&gIndexSpecific))) == NULL)
		return CW_FALSE;

	CWLog("Assembling Protocol Configuration Update Request...");

	/* Selection of type of Conf Update Request */

	switch (MsgElementType) {
	case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_UCI:
		if (!(CWAssembleWTPVendorPayloadUCI(NULL, msg)))
			return CW_FALSE;
		break;

	case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_WUM:
		if (!(CWAssembleWTPVendorPayloadWUM(NULL, msg)))
			return CW_FALSE;
		break;

	default:
		return CW_FALSE;
	}

	CWLog("Protocol Configuration Update Request Assembled");
	return CW_TRUE;
}

CWBool CWAssembleMsgElemACWTPRadioInformation(const void *ctx, CWProtocolMessage *pm)
{

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);;

	CWInitMsgElem(ctx, pm, 5, CW_MSG_ELEMENT_IEEE80211_WTP_RADIO_INFORMATION_CW_TYPE);
	CWProtocolStore8(pm, 0);	// Radio ID
	CWProtocolStore8(pm, 0);	// Reserved
	CWProtocolStore8(pm, 0);	// Reserved
	CWProtocolStore8(pm, 0);	// Reserved
	CWProtocolStore8(pm, 0);	// Radio Information Type ABGN
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemACDescriptor(const void *ctx, CWProtocolMessage *pm)
{
	CWACVendorInfos infos;
	int i = 0, size = 0;

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);;

	if (!CWACGetVendorInfos(&infos))	// get infos
		return CW_FALSE;

	for (i = 0; i < infos.vendorInfosCount; i++)
		size += 8 + infos.vendorInfos[i].length;

	size += 12;		// size of message in bytes (excluding vendor infos, already counted)

	CWInitMsgElem(ctx, pm, size, CW_MSG_ELEMENT_AC_DESCRIPTOR_CW_TYPE);
	CWProtocolStore16(pm, CWACGetStations());	// Number of mobile stations associated
	CWProtocolStore16(pm, CWACGetLimit());	// Maximum number of mobile stations supported
	CWProtocolStore16(pm, CWACGetActiveWTPs());	// Number of WTPs active
	CWProtocolStore16(pm, CWACGetMaxWTPs());	// Maximum number of WTPs supported
	CWProtocolStore8(pm, CWACGetSecurity());
	CWProtocolStore8(pm, CWACGetRMACField());
	CWProtocolStore8(pm, 0);	//Reserved
	CWProtocolStore8(pm, CWACGetDTLSPolicy());	// DTLS Policy

	for (i = 0; i < infos.vendorInfosCount; i++) {
		CWProtocolStore32(pm, infos.vendorInfos[i].vendorIdentifier);
		CWProtocolStore16(pm, infos.vendorInfos[i].type);
		CWProtocolStore16(pm, infos.vendorInfos[i].length);
		CWProtocolStoreRawBytes(pm, (unsigned char *)infos.vendorInfos[i].valuePtr,
					infos.vendorInfos[i].length);
	}
	CWFinalizeMsgElem(pm);

	CWACDestroyVendorInfos(&infos);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemACIPv4List(const void *ctx, CWProtocolMessage *pm)
{
	int *list;
	int count, i;

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if (!CWACGetACIPv4List(&list, &count))
		return CW_FALSE;

	CWInitMsgElem(ctx, pm, 4 * count, CW_MSG_ELEMENT_AC_IPV4_LIST_CW_TYPE);
	for (i = 0; i < count; i++) {
		//      CWDebugLog("AC IPv4 List(%d): %d", i, list[i]);
		CWProtocolStore32(pm, list[i]);
	}
	CWFinalizeMsgElem(pm);

	CW_FREE_OBJECT(list);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemACIPv6List(const void *ctx, CWProtocolMessage *pm)
{
	struct in6_addr *list;
	int count, i;

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if (!CWACGetACIPv6List(&list, &count))
		return CW_FALSE;

	CWInitMsgElem(ctx, pm, 16 * count, CW_MSG_ELEMENT_AC_IPV6_LIST_CW_TYPE);
	for (i = 0; i < count; i++)
		CWProtocolStoreRawBytes(pm, (unsigned char *)list[i].s6_addr, 16);
	CWFinalizeMsgElem(pm);

	CW_FREE_OBJECT(list);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemACName(const void *ctx, CWProtocolMessage *pm)
{
	char *name;

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	name = CWACGetName();

	CWInitMsgElem(ctx, pm, strlen(name), CW_MSG_ELEMENT_AC_NAME_CW_TYPE);
	CWProtocolStoreStr(pm, name);
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemAddWLAN(const void *ctx, int radioID, CWProtocolMessage *pm, unsigned char *recv_packet, int len_packet)
{
	CWInitMsgElem(ctx, pm, len_packet, CW_MSG_ELEMENT_IEEE80211_ADD_WLAN_CW_TYPE);
	CWProtocolStoreRawBytes(pm, recv_packet, len_packet);
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemDeleteWLAN(const void *ctx, int radioID, CWProtocolMessage *pm, unsigned char *recv_packet, int len_packet)
{
	CWInitMsgElem(ctx, pm, len_packet, CW_MSG_ELEMENT_IEEE80211_DELETE_WLAN_CW_TYPE);
	CWProtocolStoreRawBytes(pm, recv_packet, len_packet);
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemAddStation(const void *ctx, int radioID, CWProtocolMessage *pm, unsigned char *StationMacAddr)
{
	CWInitMsgElem(ctx, pm, 8, CW_MSG_ELEMENT_ADD_STATION_CW_TYPE);

	CWProtocolStore8(pm, radioID);
	CWProtocolStore8(pm, 6);
	CWProtocolStoreRawBytes(pm, StationMacAddr, 6);
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemDeleteStation(const void *ctx, int radioID, CWProtocolMessage *pm, unsigned char *StationMacAddr)
{
	CWInitMsgElem(ctx, pm, 8, CW_MSG_ELEMENT_DELETE_STATION_CW_TYPE);

	CWProtocolStore8(pm, radioID);
	CWProtocolStore8(pm, 6);
	CWProtocolStoreRawBytes(pm, StationMacAddr, 6);
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemCWControlIPv4Addresses(const void *ctx, CWProtocolMessage *pm)
{
	int count, i;

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	count = CWACGetInterfacesCount();
	if (count <= 0)
		return CWErrorRaise(CW_ERROR_NEED_RESOURCE, "No Interfaces Configured");

	for (i = 0; i < count; i++) {	// one Message Element for each interface
		CWInitMsgElem(ctx, pm, 6, CW_MSG_ELEMENT_RADIO_ADMIN_STATE_CW_TYPE);
		CWProtocolStore32(pm, CWACGetInterfaceIPv4AddressAtIndex(i));
		CWProtocolStore16(pm, CWACGetInterfaceWTPCountAtIndex(i));
		CWFinalizeMsgElem(pm);
	}

	return CW_TRUE;
}

CWBool CWAssembleMsgElemCWControlIPv6Addresses(const void *ctx, CWProtocolMessage *pm)
{
	int count, i;

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	count = CWACGetInterfacesCount();

	for (i = 0; i < count; i++) {	// one Message Element for each interface
		CWInitMsgElem(ctx, pm, 18, CW_MSG_ELEMENT_RADIO_ADMIN_STATE_CW_TYPE);
		CWProtocolStoreRawBytes(pm, CWACGetInterfaceIPv6AddressAtIndex(i), 16);
		CWProtocolStore16(pm, CWACGetInterfaceWTPCountAtIndex(i));
		CWFinalizeMsgElem(pm);
	}

	return CW_TRUE;
}

CWBool CWAssembleMsgElemCWTimer(const void *ctx, CWProtocolMessage *pm)
{
	int discoveryTimer, echoTimer;

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if (!(CWACGetDiscoveryTimer(&discoveryTimer)) || !(CWACGetEchoRequestTimer(&echoTimer)))
		return CW_FALSE;

	//  CWDebugLog("Discovery Timer: %d", discoveryTimer);
	//  CWDebugLog("Echo Timer: %d", echoTimer);

	CWInitMsgElem(ctx, pm, 2, CW_MSG_ELEMENT_CW_TIMERS_CW_TYPE);
	CWProtocolStore8(pm, discoveryTimer);
	CWProtocolStore8(pm, echoTimer);
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

/* Le informazioni sui Radio ID vengono prese dalle informazioni del Configure Message
   Provvisoriamente l'error Report Period è settato allo stesso valore per tutte le radio del WTP*/
CWBool CWAssembleMsgElemDecryptErrorReportPeriod(const void *ctx, CWProtocolMessage *pm)
{
	const int reportInterval = 15;
	CWRadioAdminInfoValues *radiosInfoPtr;
	int radioCount = 0;
	int *iPtr;
	int i;

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if ((iPtr = ((int *)CWThreadGetSpecific(&gIndexSpecific))) == NULL) {
		CWLog("Critical Error... closing thread");
		CWCloseThread();
	}

	radiosInfoPtr = gWTPs[*iPtr].WTPProtocolManager.radioAdminInfo.radios;
	radioCount = gWTPs[*iPtr].WTPProtocolManager.radioAdminInfo.radiosCount;

	for (i = 0; i < radioCount; i++) {
		//      CWDebugLog("Decrypt Error Report Period: %d - %d", radiosInfoPtr[i].ID, reportInterval);
		CWInitMsgElem(ctx, pm, 3, CW_MSG_ELEMENT_CW_DECRYPT_ER_REPORT_PERIOD_CW_TYPE);
		CWProtocolStore8(pm, radiosInfoPtr[i].ID);	// ID of the radio
		CWProtocolStore16(pm, reportInterval);	// state of the radio
		CWFinalizeMsgElem(pm);
	}

	return CW_TRUE;
}

CWBool CWAssembleMsgElemIdleTimeout(const void *ctx, CWProtocolMessage *pm)
{
	int idleTimeout;

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if (!(CWACGetIdleTimeout(&idleTimeout)))
		return CW_FALSE;

	//  CWDebugLog("Idle Timeout: %d", idleTimeout);
	CWInitMsgElem(ctx, pm, 4, CW_MSG_ELEMENT_IDLE_TIMEOUT_CW_TYPE);
	CWProtocolStore32(pm, idleTimeout);
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemWTPFallback(const void *ctx, CWProtocolMessage *pm)
{
	int value = 0;		//PROVVISORIO

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	//  CWDebugLog("Fallback: %d", value);
	CWInitMsgElem(ctx, pm, 1, CW_MSG_ELEMENT_WTP_FALLBACK_CW_TYPE);
	CWProtocolStore8(pm, value);
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemRadioOperationalState(const void *ctx, int radioID, CWProtocolMessage *pm)
{
	CWRadiosOperationalInfo infos;
	int i;

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if (!(CWGetWTPRadiosOperationalState(radioID, &infos)))
		return CW_FALSE;

	for (i = 0; i < infos.radiosCount; i++) {
		//      CWDebugLog("Radio operational State: %d - %d - %d", infos.radios[i].ID, infos.radios[i].state, infos.radios[i].cause);
		CWInitMsgElem(ctx, pm, 3, CW_MSG_ELEMENT_RADIO_OPERAT_STATE_CW_TYPE);
		CWProtocolStore8(pm, infos.radios[i].ID);	// ID of the radio
		CWProtocolStore8(pm, infos.radios[i].state);	// state of the radio
		CWProtocolStore8(pm, infos.radios[i].cause);
		CWFinalizeMsgElem(pm);
	}

	CW_FREE_OBJECT(infos.radios);

	return CW_TRUE;
}

/*_________________________________________________________________________*/
/*  *****************************___PARSE___*****************************  */
CWBool CWParseACNameWithIndex(CWProtocolMessage *pm, int len, CWACNameWithIndexValues * valPtr)
{
	CWParseMessageElementStart(pm);

	valPtr->index = CWProtocolRetrieve8(pm);
	//CWDebugLog("CW_MSG_ELEMENT_WTP_RADIO_ID: %d", (valPtr->radios)[radioIndex].ID);

	valPtr->ACName = CWProtocolRetrieveStr(NULL, pm, len - 1);
	//CWDebugLog("CW_MSG_ELEMENT_WTP_RADIO_TYPE: %d",   (valPtr->radios)[radioIndex].type);

	//CWDebugLog("AC Name with index: %d - %s", valPtr->index, valPtr->ACName);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseDiscoveryType(CWProtocolMessage *pm, int len, CWDiscoveryRequestValues * valPtr)
{
	CWParseMessageElementStart(pm);

	valPtr->type = CWProtocolRetrieve8(pm);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseLocationData(CWProtocolMessage *pm, int len, char **valPtr)
{
	CWParseMessageElementStart(pm);

	*valPtr = CWProtocolRetrieveStr(NULL, pm, len);
	if (valPtr == NULL)
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
//  CWDebugLog("Location Data:%s", *valPtr);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseMsgElemDuplicateIPv4Address(CWProtocolMessage *pm, int len, WTPDuplicateIPv4 * valPtr)
{
	CWParseMessageElementStart(pm);

	valPtr->ipv4Address = CWProtocolRetrieve32(pm);
	valPtr->status = CWProtocolRetrieve8(pm);
	valPtr->length = CWProtocolRetrieve8(pm);
	valPtr->MACoffendingDevice_forIpv4 = (unsigned char *)CWProtocolRetrieveRawBytes(NULL, pm, valPtr->length);

	//valPtr->MACoffendingDevice_forIpv4 = (unsigned char*)CWProtocolRetrieveRawBytes(NULL, pm,6);
	//valPtr->status = CWProtocolRetrieve8(pm);
//  CWDebugLog("Duplicate IPv4: %d", valPtr->ipv4Address);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseMsgElemDuplicateIPv6Address(CWProtocolMessage *pm, int len, WTPDuplicateIPv6 * valPtr)
{
	CWParseMessageElementStart(pm);

	int i;
	for (i = 0; i < 16; i++) {
		unsigned char *aux;
		aux = CWProtocolRetrieveRawBytes(NULL, pm, 1);
		(valPtr->ipv6Address).s6_addr[i] = *aux;
	}

//  CWDebugLog("Duplicate IPv6");
	//valPtr->MACoffendingDevice_forIpv6 = (unsigned char*)CWProtocolRetrieveRawBytes(NULL, pm,6);

	valPtr->status = CWProtocolRetrieve8(pm);

	valPtr->length = CWProtocolRetrieve8(pm);

	valPtr->MACoffendingDevice_forIpv6 = (unsigned char *)CWProtocolRetrieveRawBytes(NULL, pm, valPtr->length);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseWTPStatisticsTimer(CWProtocolMessage *pm, int len, int *valPtr)
{
	CWParseMessageElementStart(pm);

	*valPtr = CWProtocolRetrieve16(pm);

//  CWDebugLog("WTP Statistics Timer: %d", *valPtr);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseWTPBoardData(CWProtocolMessage *pm, int len, CWWTPVendorInfos * valPtr)
{
	int theOffset, i, vendorID;
	CWParseMessageElementStart(pm);

	valPtr->vendorInfosCount = 0;

	// see how many vendor ID we have in the message
	vendorID = CWProtocolRetrieve32(pm);	// ID
	theOffset = pm->pos;
	while ((pm->pos - pm->start[pm->level - 1]) < len) {
		int tmp;

		CWProtocolRetrieve16(pm);	// type
		tmp = CWProtocolRetrieve16(pm);
		pm->pos += tmp;	// len
		valPtr->vendorInfosCount++;
	}

	pm->pos = theOffset;

	// actually read each vendor ID
	if (!(valPtr->vendorInfos = ralloc_array(NULL, CWWTPVendorInfoValues, valPtr->vendorInfosCount)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	for (i = 0; i < valPtr->vendorInfosCount; i++) {
		(valPtr->vendorInfos)[i].vendorIdentifier = vendorID;
		(valPtr->vendorInfos)[i].type = CWProtocolRetrieve16(pm);
		(valPtr->vendorInfos)[i].length = CWProtocolRetrieve16(pm);
		(valPtr->vendorInfos)[i].valuePtr =
			(char *)CWProtocolRetrieveRawBytes(NULL, pm, valPtr->vendorInfos[i].length);

		if ((valPtr->vendorInfos)[i].valuePtr == NULL)
			return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

		if ((valPtr->vendorInfos)[i].length == 4) {
			*(int *)((valPtr->vendorInfos)[i].valuePtr) = ntohl(*((valPtr->vendorInfos)[i].valuePtr));
		}
//      CWDebugLog("WTP Board Data: %d - %d - %d - %d", (valPtr->vendorInfos)[i].vendorIdentifier, (valPtr->vendorInfos)[i].type, (valPtr->vendorInfos)[i].length, *(valPtr->vendorInfos)[i].valuePtr);
	}

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseMsgElemDataTransferData(CWProtocolMessage *pm, int len,
				      CWProtocolWTPDataTransferRequestValues * valPtr)
{
	CWParseMessageElementStart(pm);

	valPtr->data = CWProtocolRetrieve8(pm);
	valPtr->length = CWProtocolRetrieve8(pm);
	valPtr->debug_info = CWProtocolRetrieveStr(NULL, pm, valPtr->length);
	//CWDebugLog("- %s ---",valPtr->debug_info);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseWTPDescriptor(CWProtocolMessage *pm, int len, CWWTPDescriptor * valPtr)
{
	int theOffset, i;
	CWParseMessageElementStart(pm);

	valPtr->maxRadios = CWProtocolRetrieve8(pm);
//  CWDebugLog("WTP Descriptor Max Radios: %d", valPtr->maxRadios);

	valPtr->radiosInUse = CWProtocolRetrieve8(pm);
//  CWDebugLog("WTP Descriptor Active Radios: %d",  valPtr->radiosInUse);

	valPtr->encCapabilities.encryptCapsCount = CWProtocolRetrieve8(pm);
	if (!(valPtr->encCapabilities.encryptCaps =
	      ralloc_array(NULL, CWWTPEncryptCapValues, valPtr->encCapabilities.encryptCapsCount)))
				    return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
	for (i = 0; i < valPtr->encCapabilities.encryptCapsCount; i++) {
		(valPtr->encCapabilities.encryptCaps)[i].WBID = CWProtocolRetrieve8(pm) & 0x1f;
		(valPtr->encCapabilities.encryptCaps)[i].encryptionCapabilities = CWProtocolRetrieve16(pm);
	}

	valPtr->vendorInfos.vendorInfosCount = 0;
	theOffset = pm->pos;

	// see how many vendor ID we have in the message
	while ((pm->pos - pm->start[pm->level - 1]) < len) {
		int tmp;
		CWProtocolRetrieve32(pm);	// ID
		CWProtocolRetrieve16(pm);	// type
		tmp = CWProtocolRetrieve16(pm);	// len
		pm->pos += tmp;
		valPtr->vendorInfos.vendorInfosCount++;
	}

	pm->pos = theOffset;

	// actually read each vendor ID
	if (!(valPtr->vendorInfos.vendorInfos =
	      ralloc_array(NULL, CWWTPVendorInfoValues, valPtr->vendorInfos.vendorInfosCount)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	for (i = 0; i < valPtr->vendorInfos.vendorInfosCount; i++) {
		valPtr->vendorInfos.vendorInfos[i].vendorIdentifier = CWProtocolRetrieve32(pm);
		valPtr->vendorInfos.vendorInfos[i].type             = CWProtocolRetrieve16(pm);
		valPtr->vendorInfos.vendorInfos[i].length           = CWProtocolRetrieve16(pm);
		valPtr->vendorInfos.vendorInfos[i].valuePtr =
			CWProtocolRetrieveStr(NULL, pm, valPtr->vendorInfos.vendorInfos[i].length);
		if (valPtr->vendorInfos.vendorInfos[i].valuePtr == NULL)
			return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

#if 0
		CWDebugLog("WTP Descriptor Vendor ID: %d", valPtr->vendorInfos.vendorInfos[i].vendorIdentifier);
		CWDebugLog("WTP Descriptor Type: %d",      valPtr->vendorInfos.vendorInfos[i].type);
		CWDebugLog("WTP Descriptor Length: %d",    valPtr->vendorInfos.vendorInfos[i].length);
		CWDebugLog("WTP Descriptor Value: %s",     valPtr->vendorInfos.vendorInfos[i].valuePtr);
#endif
	}

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseWTPFrameTunnelMode(CWProtocolMessage *pm, int len, CWframeTunnelMode * valPtr)
{
	CWParseMessageElementStart(pm);

	*valPtr = CWProtocolRetrieve8(pm);
//  CWDebugLog("CW_MSG_ELEMENT_WTP_FRAME_ENCAPSULATION_TYPE: %d", valPtr->frameTunnelMode);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseWTPIPv4Address(CWProtocolMessage *pm, int len, CWProtocolJoinRequestValues * valPtr)
{
	CWParseMessageElementStart(pm);

	valPtr->addr.sin_addr.s_addr = htonl(CWProtocolRetrieve32(pm));
	valPtr->addr.sin_family = AF_INET;
	valPtr->addr.sin_port = htons(CW_CONTROL_PORT);
//  CWDebugLog("WTP Address: %s", sock_ntop((struct sockaddr*) (&(valPtr->addr)), sizeof(valPtr->addr)));

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseWTPMACType(CWProtocolMessage *pm, int len, CWMACType * valPtr)
{
	CWParseMessageElementStart(pm);

	*valPtr = CWProtocolRetrieve8(pm);
//  CWDebugLog("CW_MSG_ELEMENT_WTP_MAC_TYPE: %d",   valPtr->MACType);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseWTPRadioInformation(CWProtocolMessage *pm, int len, unsigned char *valPtr)
{

	CWParseMessageElementStart(pm);
	__attribute__ ((unused)) int RadioID;			/* TODO: support multiple radios */

	RadioID = CWProtocolRetrieve8(pm);	// Radio ID
	CWProtocolRetrieve8(pm);	// Res
	CWProtocolRetrieve8(pm);	// Res
	CWProtocolRetrieve8(pm);	// Res
	*valPtr = CWProtocolRetrieve8(pm);	// Radio Information

	return CWParseMessageElementEnd(pm, len);

}

CWBool CWParseWTPSupportedRates(CWProtocolMessage *pm, int len, unsigned char *valPtr)
{

	CWParseMessageElementStart(pm);
	__attribute__ ((unused)) int RadioID;			/* TODO: support multiple radios */
	unsigned char sup_rates[8];

	RadioID = CWProtocolRetrieve8(pm);

	sup_rates[0] = CWProtocolRetrieve8(pm);
	sup_rates[1] = CWProtocolRetrieve8(pm);
	sup_rates[2] = CWProtocolRetrieve8(pm);
	sup_rates[3] = CWProtocolRetrieve8(pm);
	sup_rates[4] = CWProtocolRetrieve8(pm);
	sup_rates[5] = CWProtocolRetrieve8(pm);
	sup_rates[6] = CWProtocolRetrieve8(pm);
	sup_rates[7] = CWProtocolRetrieve8(pm);

	memcpy(valPtr, sup_rates, 8);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseWTPMultiDomainCapability(CWProtocolMessage *pm, int len, unsigned char *valPtr)
{

	CWParseMessageElementStart(pm);
	__attribute__ ((unused)) int RadioID;			/* TODO: support multiple radios */
	unsigned char sup_cap[6];

	RadioID = CWProtocolRetrieve8(pm);
	CWProtocolRetrieve8(pm);

	sup_cap[0] = CWProtocolRetrieve8(pm);
	sup_cap[1] = CWProtocolRetrieve8(pm);
	sup_cap[2] = CWProtocolRetrieve8(pm);
	sup_cap[3] = CWProtocolRetrieve8(pm);
	sup_cap[4] = CWProtocolRetrieve8(pm);
	sup_cap[5] = CWProtocolRetrieve8(pm);

	memcpy(valPtr, sup_cap, 6);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseWTPName(CWProtocolMessage *pm, int len, char **valPtr)
{
	CWParseMessageElementStart(pm);

	*valPtr = CWProtocolRetrieveStr(NULL, pm, len);
	if (valPtr == NULL)
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
//  CWDebugLog("WTP Name:%s", *valPtr);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseWTPRebootStatistics(CWProtocolMessage *pm, int len, WTPRebootStatisticsInfo * valPtr)
{
	CWParseMessageElementStart(pm);

	valPtr->rebootCount = CWProtocolRetrieve16(pm);
	valPtr->ACInitiatedCount = CWProtocolRetrieve16(pm);
	valPtr->linkFailurerCount = CWProtocolRetrieve16(pm);
	valPtr->SWFailureCount = CWProtocolRetrieve16(pm);
	valPtr->HWFailuireCount = CWProtocolRetrieve16(pm);
	valPtr->otherFailureCount = CWProtocolRetrieve16(pm);
	valPtr->unknownFailureCount = CWProtocolRetrieve16(pm);
	valPtr->lastFailureType = CWProtocolRetrieve8(pm);

//  CWDebugLog("");
//  CWDebugLog("WTPRebootStat(1): %d - %d - %d", valPtr->rebootCount, valPtr->ACInitiatedCount, valPtr->linkFailurerCount);
//  CWDebugLog("WTPRebootStat(2): %d - %d - %d", valPtr->SWFailureCount, valPtr->HWFailuireCount, valPtr->otherFailureCount);
//  CWDebugLog("WTPRebootStat(3): %d - %d", valPtr->unknownFailureCount, valPtr->lastFailureType);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseWTPRadioStatistics(CWProtocolMessage *pm, int len, WTPRadioStatisticsValues * valPtr)
{
	CWParseMessageElementStart(pm);

	valPtr->radioID = CWProtocolRetrieve8(pm);
	valPtr->WTPRadioStatistics.lastFailureType = CWProtocolRetrieve8(pm);
	valPtr->WTPRadioStatistics.resetCount = CWProtocolRetrieve16(pm);
	valPtr->WTPRadioStatistics.SWFailureCount = CWProtocolRetrieve16(pm);
	valPtr->WTPRadioStatistics.HWFailuireCount = CWProtocolRetrieve16(pm);
	valPtr->WTPRadioStatistics.otherFailureCount = CWProtocolRetrieve16(pm);
	valPtr->WTPRadioStatistics.unknownFailureCount = CWProtocolRetrieve16(pm);
	valPtr->WTPRadioStatistics.configUpdateCount = CWProtocolRetrieve16(pm);
	valPtr->WTPRadioStatistics.channelChangeCount = CWProtocolRetrieve16(pm);
	valPtr->WTPRadioStatistics.bandChangeCount = CWProtocolRetrieve16(pm);
	valPtr->WTPRadioStatistics.currentNoiseFloor = CWProtocolRetrieve16(pm);

//  CWDebugLog("");
//  CWDebugLog("WTPRadioStatistics of radio: \"%d\"", valPtr->radioID);
//  CWDebugLog("WTPRadioStatistics(1): %d - %d - %d", valPtr->WTPRadioStatistics.lastFailureType, valPtr->WTPRadioStatistics.resetCount, valPtr->WTPRadioStatistics.SWFailureCount);
//  CWDebugLog("WTPRadioStatistics(2): %d - %d - %d", valPtr->WTPRadioStatistics.HWFailuireCount, valPtr->WTPRadioStatistics.otherFailureCount, valPtr->WTPRadioStatistics.unknownFailureCount);
//  CWDebugLog("WTPRadioStatistics(3): %d - %d - %d - %d", valPtr->WTPRadioStatistics.configUpdateCount, valPtr->WTPRadioStatistics.channelChangeCount, valPtr->WTPRadioStatistics.bandChangeCount, valPtr->WTPRadioStatistics.currentNoiseFloor);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseWTPOperationalStatistics(CWProtocolMessage *pm, int len, WTPOperationalStatisticsValues * valPtr)
{
	CWParseMessageElementStart(pm);

	valPtr->radioID = CWProtocolRetrieve8(pm);
	valPtr->TxQueueLevel = CWProtocolRetrieve8(pm);
	valPtr->wirelessLinkFramesPerSec = CWProtocolRetrieve16(pm);

//  CWDebugLog("WTPOperationalStatistics of radio \"%d\": %d - %d", valPtr->radioID, valPtr->TxQueueLevel, valPtr->wirelessLinkFramesPerSec);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseMsgElemDecryptErrorReport(CWProtocolMessage *pm, int len, CWDecryptErrorReportValues * valPtr)
{
	CWParseMessageElementStart(pm);

	valPtr->ID = CWProtocolRetrieve8(pm);
	valPtr->numEntries = CWProtocolRetrieve8(pm);

	valPtr->length = CWProtocolRetrieve8(pm);

	valPtr->decryptErrorMACAddressList = NULL;
	if ((valPtr->numEntries) > 0) {
		if (!(valPtr->decryptErrorMACAddressList = ralloc_array(NULL, CWMACAddress, valPtr->numEntries)))
			return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

		int size = sizeof(CWMACAddress) * (valPtr->numEntries);
		CW_COPY_MEMORY(valPtr->decryptErrorMACAddressList, CWProtocolRetrieveRawBytes(NULL, pm, size), size);
		//valPtr->decryptErrorMACAddressList =(unsigned char*) CWProtocolRetrieveRawBytes(NULL, pm, sizeof(CWMACAddress)*(valPtr->numEntries));
		//CW_COPY_MEMORY(&((valPtr->ACIPv6List)[i]), CWProtocolRetrieveRawBytes(NULL, pm, 16), 16);
		/*
		   int j;
		   for (j=0;j<(sizeof(CWMACAddress)*(valPtr->numEntries)); j++)
		   CWDebugLog("##(%d/6) = %d", j%6, (valPtr->decryptErrorMACAddressList)[j/6][j%6]);
		 */
	}
//  CWDebugLog("");
//  CWDebugLog("Radio Decrypt Error Report of radio \"%d\": %d", valPtr->ID, valPtr->numEntries);

	return CWParseMessageElementEnd(pm, len);
}

/*
CWBool CWParseWTPRadioInfo(CWPr<otocolMessage *pm, int len, CWRadiosInformation *valPtr, int radioIndex) {
    CWParseMessageElementStart(pm);

    (valPtr->radios)[radioIndex].ID = CWProtocolRetrieve8(pm);
    (valPtr->radios)[radioIndex].type = CWProtocolRetrieve32(pm);

    CWDebugLog("WTP Radio info: %d %d ", (valPtr->radios)[radioIndex].ID, (valPtr->radios)[radioIndex].type);

    return CWParseMessageElementEnd(pm, len);
}
*/
