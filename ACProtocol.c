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

#include "CWAC.h"
#include "CWVendorPayloads.h"

unsigned char WTPRadioInformationType;

/*____________________________________________________________________________*/
/*  *****************************___ASSEMBLE___*****************************  */
/*Update 2009:
    Assemble protocol Configuration update request.
    Mainly added to  manage vendor specific packets*/
CWBool CWProtocolAssembleConfigurationUpdateRequest(CWProtocolMessage ** msgElems,
						    int *msgElemCountPtr, int MsgElementType)
{
	int *iPtr;
	int k = -1;

	if (msgElems == NULL || msgElemCountPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if ((iPtr = ((int *)CWThreadGetSpecific(&gIndexSpecific))) == NULL) {
		return CW_FALSE;
	}

	*msgElemCountPtr = 1;

	CWLog("Assembling Protocol Configuration Update Request...");

	*msgElems = CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(*msgElemCountPtr, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); );

	/* Selection of type of Conf Update Request */

	switch (MsgElementType) {
	case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_UCI:

		// Assemble Message Elements
		if (!(CWAssembleWTPVendorPayloadUCI(msgElems, &(*msgElems[++k])))) {
			CW_FREE_OBJECT(*msgElems);
			return CW_FALSE;	// error will be handled by the caller
		}
		break;
	case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_WUM:

		// Assemble Message Elements
		if (!(CWAssembleWTPVendorPayloadWUM(msgElems, &(*msgElems[++k])))) {
			CW_FREE_OBJECT(*msgElems);
			return CW_FALSE;	// error will be handled by the caller
		}
		break;
	default:{
			return CW_FALSE;	// error will be handled by the caller
		}
	}

	CWLog("Protocol Configuration Update Request Assembled");

	return CW_TRUE;
}

CWBool CWAssembleMsgElemACWTPRadioInformation(const void *ctx, CWProtocolMessage * msgPtr)
{

	if (msgPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);;

	CWInitMsgElem(ctx, msgPtr, 5, CW_MSG_ELEMENT_IEEE80211_WTP_RADIO_INFORMATION_CW_TYPE);
	CWProtocolStore8(msgPtr, 0);	// Radio ID
	CWProtocolStore8(msgPtr, 0);	// Reserved
	CWProtocolStore8(msgPtr, 0);	// Reserved
	CWProtocolStore8(msgPtr, 0);	// Reserved
	CWProtocolStore8(msgPtr, 0);	// Radio Information Type ABGN
	CWFinalizeMsgElem(msgPtr);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemACDescriptor(const void *ctx, CWProtocolMessage * msgPtr)
{
	CWACVendorInfos infos;
	int i = 0, size = 0;

	if (msgPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);;

	if (!CWACGetVendorInfos(&infos))	// get infos
		return CW_FALSE;

	for (i = 0; i < infos.vendorInfosCount; i++)
		size += 8 + infos.vendorInfos[i].length;

	size += 12;		// size of message in bytes (excluding vendor infos, already counted)

	CWInitMsgElem(ctx, msgPtr, size, CW_MSG_ELEMENT_AC_DESCRIPTOR_CW_TYPE);
	CWProtocolStore16(msgPtr, CWACGetStations());	// Number of mobile stations associated
	CWProtocolStore16(msgPtr, CWACGetLimit());	// Maximum number of mobile stations supported
	CWProtocolStore16(msgPtr, CWACGetActiveWTPs());	// Number of WTPs active
	CWProtocolStore16(msgPtr, CWACGetMaxWTPs());	// Maximum number of WTPs supported
	CWProtocolStore8(msgPtr, CWACGetSecurity());
	CWProtocolStore8(msgPtr, CWACGetRMACField());
	CWProtocolStore8(msgPtr, 0);	//Reserved
	CWProtocolStore8(msgPtr, CWACGetDTLSPolicy());	// DTLS Policy

	for (i = 0; i < infos.vendorInfosCount; i++) {
		CWProtocolStore32(msgPtr, infos.vendorInfos[i].vendorIdentifier);
		CWProtocolStore16(msgPtr, infos.vendorInfos[i].type);
		CWProtocolStore16(msgPtr, infos.vendorInfos[i].length);
		CWProtocolStoreRawBytes(msgPtr, (unsigned char *)infos.vendorInfos[i].valuePtr,
					infos.vendorInfos[i].length);
	}
	CWFinalizeMsgElem(msgPtr);

	CWACDestroyVendorInfos(&infos);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemACIPv4List(const void *ctx, CWProtocolMessage * msgPtr)
{
	int *list;
	int count, i;

	if (msgPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if (!CWACGetACIPv4List(&list, &count))
		return CW_FALSE;

	CWInitMsgElem(ctx, msgPtr, 4 * count, CW_MSG_ELEMENT_AC_IPV4_LIST_CW_TYPE);
	for (i = 0; i < count; i++) {
		//      CWDebugLog("AC IPv4 List(%d): %d", i, list[i]);
		CWProtocolStore32(msgPtr, list[i]);
	}
	CWFinalizeMsgElem(msgPtr);

	CW_FREE_OBJECT(list);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemACIPv6List(const void *ctx, CWProtocolMessage * msgPtr)
{
	struct in6_addr *list;
	int count, i;

	if (msgPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if (!CWACGetACIPv6List(&list, &count))
		return CW_FALSE;

	CWInitMsgElem(ctx, msgPtr, 16 * count, CW_MSG_ELEMENT_AC_IPV6_LIST_CW_TYPE);
	for (i = 0; i < count; i++)
		CWProtocolStoreRawBytes(msgPtr, (unsigned char *)list[i].s6_addr, 16);
	CWFinalizeMsgElem(msgPtr);

	CW_FREE_OBJECT(list);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemACName(const void *ctx, CWProtocolMessage * msgPtr)
{
	char *name;

	if (msgPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	name = CWACGetName();

	CWInitMsgElem(ctx, msgPtr, strlen(name), CW_MSG_ELEMENT_AC_NAME_CW_TYPE);
	CWProtocolStoreStr(msgPtr, name);
	CWFinalizeMsgElem(msgPtr);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemAddWLAN(const void *ctx, int radioID, CWProtocolMessage * msgPtr, unsigned char *recv_packet, int len_packet)
{
	CWInitMsgElem(ctx, msgPtr, len_packet, CW_MSG_ELEMENT_IEEE80211_ADD_WLAN_CW_TYPE);
	CWProtocolStoreRawBytes(msgPtr, recv_packet, len_packet);
	CWFinalizeMsgElem(msgPtr);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemDeleteWLAN(const void *ctx, int radioID, CWProtocolMessage * msgPtr, unsigned char *recv_packet, int len_packet)
{
	CWInitMsgElem(ctx, msgPtr, len_packet, CW_MSG_ELEMENT_IEEE80211_DELETE_WLAN_CW_TYPE);
	CWProtocolStoreRawBytes(msgPtr, recv_packet, len_packet);
	CWFinalizeMsgElem(msgPtr);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemAddStation(const void *ctx, int radioID, CWProtocolMessage * msgPtr, unsigned char *StationMacAddr)
{
	CWInitMsgElem(ctx, msgPtr, 8, CW_MSG_ELEMENT_ADD_STATION_CW_TYPE);

	CWProtocolStore8(msgPtr, radioID);
	CWProtocolStore8(msgPtr, 6);
	CWProtocolStoreRawBytes(msgPtr, StationMacAddr, 6);
	CWFinalizeMsgElem(msgPtr);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemDeleteStation(const void *ctx, int radioID, CWProtocolMessage * msgPtr, unsigned char *StationMacAddr)
{
	CWInitMsgElem(ctx, msgPtr, 8, CW_MSG_ELEMENT_DELETE_STATION_CW_TYPE);

	CWProtocolStore8(msgPtr, radioID);
	CWProtocolStore8(msgPtr, 6);
	CWProtocolStoreRawBytes(msgPtr, StationMacAddr, 6);
	CWFinalizeMsgElem(msgPtr);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemCWControlIPv4Addresses(const void *ctx, CWProtocolMessage * msgPtr)
{
	int count, i;
	CWProtocolMessage *msgs;
	int len = 0;

	if (msgPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	count = CWACGetInterfacesCount();

	if (count <= 0)
		return CWErrorRaise(CW_ERROR_NEED_RESOURCE, "No Interfaces Configured");

	msgs = CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(count, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); );

	for (i = 0; i < count; i++) {	// one Message Element for each interface
		CWInitMsgElem(msgs, msgs + i, 6, CW_MSG_ELEMENT_RADIO_ADMIN_STATE_CW_TYPE);
		CWProtocolStore32(msgs + i, CWACGetInterfaceIPv4AddressAtIndex(i));
		CWProtocolStore16(msgs + i, CWACGetInterfaceWTPCountAtIndex(i));
		CWFinalizeMsgElem(msgs + i);

		len += msgs[i].offset;
	}

	CW_CREATE_PROTOCOL_MESSAGE(ctx, *msgPtr, len, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); );

	for (i = 0; i < count; i++)
		CWProtocolStoreMessage(msgPtr, msgs + i);

	CW_FREE_OBJECT(msgs);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemCWControlIPv6Addresses(const void *ctx, CWProtocolMessage * msgPtr)
{
	int count, i;
	CWProtocolMessage *msgs;
	int len = 0;

	if (msgPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	count = CWACGetInterfacesCount();

	msgs = CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(count, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); );

	for (i = 0; i < count; i++) {	// one Message Element for each interface
		CWInitMsgElem(msgs, msgs +i, 18, CW_MSG_ELEMENT_RADIO_ADMIN_STATE_CW_TYPE);
		CWProtocolStoreRawBytes(msgs + i, CWACGetInterfaceIPv6AddressAtIndex(i), 16);
		CWProtocolStore16(msgs + i, CWACGetInterfaceWTPCountAtIndex(i));
		CWFinalizeMsgElem(msgs + i);

		len += msgs[i].offset;
	}

	CW_CREATE_PROTOCOL_MESSAGE(ctx, *msgPtr, len, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); );

	for (i = 0; i < count; i++)
		CWProtocolStoreMessage(msgPtr, msgs + i);

	CW_FREE_OBJECT(msgs);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemCWTimer(const void *ctx, CWProtocolMessage * msgPtr)
{
	int discoveryTimer, echoTimer;

	if (msgPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if (!(CWACGetDiscoveryTimer(&discoveryTimer)) || !(CWACGetEchoRequestTimer(&echoTimer)))
		return CW_FALSE;

	//  CWDebugLog("Discovery Timer: %d", discoveryTimer);
	//  CWDebugLog("Echo Timer: %d", echoTimer);

	CWInitMsgElem(ctx, msgPtr, 2, CW_MSG_ELEMENT_CW_TIMERS_CW_TYPE);
	CWProtocolStore8(msgPtr, discoveryTimer);
	CWProtocolStore8(msgPtr, echoTimer);
	CWFinalizeMsgElem(msgPtr);

	return CW_TRUE;
}

/* Le informazioni sui Radio ID vengono prese dalle informazioni del Configure Message
   Provvisoriamente l'error Report Period è settato allo stesso valore per tutte le radio del WTP*/
CWBool CWAssembleMsgElemDecryptErrorReportPeriod(const void *ctx, CWProtocolMessage * msgPtr)
{
	const int reportInterval = 15;
	CWProtocolMessage *msgs;
	CWRadioAdminInfoValues *radiosInfoPtr;
	int radioCount = 0;
	int *iPtr;
	int len = 0;
	int i;

	if (msgPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if ((iPtr = ((int *)CWThreadGetSpecific(&gIndexSpecific))) == NULL) {
		CWLog("Critical Error... closing thread");
		CWCloseThread();
	}

	radiosInfoPtr = gWTPs[*iPtr].WTPProtocolManager.radioAdminInfo.radios;
	radioCount = gWTPs[*iPtr].WTPProtocolManager.radioAdminInfo.radiosCount;

	msgs = CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(radioCount, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); );

	for (i = 0; i < radioCount; i++) {
		//      CWDebugLog("Decrypt Error Report Period: %d - %d", radiosInfoPtr[i].ID, reportInterval);
		CWInitMsgElem(msgs, msgs +i, 3, CW_MSG_ELEMENT_CW_DECRYPT_ER_REPORT_PERIOD_CW_TYPE);
		CWProtocolStore8(msgs + i, radiosInfoPtr[i].ID);	// ID of the radio
		CWProtocolStore16(msgs + i, reportInterval);	// state of the radio
		CWFinalizeMsgElem(msgs + i);

		len += msgs[i].offset;
	}

	CW_CREATE_PROTOCOL_MESSAGE(ctx, *msgPtr, len, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); );

	for (i = 0; i < radioCount; i++)
		CWProtocolStoreMessage(msgPtr, msgs + i);

	CW_FREE_OBJECT(msgs);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemIdleTimeout(const void *ctx, CWProtocolMessage * msgPtr)
{
	int idleTimeout;

	if (msgPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if (!(CWACGetIdleTimeout(&idleTimeout)))
		return CW_FALSE;

	//  CWDebugLog("Idle Timeout: %d", idleTimeout);
	CWInitMsgElem(ctx, msgPtr, 4, CW_MSG_ELEMENT_IDLE_TIMEOUT_CW_TYPE);
	CWProtocolStore32(msgPtr, idleTimeout);
	CWFinalizeMsgElem(msgPtr);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemWTPFallback(const void *ctx, CWProtocolMessage * msgPtr)
{
	int value = 0;		//PROVVISORIO

	if (msgPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	//  CWDebugLog("Fallback: %d", value);
	CWInitMsgElem(ctx, msgPtr, 1, CW_MSG_ELEMENT_WTP_FALLBACK_CW_TYPE);
	CWProtocolStore8(msgPtr, value);
	CWFinalizeMsgElem(msgPtr);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemRadioOperationalState(const void *ctx, int radioID, CWProtocolMessage * msgPtr)
{
	CWRadiosOperationalInfo infos;
	CWProtocolMessage *msgs;
	int len = 0;
	int i;

	if (msgPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if (!(CWGetWTPRadiosOperationalState(radioID, &infos)))
		return CW_FALSE;

	msgs = CW_CREATE_PROTOCOL_MSG_ARRAY_ERR((infos.radiosCount), return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); );

	for (i = 0; i < infos.radiosCount; i++) {
		//      CWDebugLog("Radio operational State: %d - %d - %d", infos.radios[i].ID, infos.radios[i].state, infos.radios[i].cause);
		CWInitMsgElem(msgs, msgs +i, 3, CW_MSG_ELEMENT_RADIO_OPERAT_STATE_CW_TYPE);
		CWProtocolStore8(msgs + i, infos.radios[i].ID);	// ID of the radio
		CWProtocolStore8(msgs + i, infos.radios[i].state);	// state of the radio
		CWProtocolStore8(msgs + i, infos.radios[i].cause);
		CWFinalizeMsgElem(msgs + i);

		len += msgs[i].offset;
	}

	CW_CREATE_PROTOCOL_MESSAGE(ctx, *msgPtr, len, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); );

	for (i = 0; i < infos.radiosCount; i++)
		CWProtocolStoreMessage(msgPtr, msgs + i);

	CW_FREE_OBJECT(msgs);
	CW_FREE_OBJECT(infos.radios);

	return CW_TRUE;
}

/*_________________________________________________________________________*/
/*  *****************************___PARSE___*****************************  */
CWBool CWParseACNameWithIndex(CWProtocolMessage * msgPtr, int len, CWACNameWithIndexValues * valPtr)
{
	CWParseMessageElementStart();

	valPtr->index = CWProtocolRetrieve8(msgPtr);
	//CWDebugLog("CW_MSG_ELEMENT_WTP_RADIO_ID: %d", (valPtr->radios)[radioIndex].ID);

	valPtr->ACName = CWProtocolRetrieveStr(NULL, msgPtr, len - 1);
	//CWDebugLog("CW_MSG_ELEMENT_WTP_RADIO_TYPE: %d",   (valPtr->radios)[radioIndex].type);

	//CWDebugLog("AC Name with index: %d - %s", valPtr->index, valPtr->ACName);

	CWParseMessageElementEnd();
}

CWBool CWParseDiscoveryType(CWProtocolMessage * msgPtr, int len, CWDiscoveryRequestValues * valPtr)
{
	CWParseMessageElementStart();

	valPtr->type = CWProtocolRetrieve8(msgPtr);

	CWParseMessageElementEnd();
}

CWBool CWParseLocationData(CWProtocolMessage * msgPtr, int len, char **valPtr)
{
	CWParseMessageElementStart();

	*valPtr = CWProtocolRetrieveStr(NULL, msgPtr, len);
	if (valPtr == NULL)
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
//  CWDebugLog("Location Data:%s", *valPtr);

	CWParseMessageElementEnd();
}

CWBool CWParseMsgElemDuplicateIPv4Address(CWProtocolMessage * msgPtr, int len, WTPDuplicateIPv4 * valPtr)
{
	CWParseMessageElementStart();

	valPtr->ipv4Address = CWProtocolRetrieve32(msgPtr);
	valPtr->status = CWProtocolRetrieve8(msgPtr);
	valPtr->length = CWProtocolRetrieve8(msgPtr);
	valPtr->MACoffendingDevice_forIpv4 = (unsigned char *)CWProtocolRetrieveRawBytes(NULL, msgPtr, valPtr->length);

	//valPtr->MACoffendingDevice_forIpv4 = (unsigned char*)CWProtocolRetrieveRawBytes(NULL, msgPtr,6);
	//valPtr->status = CWProtocolRetrieve8(msgPtr);
//  CWDebugLog("Duplicate IPv4: %d", valPtr->ipv4Address);

	CWParseMessageElementEnd();
}

CWBool CWParseMsgElemDuplicateIPv6Address(CWProtocolMessage * msgPtr, int len, WTPDuplicateIPv6 * valPtr)
{
	CWParseMessageElementStart();

	int i;
	for (i = 0; i < 16; i++) {
		unsigned char *aux;
		aux = CWProtocolRetrieveRawBytes(NULL, msgPtr, 1);
		(valPtr->ipv6Address).s6_addr[i] = *aux;
	}

//  CWDebugLog("Duplicate IPv6");
	//valPtr->MACoffendingDevice_forIpv6 = (unsigned char*)CWProtocolRetrieveRawBytes(NULL, msgPtr,6);

	valPtr->status = CWProtocolRetrieve8(msgPtr);

	valPtr->length = CWProtocolRetrieve8(msgPtr);

	valPtr->MACoffendingDevice_forIpv6 = (unsigned char *)CWProtocolRetrieveRawBytes(NULL, msgPtr, valPtr->length);

	CWParseMessageElementEnd();
}

CWBool CWParseWTPStatisticsTimer(CWProtocolMessage * msgPtr, int len, int *valPtr)
{
	CWParseMessageElementStart();

	*valPtr = CWProtocolRetrieve16(msgPtr);

//  CWDebugLog("WTP Statistics Timer: %d", *valPtr);

	CWParseMessageElementEnd();
}

CWBool CWParseWTPBoardData(CWProtocolMessage * msgPtr, int len, CWWTPVendorInfos * valPtr)
{
	int theOffset, i, vendorID;
	CWParseMessageElementStart();

	valPtr->vendorInfosCount = 0;

	// see how many vendor ID we have in the message
	vendorID = CWProtocolRetrieve32(msgPtr);	// ID
	theOffset = msgPtr->offset;
	while ((msgPtr->offset - oldOffset) < len) {	// oldOffset stores msgPtr->offset's value at the beginning of this function.
		// See the definition of the CWParseMessageElementStart() macro.
		int tmp;

		CWProtocolRetrieve16(msgPtr);	// type
		tmp = CWProtocolRetrieve16(msgPtr);
		msgPtr->offset += tmp;	// len
		valPtr->vendorInfosCount++;
	}

	msgPtr->offset = theOffset;

	// actually read each vendor ID
	if (!(valPtr->vendorInfos = ralloc_array(NULL, CWWTPVendorInfoValues, valPtr->vendorInfosCount)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	for (i = 0; i < valPtr->vendorInfosCount; i++) {
		(valPtr->vendorInfos)[i].vendorIdentifier = vendorID;
		(valPtr->vendorInfos)[i].type = CWProtocolRetrieve16(msgPtr);
		(valPtr->vendorInfos)[i].length = CWProtocolRetrieve16(msgPtr);
		(valPtr->vendorInfos)[i].valuePtr =
			(char *)CWProtocolRetrieveRawBytes(NULL, msgPtr, valPtr->vendorInfos[i].length);

		if ((valPtr->vendorInfos)[i].valuePtr == NULL)
			return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

		if ((valPtr->vendorInfos)[i].length == 4) {
			*(int *)((valPtr->vendorInfos)[i].valuePtr) = ntohl(*((valPtr->vendorInfos)[i].valuePtr));
		}
//      CWDebugLog("WTP Board Data: %d - %d - %d - %d", (valPtr->vendorInfos)[i].vendorIdentifier, (valPtr->vendorInfos)[i].type, (valPtr->vendorInfos)[i].length, *(valPtr->vendorInfos)[i].valuePtr);
	}

	CWParseMessageElementEnd();
}

CWBool CWParseMsgElemDataTransferData(CWProtocolMessage * msgPtr, int len,
				      CWProtocolWTPDataTransferRequestValues * valPtr)
{
	CWParseMessageElementStart();

	valPtr->data = CWProtocolRetrieve8(msgPtr);
	valPtr->length = CWProtocolRetrieve8(msgPtr);
	valPtr->debug_info = CWProtocolRetrieveStr(NULL, msgPtr, valPtr->length);
	//CWDebugLog("- %s ---",valPtr->debug_info);

	CWParseMessageElementEnd();
}

CWBool CWParseWTPDescriptor(CWProtocolMessage * msgPtr, int len, CWWTPDescriptor * valPtr)
{
	int theOffset, i;
	CWParseMessageElementStart();

	valPtr->maxRadios = CWProtocolRetrieve8(msgPtr);
//  CWDebugLog("WTP Descriptor Max Radios: %d", valPtr->maxRadios);

	valPtr->radiosInUse = CWProtocolRetrieve8(msgPtr);
//  CWDebugLog("WTP Descriptor Active Radios: %d",  valPtr->radiosInUse);

	valPtr->encCapabilities.encryptCapsCount = CWProtocolRetrieve8(msgPtr);
	if (!(valPtr->encCapabilities.encryptCaps =
	      ralloc_array(NULL, CWWTPEncryptCapValues, valPtr->encCapabilities.encryptCapsCount)))
				    return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
	for (i = 0; i < valPtr->encCapabilities.encryptCapsCount; i++) {
		(valPtr->encCapabilities.encryptCaps)[i].WBID = CWProtocolRetrieve8(msgPtr) & 0x1f;
		(valPtr->encCapabilities.encryptCaps)[i].encryptionCapabilities = CWProtocolRetrieve16(msgPtr);
	}

	valPtr->vendorInfos.vendorInfosCount = 0;
	theOffset = msgPtr->offset;

	// see how many vendor ID we have in the message
	while ((msgPtr->offset - oldOffset) < len) {	// oldOffset stores msgPtr->offset's value at the beginning of this function.
		// See the definition of the CWParseMessageElementStart() macro.
		int tmp;
		CWProtocolRetrieve32(msgPtr);	// ID
		CWProtocolRetrieve16(msgPtr);	// type
		tmp = CWProtocolRetrieve16(msgPtr);	// len
		msgPtr->offset += tmp;
		valPtr->vendorInfos.vendorInfosCount++;
	}

	msgPtr->offset = theOffset;

	// actually read each vendor ID
	if (!(valPtr->vendorInfos.vendorInfos =
	      ralloc_array(NULL, CWWTPVendorInfoValues, valPtr->vendorInfos.vendorInfosCount)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	for (i = 0; i < valPtr->vendorInfos.vendorInfosCount; i++) {
		valPtr->vendorInfos.vendorInfos[i].vendorIdentifier = CWProtocolRetrieve32(msgPtr);
		valPtr->vendorInfos.vendorInfos[i].type             = CWProtocolRetrieve16(msgPtr);
		valPtr->vendorInfos.vendorInfos[i].length           = CWProtocolRetrieve16(msgPtr);
		valPtr->vendorInfos.vendorInfos[i].valuePtr =
			CWProtocolRetrieveStr(NULL, msgPtr, valPtr->vendorInfos.vendorInfos[i].length);
		if (valPtr->vendorInfos.vendorInfos[i].valuePtr == NULL)
			return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

#if 0
		CWDebugLog("WTP Descriptor Vendor ID: %d", valPtr->vendorInfos.vendorInfos[i].vendorIdentifier);
		CWDebugLog("WTP Descriptor Type: %d",      valPtr->vendorInfos.vendorInfos[i].type);
		CWDebugLog("WTP Descriptor Length: %d",    valPtr->vendorInfos.vendorInfos[i].length);
		CWDebugLog("WTP Descriptor Value: %s",     valPtr->vendorInfos.vendorInfos[i].valuePtr);
#endif
	}

	CWParseMessageElementEnd();
}

CWBool CWParseWTPFrameTunnelMode(CWProtocolMessage * msgPtr, int len, CWframeTunnelMode * valPtr)
{
	CWParseMessageElementStart();

	*valPtr = CWProtocolRetrieve8(msgPtr);
//  CWDebugLog("CW_MSG_ELEMENT_WTP_FRAME_ENCAPSULATION_TYPE: %d", valPtr->frameTunnelMode);

	CWParseMessageElementEnd();
}

CWBool CWParseWTPIPv4Address(CWProtocolMessage * msgPtr, int len, CWProtocolJoinRequestValues * valPtr)
{
	CWParseMessageElementStart();

	valPtr->addr.sin_addr.s_addr = htonl(CWProtocolRetrieve32(msgPtr));
	valPtr->addr.sin_family = AF_INET;
	valPtr->addr.sin_port = htons(CW_CONTROL_PORT);
//  CWDebugLog("WTP Address: %s", sock_ntop((struct sockaddr*) (&(valPtr->addr)), sizeof(valPtr->addr)));

	CWParseMessageElementEnd();
}

CWBool CWParseWTPMACType(CWProtocolMessage * msgPtr, int len, CWMACType * valPtr)
{
	CWParseMessageElementStart();

	*valPtr = CWProtocolRetrieve8(msgPtr);
//  CWDebugLog("CW_MSG_ELEMENT_WTP_MAC_TYPE: %d",   valPtr->MACType);

	CWParseMessageElementEnd();
}

CWBool CWParseWTPRadioInformation(CWProtocolMessage * msgPtr, int len, unsigned char *valPtr)
{

	CWParseMessageElementStart();
	__attribute__ ((unused)) int RadioID;			/* TODO: support multiple radios */

	RadioID = CWProtocolRetrieve8(msgPtr);	// Radio ID
	CWProtocolRetrieve8(msgPtr);	// Res
	CWProtocolRetrieve8(msgPtr);	// Res
	CWProtocolRetrieve8(msgPtr);	// Res
	*valPtr = CWProtocolRetrieve8(msgPtr);	// Radio Information

	CWParseMessageElementEnd();

}

CWBool CWParseWTPSupportedRates(CWProtocolMessage * msgPtr, int len, unsigned char *valPtr)
{

	CWParseMessageElementStart();
	__attribute__ ((unused)) int RadioID;			/* TODO: support multiple radios */
	unsigned char sup_rates[8];

	RadioID = CWProtocolRetrieve8(msgPtr);

	sup_rates[0] = CWProtocolRetrieve8(msgPtr);
	sup_rates[1] = CWProtocolRetrieve8(msgPtr);
	sup_rates[2] = CWProtocolRetrieve8(msgPtr);
	sup_rates[3] = CWProtocolRetrieve8(msgPtr);
	sup_rates[4] = CWProtocolRetrieve8(msgPtr);
	sup_rates[5] = CWProtocolRetrieve8(msgPtr);
	sup_rates[6] = CWProtocolRetrieve8(msgPtr);
	sup_rates[7] = CWProtocolRetrieve8(msgPtr);

	memcpy(valPtr, sup_rates, 8);

	CWParseMessageElementEnd();
}

CWBool CWParseWTPMultiDomainCapability(CWProtocolMessage * msgPtr, int len, unsigned char *valPtr)
{

	CWParseMessageElementStart();
	__attribute__ ((unused)) int RadioID;			/* TODO: support multiple radios */
	unsigned char sup_cap[6];

	RadioID = CWProtocolRetrieve8(msgPtr);
	CWProtocolRetrieve8(msgPtr);

	sup_cap[0] = CWProtocolRetrieve8(msgPtr);
	sup_cap[1] = CWProtocolRetrieve8(msgPtr);
	sup_cap[2] = CWProtocolRetrieve8(msgPtr);
	sup_cap[3] = CWProtocolRetrieve8(msgPtr);
	sup_cap[4] = CWProtocolRetrieve8(msgPtr);
	sup_cap[5] = CWProtocolRetrieve8(msgPtr);

	memcpy(valPtr, sup_cap, 6);

	CWParseMessageElementEnd();
}

CWBool CWParseWTPName(CWProtocolMessage * msgPtr, int len, char **valPtr)
{
	CWParseMessageElementStart();

	*valPtr = CWProtocolRetrieveStr(NULL, msgPtr, len);
	if (valPtr == NULL)
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
//  CWDebugLog("WTP Name:%s", *valPtr);

	CWParseMessageElementEnd();
}

CWBool CWParseWTPRebootStatistics(CWProtocolMessage * msgPtr, int len, WTPRebootStatisticsInfo * valPtr)
{
	CWParseMessageElementStart();

	valPtr->rebootCount = CWProtocolRetrieve16(msgPtr);
	valPtr->ACInitiatedCount = CWProtocolRetrieve16(msgPtr);
	valPtr->linkFailurerCount = CWProtocolRetrieve16(msgPtr);
	valPtr->SWFailureCount = CWProtocolRetrieve16(msgPtr);
	valPtr->HWFailuireCount = CWProtocolRetrieve16(msgPtr);
	valPtr->otherFailureCount = CWProtocolRetrieve16(msgPtr);
	valPtr->unknownFailureCount = CWProtocolRetrieve16(msgPtr);
	valPtr->lastFailureType = CWProtocolRetrieve8(msgPtr);

//  CWDebugLog("");
//  CWDebugLog("WTPRebootStat(1): %d - %d - %d", valPtr->rebootCount, valPtr->ACInitiatedCount, valPtr->linkFailurerCount);
//  CWDebugLog("WTPRebootStat(2): %d - %d - %d", valPtr->SWFailureCount, valPtr->HWFailuireCount, valPtr->otherFailureCount);
//  CWDebugLog("WTPRebootStat(3): %d - %d", valPtr->unknownFailureCount, valPtr->lastFailureType);

	CWParseMessageElementEnd();
}

CWBool CWParseWTPRadioStatistics(CWProtocolMessage * msgPtr, int len, WTPRadioStatisticsValues * valPtr)
{
	CWParseMessageElementStart();

	valPtr->radioID = CWProtocolRetrieve8(msgPtr);
	valPtr->WTPRadioStatistics.lastFailureType = CWProtocolRetrieve8(msgPtr);
	valPtr->WTPRadioStatistics.resetCount = CWProtocolRetrieve16(msgPtr);
	valPtr->WTPRadioStatistics.SWFailureCount = CWProtocolRetrieve16(msgPtr);
	valPtr->WTPRadioStatistics.HWFailuireCount = CWProtocolRetrieve16(msgPtr);
	valPtr->WTPRadioStatistics.otherFailureCount = CWProtocolRetrieve16(msgPtr);
	valPtr->WTPRadioStatistics.unknownFailureCount = CWProtocolRetrieve16(msgPtr);
	valPtr->WTPRadioStatistics.configUpdateCount = CWProtocolRetrieve16(msgPtr);
	valPtr->WTPRadioStatistics.channelChangeCount = CWProtocolRetrieve16(msgPtr);
	valPtr->WTPRadioStatistics.bandChangeCount = CWProtocolRetrieve16(msgPtr);
	valPtr->WTPRadioStatistics.currentNoiseFloor = CWProtocolRetrieve16(msgPtr);

//  CWDebugLog("");
//  CWDebugLog("WTPRadioStatistics of radio: \"%d\"", valPtr->radioID);
//  CWDebugLog("WTPRadioStatistics(1): %d - %d - %d", valPtr->WTPRadioStatistics.lastFailureType, valPtr->WTPRadioStatistics.resetCount, valPtr->WTPRadioStatistics.SWFailureCount);
//  CWDebugLog("WTPRadioStatistics(2): %d - %d - %d", valPtr->WTPRadioStatistics.HWFailuireCount, valPtr->WTPRadioStatistics.otherFailureCount, valPtr->WTPRadioStatistics.unknownFailureCount);
//  CWDebugLog("WTPRadioStatistics(3): %d - %d - %d - %d", valPtr->WTPRadioStatistics.configUpdateCount, valPtr->WTPRadioStatistics.channelChangeCount, valPtr->WTPRadioStatistics.bandChangeCount, valPtr->WTPRadioStatistics.currentNoiseFloor);

	CWParseMessageElementEnd();
}

CWBool CWParseWTPOperationalStatistics(CWProtocolMessage * msgPtr, int len, WTPOperationalStatisticsValues * valPtr)
{
	CWParseMessageElementStart();

	valPtr->radioID = CWProtocolRetrieve8(msgPtr);
	valPtr->TxQueueLevel = CWProtocolRetrieve8(msgPtr);
	valPtr->wirelessLinkFramesPerSec = CWProtocolRetrieve16(msgPtr);

//  CWDebugLog("WTPOperationalStatistics of radio \"%d\": %d - %d", valPtr->radioID, valPtr->TxQueueLevel, valPtr->wirelessLinkFramesPerSec);

	CWParseMessageElementEnd();
}

CWBool CWParseMsgElemDecryptErrorReport(CWProtocolMessage * msgPtr, int len, CWDecryptErrorReportValues * valPtr)
{
	CWParseMessageElementStart();

	valPtr->ID = CWProtocolRetrieve8(msgPtr);
	valPtr->numEntries = CWProtocolRetrieve8(msgPtr);

	valPtr->length = CWProtocolRetrieve8(msgPtr);

	valPtr->decryptErrorMACAddressList = NULL;
	if ((valPtr->numEntries) > 0) {
		if (!(valPtr->decryptErrorMACAddressList = ralloc_array(NULL, CWMACAddress, valPtr->numEntries)))
			return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

		int size = sizeof(CWMACAddress) * (valPtr->numEntries);
		CW_COPY_MEMORY(valPtr->decryptErrorMACAddressList, CWProtocolRetrieveRawBytes(NULL, msgPtr, size), size);
		//valPtr->decryptErrorMACAddressList =(unsigned char*) CWProtocolRetrieveRawBytes(NULL, msgPtr, sizeof(CWMACAddress)*(valPtr->numEntries));
		//CW_COPY_MEMORY(&((valPtr->ACIPv6List)[i]), CWProtocolRetrieveRawBytes(NULL, msgPtr, 16), 16);
		/*
		   int j;
		   for (j=0;j<(sizeof(CWMACAddress)*(valPtr->numEntries)); j++)
		   CWDebugLog("##(%d/6) = %d", j%6, (valPtr->decryptErrorMACAddressList)[j/6][j%6]);
		 */
	}
//  CWDebugLog("");
//  CWDebugLog("Radio Decrypt Error Report of radio \"%d\": %d", valPtr->ID, valPtr->numEntries);

	CWParseMessageElementEnd();
}

/*
CWBool CWParseWTPRadioInfo(CWPr<otocolMessage *msgPtr, int len, CWRadiosInformation *valPtr, int radioIndex) {
    CWParseMessageElementStart();

    (valPtr->radios)[radioIndex].ID = CWProtocolRetrieve8(msgPtr);
    (valPtr->radios)[radioIndex].type = CWProtocolRetrieve32(msgPtr);

    CWDebugLog("WTP Radio info: %d %d ", (valPtr->radios)[radioIndex].ID, (valPtr->radios)[radioIndex].type);

    CWParseMessageElementEnd();
}
*/
