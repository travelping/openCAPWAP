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

static CWBool CWAssembleJoinResponse(CWTransportMessage *tm, int PMTU, int seqNum, CWList msgElemList);
static CWBool CWParseJoinRequestMessage(CWProtocolMessage *pm, int *seqNumPtr,
					CWProtocolJoinRequestValues * valuesPtr);
static CWBool CWSaveJoinRequestMessage(CWProtocolJoinRequestValues * joinRequest, CWWTPProtocolManager * WTPProtocolManager);

CWBool ACEnterJoin(int WTPIndex, CWProtocolMessage *pm)
{
	int seqNum = 0;
	CWProtocolJoinRequestValues joinRequest;
	CWList msgElemList = NULL;

	assert(pm);

	CWLog("\n");
	CWLog("######### Join State #########");

	if (!(CWParseJoinRequestMessage(pm, &seqNum, &joinRequest))) {
		/* note: we can kill our thread in case of out-of-memory
		 * error to free some space.
		 * we can see this just calling CWErrorGetLastErrorCode()
		 */
		return CW_FALSE;
	}

	// cancel waitJoin timer
	if (!CWTimerCancel(&(gWTPs[WTPIndex].currentTimer))) {
		return CW_FALSE;
	}

	CWBool ACIpv4List = CW_FALSE;
	CWBool ACIpv6List = CW_FALSE;
	CWBool resultCode = CW_TRUE;
	int resultCodeValue = CW_PROTOCOL_SUCCESS;
	/* CWBool sessionID = CW_FALSE; */

	if (!(CWSaveJoinRequestMessage(&joinRequest, &(gWTPs[WTPIndex].WTPProtocolManager)))) {

		resultCodeValue = CW_PROTOCOL_FAILURE_RES_DEPLETION;
	}

	CWMsgElemData *auxData;
	if (ACIpv4List) {
		if (!(auxData = ralloc(NULL, CWMsgElemData)))
			return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

		auxData->type = CW_MSG_ELEMENT_AC_IPV4_LIST_CW_TYPE;
		auxData->value = 0;
		CWAddElementToList(NULL, &msgElemList, auxData);
	}
	if (ACIpv6List) {
		if (!(auxData = ralloc(NULL, CWMsgElemData)))
			return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

		auxData->type = CW_MSG_ELEMENT_AC_IPV6_LIST_CW_TYPE;
		auxData->value = 0;
		CWAddElementToList(NULL, &msgElemList, auxData);
	}
	if (resultCode) {
		if (!(auxData = ralloc(NULL, CWMsgElemData)))
			return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

		auxData->type = CW_MSG_ELEMENT_RESULT_CODE_CW_TYPE;
		auxData->value = resultCodeValue;
		CWAddElementToList(NULL, &msgElemList, auxData);
	}
	/*
	   if(sessionID){
	   if (!(auxData = ralloc(NULL, CWMsgElemData)))
	   	return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
	   auxData->type =  CW_MSG_ELEMENT_SESSION_ID_CW_TYPE;
	   auxData->value = CWRandomIntInRange(0, INT_MAX);
	   CWAddElementToList(NULL, &msgElemList,auxData);
	   }
	 */

	/* random session ID */
	if (!(CWAssembleJoinResponse(&gWTPs[WTPIndex].messages, gWTPs[WTPIndex].pathMTU, seqNum, msgElemList))) {
		CWDeleteList(&msgElemList, CWProtocolDestroyMsgElemData);
		return CW_FALSE;
	}

	CWDeleteList(&msgElemList, CWProtocolDestroyMsgElemData);

	if (!CWACSendFragments(WTPIndex)) {
		return CW_FALSE;
	}

	gWTPs[WTPIndex].currentState = CW_ENTER_CONFIGURE;

	return CW_TRUE;
}

/**
 * Assemble Join Response.
 *
 * Result code is not included because it's already
 * in msgElemList. Control IPv6 to be added.
 */
CWBool CWAssembleJoinResponse(CWTransportMessage *tm, int PMTU, int seqNum, CWList msgElemList)
{
	CWProtocolMessage msg;
	CWListElement *current;

	assert(tm);
	assert(msgElemList);

	CWDebugLog("Assembling Join Response...");

	if (!CWInitMessage(NULL, &msg, CW_MSG_TYPE_VALUE_JOIN_RESPONSE, seqNum) ||
	    !CWAssembleMsgElemACDescriptor(NULL, &msg) ||
	    !CWAssembleMsgElemACName(NULL, &msg) ||
	    !CWAssembleMsgElemCWControlIPv4Addresses(NULL, &msg) ||
	    !CWAssembleMsgElemACWTPRadioInformation(NULL, &msg))
		goto cw_assemble_error;

	CWListForeach(msgElemList, current) {
		switch (((CWMsgElemData *) (current->data))->type) {

		case CW_MSG_ELEMENT_AC_IPV4_LIST_CW_TYPE:
			if (!(CWAssembleMsgElemACIPv4List(NULL, &msg)))
				goto cw_assemble_error;
			break;
		case CW_MSG_ELEMENT_AC_IPV6_LIST_CW_TYPE:
			if (!(CWAssembleMsgElemACIPv6List(NULL, &msg)))
				goto cw_assemble_error;
			break;
		case CW_MSG_ELEMENT_RESULT_CODE_CW_TYPE:
			if (!(CWAssembleMsgElemResultCode(NULL, &msg,
							  ((CWMsgElemData *) current->data)->value)))
				goto cw_assemble_error;
			break;
			/*
			   case CW_MSG_ELEMENT_SESSION_ID_CW_TYPE:
			   if (!(CWAssembleMsgElemSessionID(NULL, &msg, ((CWMsgElemData *) current->data)->value)))
			   goto cw_assemble_error;
			   break;
			 */
		default:
			CWReleaseMessage(&msg);
			return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
					    "Unrecognized Message Element for Join Response Message");
		}
	}
	CWFinalizeMessage(&msg);

	if (!CWAssembleMessage(tm, PMTU, &msg))
		goto cw_assemble_error;

	CWDebugLog("Join Response Assembled");
	return CW_TRUE;

 cw_assemble_error:
	CWReleaseMessage(&msg);
        return CW_FALSE;
}

/*
 * Parses Join Request.
 */
CWBool CWParseJoinRequestMessage(CWProtocolMessage *pm, int *seqNumPtr,
				 CWProtocolJoinRequestValues * valuesPtr)
{

	CWControlHeaderValues controlVal;
	int offsetTillMessages;
	unsigned char RadioInfoABGN;

	assert(pm);
	assert(seqNumPtr);
	assert(valuesPtr);

	CWDebugLog("Parse Join Request");

	if (!(CWParseControlHeader(pm, &controlVal)))
		/* will be handled by the caller */
		return CW_FALSE;

	/* different type */
	if (controlVal.messageTypeValue != CW_MSG_TYPE_VALUE_JOIN_REQUEST)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Message is not Join Request as Expected");

	*seqNumPtr = controlVal.seqNum;
	/* skip timestamp */
	controlVal.msgElemsLen -= CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;
	offsetTillMessages = pm->pos;

	/* parse message elements */
	while ((pm->pos - offsetTillMessages) < controlVal.msgElemsLen) {

		unsigned short int elemType = 0;	/* = CWProtocolRetrieve32(&pm); */
		unsigned short int elemLen = 0;	/* = CWProtocolRetrieve16(&pm); */

		CWParseFormatMsgElem(pm, &elemType, &elemLen);

		/* CWDebugLog("Parsing Message Element: %u, elemLen: %u", elemType, elemLen); */

		switch (elemType) {
		case CW_MSG_ELEMENT_LOCATION_DATA_CW_TYPE:
			if (!(CWParseLocationData(pm, elemLen, &(valuesPtr->location))))
				/* will be handled by the caller */
				return CW_FALSE;
			break;

		case CW_MSG_ELEMENT_WTP_BOARD_DATA_CW_TYPE:
			if (!(CWParseWTPBoardData(pm, elemLen, &(valuesPtr->WTPBoardData))))
				/* will be handled by the caller */
				return CW_FALSE;
			break;

		case CW_MSG_ELEMENT_SESSION_ID_CW_TYPE:
			valuesPtr->sessionID = CWParseSessionID(pm, elemLen);
			break;

		case CW_MSG_ELEMENT_WTP_DESCRIPTOR_CW_TYPE:
			if (!(CWParseWTPDescriptor(pm, elemLen, &(valuesPtr->WTPDescriptor))))
				/* will be handled by the caller */
				return CW_FALSE;
			break;

		case CW_MSG_ELEMENT_WTP_IPV4_ADDRESS_CW_TYPE:
			if (!(CWParseWTPIPv4Address(pm, elemLen, valuesPtr)))
				/* will be handled by the caller */
				return CW_FALSE;
			break;

		case CW_MSG_ELEMENT_WTP_NAME_CW_TYPE:
			if (!(CWParseWTPName(pm, elemLen, &(valuesPtr->name))))
				/* will be handled by the caller */
				return CW_FALSE;
			break;

		case CW_MSG_ELEMENT_WTP_FRAME_TUNNEL_MODE_CW_TYPE:
			if (!(CWParseWTPFrameTunnelMode(pm, elemLen, &(valuesPtr->frameTunnelMode))))
				/* will be handled by the caller */
				return CW_FALSE;
			break;

		case CW_MSG_ELEMENT_WTP_MAC_TYPE_CW_TYPE:
			if (!(CWParseWTPMACType(pm, elemLen, &(valuesPtr->MACType))))
				/* will be handled by the caller */
				return CW_FALSE;
			break;

		case CW_MSG_ELEMENT_IEEE80211_WTP_RADIO_INFORMATION_CW_TYPE:
			if (!(CWParseWTPRadioInformation(pm, elemLen, &RadioInfoABGN)))
				return CW_FALSE;
			break;

		default:
			CWLog("Unrecognized Message Element(%d) in Discovery response", elemType);
			CWParseSkipElement(pm, elemLen);
			break;
		}
		/*CWDebugLog("bytes: %d/%d", (pm.offset-offsetTillMessages), controlVal.msgElemsLen); */
	}

	return CWParseTransportMessageEnd(pm);
}

CWBool CWSaveJoinRequestMessage(CWProtocolJoinRequestValues * joinRequest, CWWTPProtocolManager * WTPProtocolManager)
{

	CWDebugLog("Saving Join Request...");

	if (joinRequest == NULL || WTPProtocolManager == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if ((joinRequest->location) != NULL) {

		CW_FREE_OBJECT(WTPProtocolManager->locationData);
		WTPProtocolManager->locationData = joinRequest->location;
	} else
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if ((joinRequest->name) != NULL) {

		CW_FREE_OBJECT(WTPProtocolManager->name);
		WTPProtocolManager->name = joinRequest->name;
	} else
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CW_FREE_OBJECT((WTPProtocolManager->WTPBoardData).vendorInfos);
	WTPProtocolManager->WTPBoardData = joinRequest->WTPBoardData;

	WTPProtocolManager->sessionID = joinRequest->sessionID;
	WTPProtocolManager->ipv4Address = joinRequest->addr;

	WTPProtocolManager->descriptor = joinRequest->WTPDescriptor;
	WTPProtocolManager->radiosInfo.radioCount = (joinRequest->WTPDescriptor).radiosInUse;
	CW_FREE_OBJECT(WTPProtocolManager->radiosInfo.radiosInfo);

	if (!(WTPProtocolManager->radiosInfo.radiosInfo =
	      ralloc_array(NULL, CWWTPRadioInfoValues, WTPProtocolManager->radiosInfo.radioCount)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	int i;

	for (i = 0; i < WTPProtocolManager->radiosInfo.radioCount; i++) {

		WTPProtocolManager->radiosInfo.radiosInfo[i].radioID = i;
		/*WTPProtocolManager->radiosInfo.radiosInfo[i].stationCount = 0; */
		/* default value for CAPWAP */
		WTPProtocolManager->radiosInfo.radiosInfo[i].adminState = ENABLED;
		WTPProtocolManager->radiosInfo.radiosInfo[i].adminCause = AD_NORMAL;
		WTPProtocolManager->radiosInfo.radiosInfo[i].operationalState = DISABLED;
		WTPProtocolManager->radiosInfo.radiosInfo[i].operationalCause = OP_NORMAL;
		WTPProtocolManager->radiosInfo.radiosInfo[i].TxQueueLevel = 0;
		WTPProtocolManager->radiosInfo.radiosInfo[i].wirelessLinkFramesPerSec = 0;
	}
	CWDebugLog("Join Request Saved");
	return CW_TRUE;
}
