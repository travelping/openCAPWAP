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

/*_________________________________________________________*/
/*  *******************___FUNCTIONS___*******************  */

/* send Discovery Response to the host at the specified address */
CWBool CWAssembleDiscoveryResponse(CWTransportMessage *tm, int seqNum)
{
	CWProtocolMessage msg;

	assert(tm);

	CWLog("Send Discovery Response");

	/* Assemble Message Elements */
	if (!CWInitMessage(NULL, &msg, CW_MSG_TYPE_VALUE_DISCOVERY_RESPONSE, seqNum) ||
	    !CWAssembleMsgElemACDescriptor(NULL, &msg) ||
	    !CWAssembleMsgElemACName(NULL, &msg) ||
	    !CWAssembleMsgElemCWControlIPv4Addresses(NULL, &msg) ||
	    /*(CWACSupportIPv6() && !CWAssembleMsgElemCWControlIPv6Addresses(NULL, &msg)) */
	    !CWAssembleMsgElemACWTPRadioInformation(NULL, &msg))
		goto cw_assemble_error;
	CWFinalizeMessage(&msg);

	if (!CWAssembleMessage(tm, 0, &msg))
		goto cw_assemble_error;

	return CW_TRUE;

 cw_assemble_error:
	CWReleaseMessage(&msg);
        return CW_FALSE;
}

CWBool CWParseDiscoveryRequestMessage(unsigned char *msg, int len,
				      int *seqNumPtr, CWDiscoveryRequestValues * valuesPtr)
{

	CWControlHeaderValues controlVal;
	CWProtocolTransportHeaderValues transportVal;
	unsigned char RadioInfoABGN;
	int offsetTillMessages;

	CWProtocolMessage pm;

	assert(msg != NULL);
	assert(seqNumPtr != NULL);
	assert(valuesPtr != NULL);

	CWDebugLog("Parse Discovery Request");

	if (!(CWParseTransportHeader(&pm, &transportVal, NULL)))
		/* will be handled by the caller */
		return CW_FALSE;
	if (!(CWParseControlHeader(&pm, &controlVal)))
		/* will be handled by the caller */
		return CW_FALSE;

	/* different type */

	if (controlVal.messageTypeValue != CW_MSG_TYPE_VALUE_DISCOVERY_REQUEST)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Message is not Discovery Request as Expected");

	*seqNumPtr = controlVal.seqNum;

	/* skip timestamp */
	controlVal.msgElemsLen -= CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;
	offsetTillMessages = pm.pos;

	/* (*valuesPtr).radios.radiosCount = 0; */

	/* parse message elements */
	while ((pm.pos - offsetTillMessages) < controlVal.msgElemsLen) {

		unsigned short int elemType = 0;	/* = CWProtocolRetrieve32(&pm); */
		unsigned short int elemLen = 0;	/* = CWProtocolRetrieve16(&pm); */

		CWParseFormatMsgElem(&pm, &elemType, &elemLen);

		/* CWDebugLog("Parsing Message Element: %u, elemLen: %u", elemType, elemLen); */

		switch (elemType) {
		case CW_MSG_ELEMENT_DISCOVERY_TYPE_CW_TYPE:
			if (!(CWParseDiscoveryType(&pm, elemLen, valuesPtr)))
				/* will be handled by the caller */
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_WTP_BOARD_DATA_CW_TYPE:
			if (!(CWParseWTPBoardData(&pm, elemLen, &(valuesPtr->WTPBoardData))))
				/* will be handled by the caller */
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_WTP_DESCRIPTOR_CW_TYPE:
			if (!(CWParseWTPDescriptor(&pm, elemLen, &(valuesPtr->WTPDescriptor))))
				/* will be handled by the caller */
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_WTP_FRAME_TUNNEL_MODE_CW_TYPE:
			if (!(CWParseWTPFrameTunnelMode(&pm, elemLen, &(valuesPtr->frameTunnelMode))))
				/* will be handled by the caller */
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_WTP_MAC_TYPE_CW_TYPE:
			if (!(CWParseWTPMACType(&pm, elemLen, &(valuesPtr->MACType))))
				/* will be handled by the caller */
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_IEEE80211_WTP_RADIO_INFORMATION_CW_TYPE:
			if (!(CWParseWTPRadioInformation(&pm, elemLen, &RadioInfoABGN)))
				return CW_FALSE;

			break;
			/*case CW_MSG_ELEMENT_WTP_RADIO_INFO_CW_TYPE:
			   // just count how many radios we have, so we can allocate the array
			   (*valuesPtr).radios.radiosCount++;
			   pm.offset += elemLen;
			   break;
			 */
		default:
			CWLog("Unrecognized Message Element(%d) in Discovery response", elemType);
			CWParseSkipElement(&pm, elemLen);
			break;
		}

		/*CWDebugLog("bytes: %d/%d", (pm.offset-offsetTillMessages), controlVal.msgElemsLen); */
	}

	return CWParseTransportMessageEnd(&pm);
}

void CWDestroyDiscoveryRequestValues(CWDiscoveryRequestValues * valPtr)
{

	int i;

	if (valPtr == NULL)
		return;

	for (i = 0; i < valPtr->WTPDescriptor.vendorInfos.vendorInfosCount; i++)
		CW_FREE_OBJECT(valPtr->WTPDescriptor.vendorInfos.vendorInfos[i].valuePtr);
	CW_FREE_OBJECT(valPtr->WTPDescriptor.vendorInfos.vendorInfos);

	for (i = 0; i < valPtr->WTPBoardData.vendorInfosCount; i++)
		CW_FREE_OBJECT(valPtr->WTPBoardData.vendorInfos[i].valuePtr);
	CW_FREE_OBJECT(valPtr->WTPBoardData.vendorInfos);

	/*CW_FREE_OBJECT((valPtr->radios).radios); */
}
