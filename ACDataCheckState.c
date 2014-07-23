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

#include "CWAC.h"

static CWBool CWParseChangeStateEventRequestMessage(CWProtocolMessage *pm, int *seqNumPtr,
						    CWProtocolChangeStateEventRequestValues * valuesPtr);

CWBool ACEnterDataCheck(int WTPIndex, CWProtocolMessage *pm)
{

	/*CWProtocolMessage *messages = NULL; */
	int seqNum = 0;
	CWProtocolChangeStateEventRequestValues *changeStateEvent;

	CWLog("\n");
	CWDebugLog("######### Status Event #########");

	/* Destroy ChangeStatePending timer */
	if (!CWErr(CWTimerCancel(&(gWTPs[WTPIndex].currentTimer)))) {

		CWCloseThread();
	}

	if (!(changeStateEvent = ralloc(NULL, CWProtocolChangeStateEventRequestValues)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	if (!(CWParseChangeStateEventRequestMessage(pm, &seqNum, changeStateEvent))) {
		/* note: we can kill our thread in case of out-of-memory
		 * error to free some space.
		 * we can see this just calling CWErrorGetLastErrorCode()
		 */
		return CW_FALSE;
	}

	CWLog("Change State Event Received");

	if (!CWSaveChangeStateEventRequestMessage(changeStateEvent, &(gWTPs[WTPIndex].WTPProtocolManager)))
		return CW_FALSE;

	if (!CWAssembleChangeStateEventResponse(&gWTPs[WTPIndex].messages, gWTPs[WTPIndex].pathMTU, seqNum))
		return CW_FALSE;

	if (!CWACSendFragments(WTPIndex)) {

		return CW_FALSE;
	}

	/* Start NeighbourDeadInterval timer */
	if (!CWErr(CWTimerRequest(gCWNeighborDeadInterval,
				  &(gWTPs[WTPIndex].thread),
				  &(gWTPs[WTPIndex].currentTimer), CW_CRITICAL_TIMER_EXPIRED_SIGNAL))) {

		CWCloseThread();
	}

	CWLog("Change State Event Response Sent");

	gWTPs[WTPIndex].currentState = CW_ENTER_RUN;
	gWTPs[WTPIndex].subState = CW_WAITING_REQUEST;

	return CW_TRUE;
}

CWBool CWParseChangeStateEventRequestMessage(CWProtocolMessage *pm, int *seqNumPtr,
					     CWProtocolChangeStateEventRequestValues * valuesPtr)
{

	CWControlHeaderValues controlVal;
	int i;
	int offsetTillMessages;

	assert(pm);
	assert(seqNumPtr);
	assert(valuesPtr);

	CWDebugLog("Parsing Change State Event Request...");

	if (!(CWParseControlHeader(pm, &controlVal)))
		/* will be handled by the caller */
		return CW_FALSE;

	/* different type */
	if (controlVal.messageTypeValue != CW_MSG_TYPE_VALUE_CHANGE_STATE_EVENT_REQUEST)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Message is not Change State Event Request");

	*seqNumPtr = controlVal.seqNum;
	/* skip timestamp */
	controlVal.msgElemsLen -= CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;

	offsetTillMessages = pm->pos;
	valuesPtr->radioOperationalInfo.radiosCount = 0;

	/* parse message elements */
	while ((pm->pos - offsetTillMessages) < controlVal.msgElemsLen) {
		unsigned short int elemType = 0;	/* = CWProtocolRetrieve32(pm); */
		unsigned short int elemLen = 0;	/* = CWProtocolRetrieve16(pm); */

		CWParseFormatMsgElem(pm, &elemType, &elemLen);

		/*CWDebugLog("Parsing Message Element: %u, elemLen: %u", elemType, elemLen); */

		switch (elemType) {
		case CW_MSG_ELEMENT_RADIO_OPERAT_STATE_CW_TYPE:
			/* just count how many radios we have,
			 * so we can allocate the array
			 */
			valuesPtr->radioOperationalInfo.radiosCount++;
			CWParseSkipElement(pm, elemLen);
			break;

		case CW_MSG_ELEMENT_RESULT_CODE_CW_TYPE:
			if (!(CWParseResultCode(pm, elemLen, &(valuesPtr->resultCode))))
				return CW_FALSE;
			break;

		default:
			CWLog("Unrecognized Message Element(%d) in Discovery response", elemType);
			CWParseSkipElement(pm, elemLen);
			break;
		}
	}

	CWParseTransportMessageEnd(pm);

	if (!(valuesPtr->radioOperationalInfo.radios =
	      ralloc_array(NULL, CWRadioOperationalInfoValues, valuesPtr->radioOperationalInfo.radiosCount)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	pm->pos = offsetTillMessages;
	i = 0;

	while (pm->pos - offsetTillMessages < controlVal.msgElemsLen) {
		unsigned short int type = 0;	/* = CWProtocolRetrieve32(pm); */
		unsigned short int len = 0;	/* = CWProtocolRetrieve16(pm); */

		CWParseFormatMsgElem(pm, &type, &len);

		switch (type) {
		case CW_MSG_ELEMENT_RADIO_OPERAT_STATE_CW_TYPE:
			if (!
			    (CWParseWTPRadioOperationalState
			     (pm, len, &(valuesPtr->radioOperationalInfo.radios[i]))))
				/* will be handled by the caller */
				return CW_FALSE;
			i++;
			break;
		default:
			CWParseSkipElement(pm, len);
			break;
		}
	}
	CWDebugLog("Change State Event Request Parsed");

	return CW_TRUE;
}

CWBool CWAssembleChangeStateEventResponse(CWTransportMessage *tm, int PMTU, int seqNum)
{
	CWProtocolMessage msg;

	assert(tm);

	CWDebugLog("Assembling Change State Event Response...");
	if (!CWInitMessage(NULL, &msg, CW_MSG_TYPE_VALUE_CHANGE_STATE_EVENT_RESPONSE, seqNum))
		goto cw_assemble_error;
	CWFinalizeMessage(&msg);

	if (!CWAssembleMessage(tm, PMTU, &msg))
		goto cw_assemble_error;

	CWDebugLog("Change State Event Response Assembled");
	return CW_TRUE;

 cw_assemble_error:
	CWReleaseMessage(&msg);
        return CW_FALSE;
}
