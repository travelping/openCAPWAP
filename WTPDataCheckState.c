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

static CWBool CWAssembleChangeStateEventRequest(CWTransportMessage *tm, int PMTU, int seqNum, CWList msgElemList);
static CWBool CWParseChangeStateEventResponseMessage(CWProtocolMessage *, int seqNum, void *values);
static CWBool CWSaveChangeStateEventResponseMessage(void *changeStateEventResp);

CWStateTransition CWWTPEnterDataCheck()
{
	int seqNum;

	CWLog("\n");
	CWLog("######### Data Check State #########");

	CWLog("\n");
	CWLog("#________ Change State Event (Data Check) ________#");

	/* Send Change State Event Request */
	seqNum = CWGetSeqNum();

	if (!CWErr(CWStartHeartbeatTimer())) {
		return CW_ENTER_RESET;
	}

	if (!CWErr(CWWTPSendAcknowledgedPacket(seqNum,
					       NULL,
					       CWAssembleChangeStateEventRequest,
					       CWParseChangeStateEventResponseMessage,
					       CWSaveChangeStateEventResponseMessage, NULL))) {
		return CW_ENTER_RESET;
	}

	if (!CWErr(CWStopHeartbeatTimer())) {

		return CW_ENTER_RESET;
	}

	return CW_ENTER_RUN;
}

CWBool CWAssembleChangeStateEventRequest(CWTransportMessage *tm, int PMTU, int seqNum, CWList msgElemList)
{
	CWProtocolMessage msg;
	int resultCode = CW_PROTOCOL_SUCCESS;

	assert(tm != NULL);

	CWLog("Assembling Change State Event Request...");

	/* Assemble Message Elements */
	if (!CWInitMessage(NULL, &msg, CW_MSG_TYPE_VALUE_CHANGE_STATE_EVENT_REQUEST, seqNum) ||
	    !CWAssembleMsgElemRadioOperationalState(NULL, -1, &msg) ||
	    !CWAssembleMsgElemResultCode(NULL, &msg, resultCode))
		goto cw_assemble_error;
	CWFinalizeMessage(&msg);

	if (!CWAssembleMessage(tm, PMTU, &msg))
		goto cw_assemble_error;

	CWLog("Change State Event Request Assembled");
	return CW_TRUE;

 cw_assemble_error:
	CWReleaseMessage(&msg);
        return CW_FALSE;
}

CWBool CWParseChangeStateEventResponseMessage(CWProtocolMessage *pm, int seqNum, void *values)
{
	CWControlHeaderValues controlVal;

	assert(pm != NULL);

	CWLog("Parsing Change State Event Response...");

	/* error will be handled by the caller */
	if (!(CWParseControlHeader(pm, &controlVal)))
		return CW_FALSE;

	if (controlVal.messageTypeValue != CW_MSG_TYPE_VALUE_CHANGE_STATE_EVENT_RESPONSE)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Message is not Change State Event Response as Expected");

	if (controlVal.seqNum != seqNum)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Different Sequence Number");

	/* skip timestamp */
	controlVal.msgElemsLen -= CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;

	if (controlVal.msgElemsLen != 0)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
				    "Change State Event Response must carry no message elements");

	CWParseTransportMessageEnd(pm);

	CWLog("Change State Event Response Parsed");
	return CW_TRUE;
}

CWBool CWSaveChangeStateEventResponseMessage(void *changeStateEventResp)
{
	CWDebugLog("Saving Change State Event Response...");
	CWDebugLog("Change State Event Response Saved");
	return CW_TRUE;
}
