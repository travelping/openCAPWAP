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

#include "CWWTP.h"

/*_______________________________________________________________*/
/*  *******************___CHECK FUNCTIONS___*******************  */

CWBool CWWTPCheckForBindingFrame()
{
	//
	CWLockSafeList(gFrameList);

	while (CWGetCountElementFromSafeList(gFrameList) > 0) {
		CWBindingDataListElement *dataFirstElem = CWRemoveHeadElementFromSafeList(gFrameList, NULL);
		if (dataFirstElem) {
			int k;
			CWTransportMessage tm;

			if (!CWAssembleDataMessage(&tm, gWTPPathMTU, 1, BINDING_IEEE_802_11, CW_FALSE, CW_TRUE, NULL,
						   dataFirstElem->bindingValues, &dataFirstElem->frame)) {
				CWReleaseTransportMessage(&tm);
				CWReleaseMessage(&dataFirstElem->frame);
				CW_FREE_OBJECT(dataFirstElem->bindingValues);
				CW_FREE_OBJECT(dataFirstElem);
				continue;
			}

			for (k = 0; k < tm.count; k++) {
				if (!CWNetworkSendUnsafeConnected(gWTPDataSocket, tm.parts[k].data, tm.parts[k].pos)) {
					CWDebugLog("Failure sending Request");
					break;
				}
				CWDebugLog("Sending binding Request to AC");
			}

			CWReleaseTransportMessage(&tm);
			CW_FREE_OBJECT(dataFirstElem->bindingValues);
			CW_FREE_OBJECT(dataFirstElem);
		}
	}

	CWUnlockSafeList(gFrameList);

	return CW_TRUE;
}

CWBool CWWTPCheckForWTPEventRequest()
{
	CWLog("\n");
	CWLog("#________ WTP Event Request Message (Run) ________#");

	/* Send WTP Event Request */
	CWList msgElemList = NULL;
	CWTransportMessage tm;
	int seqNum;
	int *pendingReqIndex;

	seqNum = CWGetSeqNum();

	if (!(pendingReqIndex = ralloc(NULL, int)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	if (!(msgElemList = ralloc(NULL, CWListElement)) ||
	    !(msgElemList->data = ralloc(NULL, CWMsgElemData))) {
		ralloc_free(pendingReqIndex);
		ralloc_free(msgElemList);
	    	return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
	}
	msgElemList->next = NULL;
	//Change type and value to change the msg elem to send
	((CWMsgElemData *) (msgElemList->data))->type = CW_MSG_ELEMENT_CW_DECRYPT_ER_REPORT_CW_TYPE;
	((CWMsgElemData *) (msgElemList->data))->value = 0;

	if (!CWAssembleWTPEventRequest(&tm, gWTPPathMTU, seqNum, msgElemList)) {
		CWReleaseTransportMessage(&tm);
		return CW_FALSE;
	}

	*pendingReqIndex = CWSendPendingRequestMessage(gPendingRequestMsgs, &tm);
	if (*pendingReqIndex < 0) {
		CWDebugLog("Failure sending WTP Event Request");
		CWReleaseTransportMessage(&tm);
		CWDeleteList(&msgElemList, CWProtocolDestroyMsgElemData);
		return CW_FALSE;
	}
	CWUpdatePendingMsgBox(&(gPendingRequestMsgs[*pendingReqIndex]),
			      CW_MSG_TYPE_VALUE_WTP_EVENT_RESPONSE,
			      seqNum,
			      gCWRetransmitTimer,
			      pendingReqIndex, CWWTPRetransmitTimerExpiredHandler, 0, &tm);

	CWDeleteList(&msgElemList, CWProtocolDestroyMsgElemData);

	return CW_TRUE;
}

void CWWTPRetransmitTimerExpiredHandler(CWTimerArg hdl_arg)
{
	int index = *((int *)hdl_arg);

	CWDebugLog("Retransmit Timer Expired for Thread: %08x", (unsigned int)CWThreadSelf());

	if (gPendingRequestMsgs[index].retransmission == gCWMaxRetransmit) {
		CWDebugLog("Peer is Dead");
		//_CWCloseThread(*iPtr);
		return;
	}

	CWDebugLog("Retransmission Count increases to %d", gPendingRequestMsgs[index].retransmission);

	int i;
	for (i = 0; i < gPendingRequestMsgs[index].msg.count; i++) {
#ifdef CW_NO_DTLS
		if (!CWNetworkSendUnsafeConnected(gWTPSocket,
						  gPendingRequestMsgs[index].msg.parts[i].data,
						  gPendingRequestMsgs[index].msg.parts[i].pos)) {
#else
		if (!CWSecuritySend(gWTPSession,
				    gPendingRequestMsgs[index].msg.parts[i].data,
				    gPendingRequestMsgs[index].msg.parts[i].pos)) {
#endif
			CWDebugLog("Failure sending Request");
			CWReleaseTransportMessage(&gPendingRequestMsgs[index].msg);
			CW_FREE_OBJECT(hdl_arg);
			return;
		}
	}
	gPendingRequestMsgs[index].retransmission++;
	gPendingRequestMsgs[index].timer = timer_add(gPendingRequestMsgs[index].timer_sec,
						     0,
						     gPendingRequestMsgs[index].timer_hdl,
						     gPendingRequestMsgs[index].timer_arg);
	CW_FREE_OBJECT(hdl_arg);
	return;
}
