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

int gCWChangeStatePendingTimer = CW_CHANGE_STATE_INTERVAL_DEFAULT;

static CWBool CWAssembleConfigureResponse(CWTransportMessage *tm, int PMTU, int seqNum);
static CWBool CWParseConfigureRequestMessage(CWProtocolMessage *pm, int *seqNumPtr,
					     CWProtocolConfigureRequestValues * valuesPtr,
					     unsigned char *, unsigned char *, unsigned char *);
static CWBool CWSaveConfigureRequestMessage(CWProtocolConfigureRequestValues * configureRequest,
				     CWWTPProtocolManager * WTPProtocolManager);

CWBool ACEnterConfigure(int WTPIndex, CWProtocolMessage *pm)
{

	/*** tmp Radio Info ***/
	unsigned char tmp_RadioInformationABGN;
	unsigned char tmp_SuppRates[8];
	unsigned char tmp_MultiDomCapa[6];

	int seqNum = 0;
	CWProtocolConfigureRequestValues configureRequest;

	CWLog("\n");
	CWLog("######### Configure State #########");

	if (!(CWParseConfigureRequestMessage(pm, &seqNum, &configureRequest,
					     &tmp_RadioInformationABGN, tmp_SuppRates, tmp_MultiDomCapa))) {
		/* note: we can kill our thread in case of out-of-memory
		 * error to free some space.
		 * we can see this just calling CWErrorGetLastErrorCode()
		 */
		return CW_FALSE;
	}

	CWLog("Configure Request Received");

	if (!(CWSaveConfigureRequestMessage(&configureRequest, &(gWTPs[WTPIndex].WTPProtocolManager)))) {
		return CW_FALSE;
	}

	/* Store Radio Info in gWTPs */
	gWTPs[WTPIndex].RadioInformationABGN = tmp_RadioInformationABGN;
	memcpy(gWTPs[WTPIndex].SuppRates, tmp_SuppRates, 8);
	memcpy(gWTPs[WTPIndex].MultiDomCapa, tmp_MultiDomCapa, 6);

	/* Store Radio Info in gWTPs */

	if (!(CWAssembleConfigureResponse(&gWTPs[WTPIndex].messages, gWTPs[WTPIndex].pathMTU, seqNum))) {
		return CW_FALSE;
	}

	if (!CWACSendFragments(WTPIndex)) {
		return CW_FALSE;
	}

	CWLog("Configure Response Sent");

	/* start Change State Pending timer */
	if (!CWErr(CWTimerRequest(gCWChangeStatePendingTimer,
				  &(gWTPs[WTPIndex].thread),
				  &(gWTPs[WTPIndex].currentTimer), CW_CRITICAL_TIMER_EXPIRED_SIGNAL))) {

		CWCloseThread();
	}

	gWTPs[WTPIndex].currentState = CW_ENTER_DATA_CHECK;
	return CW_TRUE;
}

CWBool CWParseConfigureRequestMessage(CWProtocolMessage *pm,
				      int *seqNumPtr,
				      CWProtocolConfigureRequestValues * valuesPtr,
				      unsigned char *tmp_RadioInformationABGN,
				      unsigned char *tmp_SuppRates,
				      unsigned char *tmp_MultiDomCapa)
{

	CWControlHeaderValues controlVal;
	int i, j;
	int offsetTillMessages;

	assert(pm);
	assert(seqNumPtr);
	assert(valuesPtr);

	CWDebugLog("Parsing Configure Request...");

	if (!(CWParseControlHeader(pm, &controlVal)))
		/* will be handled by the caller */
		return CW_FALSE;

	/* different type */
	if (controlVal.messageTypeValue != CW_MSG_TYPE_VALUE_CONFIGURE_REQUEST)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
				    "Message is not Configure Request (maybe it is Image Data Request)");

	*seqNumPtr = controlVal.seqNum;
	/* skip timestamp */
	controlVal.msgElemsLen -= CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;

	offsetTillMessages = pm->pos;

	/* valuesPtr->WTPRadioInfo.radiosCount=0; */
	valuesPtr->ACinWTP.count = 0;
	valuesPtr->radioAdminInfoCount = 0;

	/* parse message elements */
	while ((pm->pos - offsetTillMessages) < controlVal.msgElemsLen) {

		unsigned short int elemType = 0;	/* = CWProtocolRetrieve32(pm); */
		unsigned short int elemLen = 0;	/* = CWProtocolRetrieve16(pm); */

		CWParseFormatMsgElem(pm, &elemType, &elemLen);

		/*CWDebugLog("Parsing Message Element: %u, elemLen: %u", elemType, elemLen); */

		switch (elemType) {
		case CW_MSG_ELEMENT_AC_NAME_CW_TYPE:
			if (!(CWParseACName(valuesPtr, pm, elemLen, &(valuesPtr->ACName))))
				/* will be handled by the caller */
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_AC_NAME_INDEX_CW_TYPE:
			/* just count how many radios we have,
			 * so we can allocate the array
			 */
			valuesPtr->ACinWTP.count++;
			CWParseSkipElement(pm, elemLen);
			break;
		case CW_MSG_ELEMENT_RADIO_ADMIN_STATE_CW_TYPE:
			/* just count how many radios we have,
			 * so we can allocate the array
			 */
			(valuesPtr->radioAdminInfoCount)++;
			CWParseSkipElement(pm, elemLen);
			break;
		case CW_MSG_ELEMENT_STATISTICS_TIMER_CW_TYPE:
			if (!(CWParseWTPStatisticsTimer(pm, elemLen, &(valuesPtr->StatisticsTimer))))
				/* will be handled by the caller */
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_WTP_REBOOT_STATISTICS_CW_TYPE:
			if (!(valuesPtr->WTPRebootStatistics = ralloc(NULL, WTPRebootStatisticsInfo)))
				return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

			if (!(CWParseWTPRebootStatistics(pm, elemLen, valuesPtr->WTPRebootStatistics)))
				/* will be handled by the caller */
				return CW_FALSE;
			break;

		case CW_MSG_ELEMENT_IEEE80211_WTP_RADIO_INFORMATION_CW_TYPE:
			if (!(CWParseWTPRadioInformation(pm, elemLen, tmp_RadioInformationABGN)))
				return CW_FALSE;
			break;

		case CW_MSG_ELEMENT_IEEE80211_MULTI_DOMAIN_CAPABILITY_CW_TYPE:
			if (!(CWParseWTPMultiDomainCapability(pm, elemLen, tmp_MultiDomCapa)))
				return CW_FALSE;
			break;

		case CW_MSG_ELEMENT_IEEE80211_SUPPORTED_RATES_CW_TYPE:
			if (!(CWParseWTPSupportedRates(pm, elemLen, tmp_SuppRates)))
				return CW_FALSE;
			break;

		default:
			CWLog("Unrecognized Message Element(%d) in Discovery response", elemType);
			CWParseSkipElement(pm, elemLen);
			break;
		}
	}

	CWParseTransportMessageEnd(pm);

	/* actually read each radio info */
	if (!(valuesPtr->ACinWTP.ACNameIndex = ralloc_array(NULL, CWACNameWithIndexValues, valuesPtr->ACinWTP.count)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	if (!(valuesPtr->radioAdminInfo = ralloc_array(NULL, CWRadioAdminInfoValues, valuesPtr->radioAdminInfoCount)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	i = 0;
	j = 0;

	pm->pos = offsetTillMessages;
	while (pm->pos - offsetTillMessages < controlVal.msgElemsLen) {
		unsigned short int type = 0;
		unsigned short int len = 0;

		CWParseFormatMsgElem(pm, &type, &len);

		switch (type) {
		case CW_MSG_ELEMENT_AC_NAME_INDEX_CW_TYPE:
			if (!(CWParseACNameWithIndex(pm, len, &(valuesPtr->ACinWTP.ACNameIndex[i]))))
				/* will be handled by the caller */
				return CW_FALSE;
			i++;
			break;
		case CW_MSG_ELEMENT_RADIO_ADMIN_STATE_CW_TYPE:
			if (!(CWParseWTPRadioAdminState(pm, len, &(valuesPtr->radioAdminInfo[j]))))
				/* will be handled by the caller */
				return CW_FALSE;
			j++;
			break;
		default:
			CWParseSkipElement(pm, len);
			break;
		}
	}
	CWDebugLog("Configure Request Parsed");
	return CW_TRUE;
}

CWBool CWAssembleConfigureResponse(CWTransportMessage *tm, int PMTU, int seqNum)
{
	CWProtocolMessage msg;

	assert(tm);

	CWDebugLog("Assembling Configure Response...");

	/* Assemble Message Elements */
	if (!CWInitMessage(NULL, &msg, CW_MSG_TYPE_VALUE_CONFIGURE_RESPONSE, seqNum) ||
	    !CWAssembleMsgElemACIPv4List(NULL, &msg) ||
	    !CWAssembleMsgElemACIPv6List(NULL, &msg) ||
	    !CWAssembleMsgElemCWTimer(NULL, &msg) ||
	    /*!CWAssembleMsgElemRadioOperationalState(NULL, , -1, &msg) || */
	    !CWAssembleMsgElemDecryptErrorReportPeriod(NULL, &msg) ||
	    !CWAssembleMsgElemIdleTimeout(NULL, &msg) ||
	    !CWAssembleMsgElemWTPFallback(NULL, &msg) ||
	    !CWBindingAssembleConfigureResponse(&msg))
		goto cw_assemble_error;
	CWFinalizeMessage(&msg);

	if (!CWAssembleMessage(tm, PMTU, &msg))
		goto cw_assemble_error;

	CWDebugLog("Configure Response Assembled");
	return CW_TRUE;

 cw_assemble_error:
	CWReleaseMessage(&msg);
        return CW_FALSE;
}

CWBool CWSaveConfigureRequestMessage(CWProtocolConfigureRequestValues * configureRequest,
				     CWWTPProtocolManager * WTPProtocolManager)
{

	CWDebugLog("Saving Configure Request...");

	CW_FREE_OBJECT(WTPProtocolManager->ACName);

	if ((configureRequest->ACName) != NULL)
		WTPProtocolManager->ACName = configureRequest->ACName;

	CW_FREE_OBJECT((WTPProtocolManager->ACNameIndex).ACNameIndex);
	WTPProtocolManager->ACNameIndex = configureRequest->ACinWTP;

	CW_FREE_OBJECT((WTPProtocolManager->radioAdminInfo).radios);
	(WTPProtocolManager->radioAdminInfo).radiosCount = configureRequest->radioAdminInfoCount;
	(WTPProtocolManager->radioAdminInfo).radios = configureRequest->radioAdminInfo;

	WTPProtocolManager->StatisticsTimer = configureRequest->StatisticsTimer;

	/*
	   CW_FREE_OBJECT((WTPProtocolManager->WTPRadioInfo).radios);
	   WTPProtocolManager->WTPRadioInfo = configureRequest->WTPRadioInfo;
	 */

	CW_FREE_OBJECT(WTPProtocolManager->WTPRebootStatistics);
	WTPProtocolManager->WTPRebootStatistics = configureRequest->WTPRebootStatistics;

	CWDebugLog("Configure Request Saved");
	return CW_TRUE;
}
