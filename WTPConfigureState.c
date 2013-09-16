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

/* void CWWTPResponseTimerExpired(void *arg, CWTimerID id); */
static CWBool CWAssembleConfigureRequest(CWTransportMessage *tm, int PMTU, int seqNum, CWList msgElemList);
static CWBool CWParseConfigureResponseMessage(CWProtocolMessage *pm, int seqNum, void *values);
static CWBool CWSaveConfigureResponseMessage(void *value);

/*_________________________________________________________*/
/*  *******************___FUNCTIONS___*******************  */

/*
 * Manage Configure State.
 */
CWStateTransition CWWTPEnterConfigure()
{

	int seqNum;
	CWProtocolConfigureResponseValues *values;

	CWLog("\n");
	CWLog("######### Configure State #########");

	/* send Configure Request */
	seqNum = CWGetSeqNum();

	if (!(values = rzalloc(NULL, CWProtocolConfigureResponseValues)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	if (!CWErr(CWWTPSendAcknowledgedPacket(seqNum, NULL,
					       CWAssembleConfigureRequest,
					       CWParseConfigureResponseMessage,
					       CWSaveConfigureResponseMessage, values))) {

		ralloc_free(values);
		CWNetworkCloseSocket(gWTPSocket);
#ifndef CW_NO_DTLS
		CWSecurityDestroySession(&gWTPSession);
		CWSecurityDestroyContext(&gWTPSecurityContext);
#endif
		return CW_QUIT;
	}

	ralloc_free(values);
	return CW_ENTER_DATA_CHECK;
}

/*
void CWWTPResponseTimerExpired(void *arg, CWTimerID id)
{
    CWLog("WTP Response Configure Timer Expired");
    CWNetworkCloseSocket(gWTPSocket);
}
*/

/*
 * Send Configure Request on the active session.
 */
CWBool CWAssembleConfigureRequest(CWTransportMessage *tm, int PMTU, int seqNum, CWList msgElemList)
{
	CWProtocolMessage msg;

	assert(tm != NULL);

	CWDebugLog("Assembling Configure Request...");

	/* Assemble Message Elements */
	if (!CWInitMessage(NULL, &msg, CW_MSG_TYPE_VALUE_CONFIGURE_REQUEST, seqNum) ||
	    !CWAssembleMsgElemACName(NULL, &msg) ||
	    !CWAssembleMsgElemACNameWithIndex(NULL, &msg) ||
	    !CWAssembleMsgElemRadioAdminState(NULL, &msg) ||
	    !CWAssembleMsgElemStatisticsTimer(NULL, &msg) ||
	    !CWAssembleMsgElemWTPRebootStatistics(NULL, &msg) ||
	    !CWAssembleMsgElemWTPRadioInformation(NULL, &msg) ||
	    !CWAssembleMsgElemSupportedRates(NULL, &msg) ||
	    !CWAssembleMsgElemMultiDomainCapability(NULL, &msg))
		goto cw_assemble_error;
	CWFinalizeMessage(&msg);

	if (!CWAssembleMessage(tm, PMTU, &msg))
		goto cw_assemble_error;

	CWDebugLog("Configure Request Assembled");
	return CW_TRUE;

 cw_assemble_error:
	CWReleaseMessage(&msg);
        return CW_FALSE;
}

CWBool CWParseConfigureResponseMessage(CWProtocolMessage *pm, int seqNum, void *values)
{
	CWProtocolConfigureResponseValues *cr = (CWProtocolConfigureResponseValues *)values;
	CWControlHeaderValues controlVal;
	CWBool acAddressWithPrioFound = CW_FALSE;

	assert(pm != NULL);
	assert(values != NULL);

	CWDebugLog("Parsing Configure Response...");

	CW_ZERO_MEMORY(cr, sizeof(CWProtocolConfigureResponseValues));

	/* error will be handled by the caller */
	if (!(CWParseControlHeader(pm, &controlVal)))
		return CW_FALSE;

	/* different type */
	if (controlVal.messageTypeValue != CW_MSG_TYPE_VALUE_CONFIGURE_RESPONSE)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Message is not Configure Response as Expected");

	if (controlVal.seqNum != seqNum)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Different Sequence Number");

	/* skip timestamp */
	controlVal.msgElemsLen -= CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;

	CWParseMessageElementStart(pm);

	/* parse message elements */
	CWParseMessageElementWhile(pm, controlVal.msgElemsLen) {
		unsigned short int type = 0;	/* = CWProtocolRetrieve32(pm); */
		unsigned short int len = 0;	/* = CWProtocolRetrieve16(pm); */

		CWParseFormatMsgElem(pm, &type, &len);
		/* CWDebugLog("Parsing Message Element: %u, len: %u", type, len); */

		switch (type) {
		case CW_MSG_ELEMENT_AC_IPV4_LIST_CW_TYPE:
			if (!(CWParseACIPv4List(cr, pm, len, &(cr->ACIPv4ListInfo))))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_AC_IPV6_LIST_CW_TYPE:
			if (!(CWParseACIPv6List(cr, pm, len, &(cr->ACIPv6ListInfo))))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_CW_TIMERS_CW_TYPE:
			if (!(CWParseCWTimers(pm, len, &cr->CWTimers)))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_RADIO_OPERAT_STATE_CW_TYPE:
			if ((cr->radioOperationalInfoCount % CW_BLOCK_ALLOC) == 0) {
				cr->radioOperationalInfo =
					reralloc(cr, cr->radioOperationalInfo, CWRadioOperationalInfoValues,
						 cr->radioOperationalInfoCount + CW_BLOCK_ALLOC);
			}
			if (!cr->radioOperationalInfo)
				return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

			if (!CWParseWTPRadioOperationalState(pm, len, cr->radioOperationalInfo + cr->radioOperationalInfoCount))
				return CW_FALSE;
			cr->radioOperationalInfoCount++;
			break;
		case CW_MSG_ELEMENT_CW_DECRYPT_ER_REPORT_PERIOD_CW_TYPE:
			if ((cr->radiosDecryptErrorPeriod.radiosCount % CW_BLOCK_ALLOC) == 0) {
				cr->radiosDecryptErrorPeriod.radios =
					reralloc(cr, cr->radiosDecryptErrorPeriod.radios, WTPDecryptErrorReportValues,
						 cr->radiosDecryptErrorPeriod.radiosCount + CW_BLOCK_ALLOC);
			}
			if (!cr->radiosDecryptErrorPeriod.radios)
				return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

			if (!CWParseDecryptErrorReportPeriod(pm, len, cr->radiosDecryptErrorPeriod.radios + cr->radiosDecryptErrorPeriod.radiosCount))
				return CW_FALSE;
			cr->radiosDecryptErrorPeriod.radiosCount++;
			break;
		case CW_MSG_ELEMENT_IDLE_TIMEOUT_CW_TYPE:
			if (!(CWParseIdleTimeout(pm, len, cr)))
				return CW_FALSE;
			break;
		case CW_MSG_ELEMENT_WTP_FALLBACK_CW_TYPE:
			if (!(CWParseWTPFallback(pm, len, cr)))
				return CW_FALSE;
			break;

		case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_BW_CW_TYPE: {
			unsigned int vendorId = CWProtocolRetrieve32(pm);
			unsigned short int vendorElemType = CWProtocolRetrieve16(pm);
			len -= 6;

			CWDebugLog("Parsing Vendor Message Element, Vendor: %u, Element: %u", vendorId, vendorElemType);
			switch (vendorId) {
			case CW_IANA_ENTERPRISE_NUMBER_VENDOR_TRAVELPING: {
				CWDebugLog("Parsing TP Vendor Message Element: %u", vendorElemType);
				switch (vendorElemType) {
				case CW_MSG_ELEMENT_TRAVELPING_IEEE_80211_WLAN_HOLD_TIME:
					CWParseTPIEEE80211WLanHoldTime(pm, len, &cr->vendorTP_IEEE80211WLanHoldTime);
					break;

				case CW_MSG_ELEMENT_TRAVELPING_DATA_CHANNEL_DEAD_INTERVAL:
					CWParseTPDataChannelDeadInterval(pm, len, &cr->vendorTP_DataChannelDeadInterval);
					break;

				case CW_MSG_ELEMENT_TRAVELPING_AC_JOIN_TIMEOUT:
					CWParseTPACJoinTimeout(pm, len, &cr->vendorTP_ACJoinTimeout);
					break;

				case CW_MSG_ELEMENT_TRAVELPING_AC_ADDRESS_LIST_WITH_PRIORITY:
					if (acAddressWithPrioFound != CW_TRUE) {
						CWResetDiscoveredACAddresses();
						acAddressWithPrioFound = CW_TRUE;
					}
					if (!(CWParseACAddressListWithPrio(pm, len)))
						return CW_FALSE;
					break;

				default:
					CWLog("unknown TP Vendor Message Element: %u", vendorElemType);

					/* ignore unknown vendor extensions */
					CWParseSkipElement(pm, len);
					break;
				}
				break;
			}

			default:
				CWLog("unknown Vendor Message Element, Vendor: %u, Element: %u", vendorId, vendorElemType);

				/* ignore unknown vendor extensions */
				CWParseSkipElement(pm, len);
				break;
			}

			break;
		}

		case BINDING_MIN_ELEM_TYPE...BINDING_MAX_ELEM_TYPE:
			if (!CWBindingParseConfigureResponseElement(cr, pm, type, len, &cr->bindingValues))
				return CW_FALSE;
			break;

		default:
			CWLog("unknown Message Element, Element; %u", type);

			/* ignore unknown IE */
			CWParseSkipElement(pm, len);
		}
	}

	CWParseMessageElementEnd(pm, controlVal.msgElemsLen);
	CWParseTransportMessageEnd(pm);

	CWDebugLog("Configure Response Parsed");
	return CW_TRUE;
}

CWBool CWSaveConfigureResponseMessage(void *values)
{
	CWProtocolConfigureResponseValues *cr = (CWProtocolConfigureResponseValues *)values;

	assert(values != NULL);

	if (gACInfoPtr == NULL)
		return CWErrorRaise(CW_ERROR_NEED_RESOURCE, NULL);

	CWDebugLog("Saving Configure Response...");
	CWDebugLog("###A");
	CWDebugLog("###Count:%d", (cr->ACIPv4ListInfo).ACIPv4ListCount);
	if ((gACInfoPtr->ACIPv4ListInfo).ACIPv4List == NULL) {

		CWDebugLog("###NULL");
	}

	if ((cr->ACIPv4ListInfo).ACIPv4ListCount > 0) {

		CW_FREE_OBJECT((gACInfoPtr->ACIPv4ListInfo).ACIPv4List);
		(gACInfoPtr->ACIPv4ListInfo).ACIPv4ListCount = (cr->ACIPv4ListInfo).ACIPv4ListCount;
		(gACInfoPtr->ACIPv4ListInfo).ACIPv4List = (cr->ACIPv4ListInfo).ACIPv4List;
	}

	CWDebugLog("###B");

	if ((cr->ACIPv6ListInfo).ACIPv6ListCount > 0) {

		CW_FREE_OBJECT((gACInfoPtr->ACIPv6ListInfo).ACIPv6List);
		(gACInfoPtr->ACIPv6ListInfo).ACIPv6ListCount = (cr->ACIPv6ListInfo).ACIPv6ListCount;
		(gACInfoPtr->ACIPv6ListInfo).ACIPv6List = (cr->ACIPv6ListInfo).ACIPv6List;
	}

	if (cr->bindingValues != NULL) {

		CWProtocolResultCode resultCode;

		if (!CWBindingSaveConfigureResponse(cr->bindingValues, &resultCode)) {

			CW_FREE_OBJECT(cr->bindingValues);
			return CW_FALSE;
		}
	}

	if (cr->vendorTP_DataChannelDeadInterval != 0)
		gCWNeighborDeadInterval = cr->vendorTP_DataChannelDeadInterval;

	if (cr->vendorTP_ACJoinTimeout != 0)
		gCWWaitJoin = cr->vendorTP_ACJoinTimeout;

	if (cr->CWTimers.discoveryTimer != 0)
		gCWMaxDiscoveryInterval = cr->CWTimers.discoveryTimer;

	if (cr->CWTimers.echoRequestTimer > 0)
		gEchoInterval = cr->CWTimers.echoRequestTimer;

	/*
	   ""need to be added""

	   int radioOperationalInfoCount;
	   CWRadioOperationalInfoValues *radioOperationalInfo;
	   WTPDecryptErrorReport radiosDecryptErrorPeriod;
	   int idleTimeout;
	   int fallback;
	 */

	/*
	 * It is not clear to me what the original developers intended to
	 * accomplish. One thing's for sure: radioOperationalInfo, radiosDecryptErrorPeriod.radios,
	 * and bidingValues get allocated and are never freed,
	 * so we do it here...
	 *
	 * BUGs ML02-ML04-ML05
	 * 16/10/2009 - Donato Capitella
	 */
	CW_FREE_OBJECT(cr->radioOperationalInfo);
	CW_FREE_OBJECT(cr->radiosDecryptErrorPeriod.radios);
	CW_FREE_OBJECT(cr->bindingValues);

	CWDebugLog("Configure Response Saved");
	return CW_TRUE;
}
