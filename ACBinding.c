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
 * -------------------------------------------------------------------------------------------- *
 * Project:  Capwap                                                                             *
 *                                                                                              *
 * Authors : Ludovico Rossi (ludo@bluepixysw.com)                                               *
 *           Del Moro Andrea (andrea_delmoro@libero.it)                                         *
 *           Giovannini Federica (giovannini.federica@gmail.com)                                *
 *           Massimo Vellucci (m.vellucci@unicampus.it)                                         *
 *           Mauro Bisson (mauro.bis@gmail.com)                                                 *
 *           Daniele De Sanctis (danieledesanctis@gmail.com)                                    *
 *           Antonio Davoli (antonio.davoli@gmail.com)                                          *
 ************************************************************************************************/

#include "CWAC.h"

CWBool CWACInitBinding(int i)
{
	int j;
	bindingValues *aux;

	if (!(aux = ralloc(NULL, bindingValues)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	(gWTPs[i].WTPProtocolManager).bindingValuesPtr = (void *)aux;

	if (!(aux->qosValues = ralloc_array(aux, WTPQosValues, NUM_QOS_PROFILES)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	//Init default values
	for (j = 0; j < NUM_QOS_PROFILES; j++) {
		aux->qosValues[j].cwMin = gDefaultQosValues[j].cwMin;
		aux->qosValues[j].cwMax = gDefaultQosValues[j].cwMax;
		aux->qosValues[j].AIFS = gDefaultQosValues[j].AIFS;

		aux->qosValues[j].queueDepth = 0;
		aux->qosValues[j].dot1PTag = 0;
		aux->qosValues[j].DSCPTag = 0;
	}

	return CW_TRUE;
}

CWBool CWMergeQosValues(int WTPIndex)
{
	int i;
	bindingValues *aux;

	aux = (bindingValues *) (gWTPs[WTPIndex].WTPProtocolManager).bindingValuesPtr;

	for (i = 0; i < NUM_QOS_PROFILES; i++) {
		if (gWTPs[WTPIndex].qosValues[i].cwMin == UNUSED_QOS_VALUE) {
			gWTPs[WTPIndex].qosValues[i].cwMin = aux->qosValues[i].cwMin;
		}

		if (gWTPs[WTPIndex].qosValues[i].cwMax == UNUSED_QOS_VALUE) {
			gWTPs[WTPIndex].qosValues[i].cwMax = aux->qosValues[i].cwMax;
		}

		if (gWTPs[WTPIndex].qosValues[i].AIFS == UNUSED_QOS_VALUE) {
			gWTPs[WTPIndex].qosValues[i].AIFS = aux->qosValues[i].AIFS;
		}
	}
	return CW_TRUE;
}

/******************************************************************
 * 2009 Updates:                                                  *
 *              Functions for management of Configuration Update  *
 *              Request with OFDM Message Element                 *
 ******************************************************************/

CWBool CWMergeOFDMValues(int WTPIndex)
{

	OFDMControlValues *aux;

	aux = (OFDMControlValues *) (gWTPs[WTPIndex].WTPProtocolManager).bindingValuesPtr;

	if (gWTPs[WTPIndex].ofdmValues->currentChan == UNUSED_OFDM_VALUE)
		gWTPs[WTPIndex].ofdmValues->currentChan = aux->currentChan;

	if (gWTPs[WTPIndex].ofdmValues->BandSupport == UNUSED_OFDM_VALUE)
		gWTPs[WTPIndex].ofdmValues->BandSupport = aux->BandSupport;

	if (gWTPs[WTPIndex].ofdmValues->TIThreshold == UNUSED_OFDM_VALUE)
		gWTPs[WTPIndex].ofdmValues->TIThreshold = aux->TIThreshold;

	return CW_TRUE;
}

CWBool CWAssembleWTPOFDM(const void *ctx, CWProtocolMessage *pm, int radioID)
{
	int *iPtr;
	OFDMControlValues *valuesPtr;

	CWLog("Assembling Binding Configuration Update Request [OFDM CASE]...");

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if ((iPtr = ((int *)CWThreadGetSpecific(&gIndexSpecific))) == NULL)
		return CW_FALSE;

	if (!CWMergeOFDMValues(*iPtr))
		return CW_FALSE;

	valuesPtr = gWTPs[*iPtr].ofdmValues;

	CWInitMsgElem(ctx, pm, BINDING_MSG_ELEMENT_TYPE_OFDM_CONTROL_LENGTH, BINDING_MSG_ELEMENT_TYPE_OFDM_CONTROL);
	CWProtocolStore8(pm, radioID);
	CWProtocolStore32(pm, valuesPtr->currentChan);
	CWProtocolStore8(pm, valuesPtr->BandSupport);
	CWProtocolStore32(pm, valuesPtr->TIThreshold);
	CWFinalizeMsgElem(pm);

	CWLog("Assembling Binding Configuration Update Request [OFDM CASE]: Message Assembled.");

	return CW_TRUE;
}

CWBool CWAssembleWTPQoS(const void *ctx, CWProtocolMessage *pm, int radioID, int tagPackets)
{
	int i;
	int *iPtr;
	WTPQosValues *valuesPtr;

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if ((iPtr = ((int *)CWThreadGetSpecific(&gIndexSpecific))) == NULL)
		return CW_FALSE;

	if (!CWMergeQosValues(*iPtr))
		return CW_FALSE;

	valuesPtr = gWTPs[*iPtr].qosValues;

	CWInitMsgElem(ctx, pm, 2 + 8 * NUM_QOS_PROFILES, BINDING_MSG_ELEMENT_TYPE_WTP_QOS);
	CWProtocolStore8(pm, radioID);
	CWProtocolStore8(pm, tagPackets);
	for (i = 0; i < NUM_QOS_PROFILES; i++) {
		CWProtocolStore8(pm, valuesPtr[i].queueDepth);
		CWProtocolStore16(pm, valuesPtr[i].cwMin);
		CWProtocolStore16(pm, valuesPtr[i].cwMax);
		CWProtocolStore8(pm, valuesPtr[i].AIFS);
		CWProtocolStore8(pm, valuesPtr[i].dot1PTag);
		CWProtocolStore8(pm, valuesPtr[i].DSCPTag);
	}
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWBindingAssembleConfigureResponse(CWProtocolMessage *msg)
{
	CWWTPRadiosInfo radiosInfo;
	int *iPtr;
	const int tagPackets = 0;
	int radioCount, radioID, j;

	if (msg == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if ((iPtr = ((int *)CWThreadGetSpecific(&gIndexSpecific))) == NULL)
		return CW_FALSE;

	//Calculate the number of msg Elements
	radiosInfo = gWTPs[*iPtr].WTPProtocolManager.radiosInfo;
	radioCount = radiosInfo.radioCount;

	CWLog("Assembling Binding Configuration Response...");

	if (!CWThreadMutexLock(&(gWTPs[*iPtr].interfaceMutex))) {
		CWLog("Error locking a mutex");
		CWCloseThread();
	}

	//Fill gWTPs[*iPtr].qosValues with default settings
	gWTPs[*iPtr].qosValues = gDefaultQosValues;

	for (j = 0; j < radioCount; j++) {
		radioID = radiosInfo.radiosInfo[j].radioID;
		// Assemble WTP QoS Message Element for each radio
		if (!(CWAssembleWTPQoS(NULL, msg, radioID, tagPackets))) {
			CWThreadMutexUnlock(&(gWTPs[*iPtr].interfaceMutex));
			return CW_FALSE;	// error will be handled by the caller
		}
	}

	gWTPs[*iPtr].qosValues = NULL;
	CWThreadMutexUnlock(&(gWTPs[*iPtr].interfaceMutex));

	CWLog("Binding Configuration Response Assembled");

	return CW_TRUE;
}

/******************************************************************
 * 2009 Updates:                                                  *
 *              Added new switch case for ofdm message management *
 ******************************************************************/

CWBool CWBindingAssembleConfigurationUpdateRequest(CWProtocolMessage *msg, int BindingMsgElement)
{
	CWWTPRadiosInfo radiosInfo;
	int *iPtr;
	const int tagPackets = 0;
	int radioCount, radioID, j;

	if (msg == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if ((iPtr = ((int *)CWThreadGetSpecific(&gIndexSpecific))) == NULL)
		return CW_FALSE;

	radiosInfo = gWTPs[*iPtr].WTPProtocolManager.radiosInfo;
	radioCount = radiosInfo.radioCount;

	CWLog("Assembling Binding Configuration Update Request...");

	/* Selection of type of Conf Update Request */

	switch (BindingMsgElement) {
	case BINDING_MSG_ELEMENT_TYPE_WTP_QOS:
		for (j = 0; j < radioCount; j++) {
			radioID = radiosInfo.radiosInfo[j].radioID;

			if (!(CWAssembleWTPQoS(NULL, msg, radioID, tagPackets)))
				return CW_FALSE;
		}
		break;

	case BINDING_MSG_ELEMENT_TYPE_OFDM_CONTROL:
		for (j = 0; j < radioCount; j++) {
			radioID = radiosInfo.radiosInfo[j].radioID;

			if (!(CWAssembleWTPOFDM(NULL, msg, radioID)))
				return CW_FALSE;
		}
		break;

	default:
		return CW_FALSE;
	}

	CWLog("Binding Configuration Update Request Assembled");

	return CW_TRUE;
}

CWBool CWBindingSaveConfigurationUpdateResponse(CWProtocolResultCode resultCode, int WTPIndex)
{
	int i;

	bindingValues *aux = (bindingValues *) gWTPs[WTPIndex].WTPProtocolManager.bindingValuesPtr;

	if (resultCode == CW_PROTOCOL_SUCCESS) {
		if (gWTPs[WTPIndex].qosValues != NULL) {
			for (i = 0; i < NUM_QOS_PROFILES; i++) {
				aux->qosValues[i].cwMin = gWTPs[WTPIndex].qosValues[i].cwMin;
				aux->qosValues[i].cwMax = gWTPs[WTPIndex].qosValues[i].cwMax;
				aux->qosValues[i].AIFS = gWTPs[WTPIndex].qosValues[i].AIFS;
			}
		}
	}

	return CW_TRUE;
}
