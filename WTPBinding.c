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
 * In addition, as a special exception, the copyright holders give permission to link the       *
 * code of portions of this program with the OpenSSL library under certain conditions as        *
 * described in each individual source file, and distribute linked combinations including       *
 * the two. You must obey the GNU General Public License in all respects for all of the         *
 * code used other than OpenSSL.  If you modify file(s) with this exception, you may            *
 * extend this exception to your version of the file(s), but you are not obligated to do        *
 * so.  If you do not wish to do so, delete this exception statement from your version.         *
 * If you delete this exception statement from all source files in the program, then also       *
 * delete it here.                                                                              *
 *                                                                                              *
 * -------------------------------------------------------------------------------------------- *
 * Project:  Capwap                                                                             *
 *                                                                                              *
 * Authors : Ludovico Rossi (ludo@bluepixysw.com)                                               *
 *           Del Moro Andrea (andrea_delmoro@libero.it)                                         *
 *           Giovannini Federica (giovannini.federica@gmail.com)                                *
 *           Massimo Vellucci (m.vellucci@unicampus.it)                                         *
 *           Mauro Bisson (mauro.bis@gmail.com)                                                 *
 *           Antonio Davoli (antonio.davoli@gmail.com)                                          *
 ************************************************************************************************/

#include "wireless_copy.h"
#include "CWWTP.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <signal.h>

int CWTranslateQueueIndex(int j)
{
	if (j == VOICE_QUEUE_INDEX)
		return 3;
	if (j == VIDEO_QUEUE_INDEX)
		return 2;
	if (j == BACKGROUND_QUEUE_INDEX)
		return 1;

	return 0;
}

#ifdef SOFTMAC
CWBool CWWTPInitBinding(int radioIndex)
{

	bindingValues *aux;
	int i;

	if (!(aux = ralloc(NULL, bindingValues)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	gRadiosInfo.radiosInfo[radioIndex].bindingValuesPtr = (void *)aux;

	if (!(aux->qosValues = ralloc_array(NULL, WTPQosValues, NUM_QOS_PROFILES)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	for (i = 0; i < NUM_QOS_PROFILES; i++) {
		/* TODO: Get info from Hostapd UNIX DOMAIN SOCKET */
		aux->qosValues[i].cwMin = 3;
		aux->qosValues[i].cwMax = 15;
		aux->qosValues[i].AIFS = 2;
	}

	return CW_TRUE;
}

#else

#ifndef BCM
CWBool CWWTPInitBinding(int radioIndex)
{

	bindingValues *aux;
	int i, sock;
	struct iwreq wrq;

	/*** Inizializzazione socket ***/
	sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (sock < 0) {

		CWLog("Error Creating Socket for ioctl");
		return CW_FALSE;
	}

	/*** Inizializzazione struttura iwreq ***/
	memset(&wrq, 0, sizeof(wrq));
	strncpy(wrq.ifr_name, gInterfaceName, IFNAMSIZ);

	CWLog("wrq.ifr_name %s ", wrq.ifr_name);

	if (!(aux = ralloc(NULL, bindingValues)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	gRadiosInfo.radiosInfo[radioIndex].bindingValuesPtr = (void *)aux;

	if (!(aux->qosValues = ralloc_array(NULL, WTPQosValues, NUM_QOS_PROFILES)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	for (i = 0; i < NUM_QOS_PROFILES; i++) {

		/*
		 * Donato Capitella - TO_REMOVE_DEVELOP
		 * Commented the following lines just to make the WTP work in a test machine.
		 */
		//if(!get_cwmin(sock, &wrq, CWTranslateQueueIndex(i), 0)){return CW_FALSE;}

		//aux->qosValues[i].cwMin = wrq.u.param.value;

		//if(!get_cwmax(sock, &wrq, CWTranslateQueueIndex(i), 0)){return CW_FALSE;}
		//aux->qosValues[i].cwMax = wrq.u.param.value;

		//if(!get_aifs(sock, &wrq, CWTranslateQueueIndex(i), 0)){return CW_FALSE;}
		//aux->qosValues[i].AIFS = wrq.u.param.value;

		/*##        aux->qosValues[i].cwMin = 2;
		   aux->qosValues[i].cwMax = 4;
		   aux->qosValues[i].AIFS = 3;
		 */
	}

	return CW_TRUE;
}

#else
CWBool CWWTPInitBinding(int radioIndex)
{

	bindingValues *aux;
	int i;

	if (!(aux = ralloc(NULL, bindingValues)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	gRadiosInfo.radiosInfo[radioIndex].bindingValuesPtr = (void *)aux;

	if (!(aux->qosValues = ralloc_array(NULL, WTPQosValues, NUM_QOS_PROFILES)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	for (i = 0; i < NUM_QOS_PROFILES; i++) {
		/*Daniele: i driver Broadcom non permettono get sulle WME: setto i parametri del Qos a valori costanti */
		aux->qosValues[i].cwMin = 2;
		aux->qosValues[i].cwMax = 4;
		aux->qosValues[i].AIFS = 3;
	}

	return CW_TRUE;
}
#endif

#endif

#ifdef SOFTMAC

CWBool CWBindingSetQosValues(int qosCount, RadioQosValues * radioQosValues, CWProtocolResultCode * resultCode)
{

	if (qosCount <= 0) {
		return CW_TRUE;
	}
	if (radioQosValues == NULL) {
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	}

	*resultCode = CW_PROTOCOL_SUCCESS;

	int i, k, j;

	for (i = 0; i < qosCount; i++) {
		for (k = 0; k < gRadiosInfo.radioCount; k++) {
			if (radioQosValues[i].radioID == gRadiosInfo.radiosInfo[k].radioID) {
				bindingValues *auxPtr = (bindingValues *) gRadiosInfo.radiosInfo[k].bindingValuesPtr;

				for (j = 0; j < NUM_QOS_PROFILES; j++) {

					CWLog("AIFS:  %d    %d", auxPtr->qosValues[j].AIFS,
					      radioQosValues[i].qosValues[j].AIFS);

					int aifs = (int)radioQosValues[i].qosValues[j].AIFS;
					int burst_time = 0;
					if (j == 0)
						burst_time = 15;
					else if (j == 1)
						burst_time = 30;

					if (set_txq
					    (j, radioQosValues[i].qosValues[j].cwMin,
					     radioQosValues[i].qosValues[j].cwMax, aifs, burst_time)) {
						auxPtr->qosValues[j].cwMin = radioQosValues[i].qosValues[j].cwMin;
						auxPtr->qosValues[j].cwMax = radioQosValues[i].qosValues[j].cwMax;
						auxPtr->qosValues[j].AIFS = radioQosValues[i].qosValues[j].AIFS;
					} else {
						*resultCode = CW_PROTOCOL_FAILURE;
					}

					/*
					   if(auxPtr->qosValues[j].cwMin!=radioQosValues[i].qosValues[j].cwMin)
					   {
					   if (set_wme_cwmin(CWTranslateQueueIndex(j), radioQosValues[i].qosValues[j].cwMin))
					   {auxPtr->qosValues[j].cwMin=radioQosValues[i].qosValues[j].cwMin;}
					   else {*resultCode=CW_PROTOCOL_FAILURE;}
					   }

					   if(auxPtr->qosValues[j].cwMax!=radioQosValues[i].qosValues[j].cwMax)
					   {
					   if (set_wme_cwmax(CWTranslateQueueIndex(j), radioQosValues[i].qosValues[j].cwMax))
					   {auxPtr->qosValues[j].cwMax=radioQosValues[i].qosValues[j].cwMax;}
					   else {*resultCode=CW_PROTOCOL_FAILURE;}
					   }

					   if(auxPtr->qosValues[j].AIFS!=radioQosValues[i].qosValues[j].AIFS)
					   {
					   if (set_wme_aifsn(CWTranslateQueueIndex(j), radioQosValues[i].qosValues[j].AIFS))
					   {auxPtr->qosValues[j].AIFS=radioQosValues[i].qosValues[j].AIFS;}
					   else {*resultCode=CW_PROTOCOL_FAILURE;}
					   }
					 */
				}
				break;
			}
		}
	}

	return CW_TRUE;
}

#else

#ifndef BCM
CWBool CWBindingSetQosValues(int qosCount, RadioQosValues * radioQosValues, CWProtocolResultCode * resultCode)
{
	struct iwreq wrq;
	int sock;

	if (qosCount <= 0) {
		return CW_TRUE;
	}
	if (radioQosValues == NULL) {
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	}

	*resultCode = CW_PROTOCOL_SUCCESS;

	/*** Inizializzazione socket ***/
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		CWLog("Error Creating Socket for ioctl");
		return CWErrorRaise(CW_ERROR_GENERAL, NULL);;
	}

	/*** Inizializzazione struttura iwreq ***/
	memset(&wrq, 0, sizeof(wrq));
	strncpy(wrq.ifr_name, gInterfaceName, IFNAMSIZ);

	int i, k, j;

	for (i = 0; i < qosCount; i++) {
		for (k = 0; k < gRadiosInfo.radioCount; k++) {
			if (radioQosValues[i].radioID == gRadiosInfo.radiosInfo[k].radioID) {
				bindingValues *auxPtr = (bindingValues *) gRadiosInfo.radiosInfo[k].bindingValuesPtr;

				for (j = 0; j < NUM_QOS_PROFILES; j++) {
					if (auxPtr->qosValues[j].cwMin != radioQosValues[i].qosValues[j].cwMin) {
						if (set_cwmin
						    (sock, wrq, CWTranslateQueueIndex(j), 0,
						     radioQosValues[i].qosValues[j].cwMin)) {
							auxPtr->qosValues[j].cwMin =
							    radioQosValues[i].qosValues[j].cwMin;
						} else {
							*resultCode = CW_PROTOCOL_FAILURE;
						}
					}

					if (auxPtr->qosValues[j].cwMax != radioQosValues[i].qosValues[j].cwMax) {
						if (set_cwmax
						    (sock, wrq, CWTranslateQueueIndex(j), 0,
						     radioQosValues[i].qosValues[j].cwMax)) {
							auxPtr->qosValues[j].cwMax =
							    radioQosValues[i].qosValues[j].cwMax;
						} else {
							*resultCode = CW_PROTOCOL_FAILURE;
						}
					}

					if (auxPtr->qosValues[j].AIFS != radioQosValues[i].qosValues[j].AIFS) {
						if (set_aifs
						    (sock, wrq, CWTranslateQueueIndex(j), 0,
						     radioQosValues[i].qosValues[j].AIFS)) {
							auxPtr->qosValues[j].AIFS = radioQosValues[i].qosValues[j].AIFS;
						} else {
							*resultCode = CW_PROTOCOL_FAILURE;
						}
					}
				}
				break;
			}
		}
	}
	//WTPQosValues* aux=radioQosValues;

	close(sock);
	return CW_TRUE;
}

#else

CWBool CWBindingSetQosValues(int qosCount, RadioQosValues * radioQosValues, CWProtocolResultCode * resultCode)
{

	if (qosCount <= 0) {
		return CW_TRUE;
	}
	if (radioQosValues == NULL) {
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	}

	*resultCode = CW_PROTOCOL_SUCCESS;

	int i, k, j;

	for (i = 0; i < qosCount; i++) {
		for (k = 0; k < gRadiosInfo.radioCount; k++) {
			if (radioQosValues[i].radioID == gRadiosInfo.radiosInfo[k].radioID) {
				bindingValues *auxPtr = (bindingValues *) gRadiosInfo.radiosInfo[k].bindingValuesPtr;

				for (j = 0; j < NUM_QOS_PROFILES; j++) {

					if (auxPtr->qosValues[j].cwMin != radioQosValues[i].qosValues[j].cwMin) {
						if (set_wme_cwmin
						    (CWTranslateQueueIndex(j), radioQosValues[i].qosValues[j].cwMin)) {
							auxPtr->qosValues[j].cwMin =
							    radioQosValues[i].qosValues[j].cwMin;
						} else {
							*resultCode = CW_PROTOCOL_FAILURE;
						}
					}

					if (auxPtr->qosValues[j].cwMax != radioQosValues[i].qosValues[j].cwMax) {
						if (set_wme_cwmax
						    (CWTranslateQueueIndex(j), radioQosValues[i].qosValues[j].cwMax)) {
							auxPtr->qosValues[j].cwMax =
							    radioQosValues[i].qosValues[j].cwMax;
						} else {
							*resultCode = CW_PROTOCOL_FAILURE;
						}
					}

					if (auxPtr->qosValues[j].AIFS != radioQosValues[i].qosValues[j].AIFS) {
						if (set_wme_aifsn
						    (CWTranslateQueueIndex(j), radioQosValues[i].qosValues[j].AIFS)) {
							auxPtr->qosValues[j].AIFS = radioQosValues[i].qosValues[j].AIFS;
						} else {
							*resultCode = CW_PROTOCOL_FAILURE;
						}
					}
				}
				break;
			}
		}
	}

	return CW_TRUE;
}

#endif

#endif

CWBool CWManageOFDMValues(CWBindingConfigurationUpdateRequestValuesOFDM * ofdmValues, CWProtocolResultCode * resultCode)
{
	if (ofdmValues == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	*resultCode = CW_PROTOCOL_SUCCESS;

	OFDMControlValues *radioValues = ofdmValues->radioOFDMValues;
	//unsigned char radioID = ofdmValues->radioID;

	struct sockaddr_in serv_addr;
	int sendSock, slen = sizeof(serv_addr);

	if ((sendSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		CWLog("[FreqAnalyzer]: Error on creation of socket.");
		return CWErrorRaise(CW_ERROR_GENERAL, NULL);
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(FREQ_SERVER_PORT);

	if (inet_aton(FREQ_SERVER_ADDR, &serv_addr.sin_addr) == 0) {
		CWLog("[CWManageOFDMValue]: Error on aton function.");
		close(sendSock);
		return CWErrorRaise(CW_ERROR_GENERAL, NULL);
	}

	if (sendto(sendSock, radioValues, sizeof(OFDMControlValues), 0, (struct sockaddr *)&serv_addr, slen) < 0) {
		CWLog("[CWManageOFDMValue]: Error on sendto function.");
		close(sendSock);
		return CWErrorRaise(CW_ERROR_GENERAL, NULL);
	}

	close(sendSock);
	return CW_TRUE;
}

CWBool CWParseWTPOFDM(CWProtocolMessage *pm, int len, unsigned char *radioID, OFDMControlValues * valPtr)
{
	CWParseMessageElementStart(pm);

	*radioID = CWProtocolRetrieve8(pm);

	valPtr->currentChan = CWProtocolRetrieve32(pm);
	valPtr->BandSupport = (unsigned char)CWProtocolRetrieve8(pm);
	valPtr->TIThreshold = (unsigned int)CWProtocolRetrieve32(pm);

	return CWParseMessageElementEnd(pm, len);

}

CWBool CWParseWTPQoS(CWProtocolMessage *pm, int len, unsigned char *radioID, unsigned char *tagPackets,
		     WTPQosValues * valPtr)
{
	int i;

	CWParseMessageElementStart(pm);

	*radioID = CWProtocolRetrieve8(pm);
	*tagPackets = CWProtocolRetrieve8(pm);

	for (i = 0; i < NUM_QOS_PROFILES; i++) {
		valPtr[i].queueDepth = (unsigned char)CWProtocolRetrieve8(pm);
		valPtr[i].cwMin = CWProtocolRetrieve16(pm);
		valPtr[i].cwMax = CWProtocolRetrieve16(pm);
		valPtr[i].AIFS = (unsigned char)CWProtocolRetrieve8(pm);
		valPtr[i].dot1PTag = (unsigned char)CWProtocolRetrieve8(pm);
		valPtr[i].DSCPTag = (unsigned char)CWProtocolRetrieve8(pm);
	}

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWBindingSaveConfigurationUpdateRequest(void *bindingValuesPtr, CWProtocolResultCode * resultCode,
					       int *updateRequestType)
{
	if (bindingValuesPtr == NULL) {
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	}
	*resultCode = CW_PROTOCOL_SUCCESS;

	switch (*updateRequestType) {
	case BINDING_MSG_ELEMENT_TYPE_WTP_QOS:{
			CWBindingConfigurationUpdateRequestValues *bindingPtr =
			    (CWBindingConfigurationUpdateRequestValues *) bindingValuesPtr;

			if (bindingPtr->qosCount > 0) {
				if (!CWBindingSetQosValues
				    (bindingPtr->qosCount, bindingPtr->radioQosValues, resultCode)) {
					CW_FREE_OBJECT(bindingPtr);
					return CW_FALSE;
				}
				CW_FREE_OBJECT(bindingPtr);
			}
			return CW_TRUE;
			break;
		}
	case BINDING_MSG_ELEMENT_TYPE_OFDM_CONTROL:{
			CWBindingConfigurationUpdateRequestValuesOFDM *bindingPtr =
			    (CWBindingConfigurationUpdateRequestValuesOFDM *) bindingValuesPtr;

			if (!CWManageOFDMValues(bindingPtr, resultCode)) {
				CW_FREE_OBJECT(bindingPtr);
				return CW_FALSE;
			}

			return CW_TRUE;
			break;
		}
	}

	return CW_TRUE;
}

CWBool CWBindingParseConfigurationUpdateRequestElement(const void *ctx, CWProtocolMessage *pm,
						       unsigned short int type, unsigned short int len,
						       void **valuesPtr)
{
	CWBindingConfigurationUpdateRequestValues *auxBindingPtr = NULL;
	CWBindingConfigurationUpdateRequestValuesOFDM *ofdmBindingPtr = NULL;

	assert(pm != NULL);
	assert(valuesPtr != NULL);

	CWLog("Parsing Binding Configuration Update Request Element...");

	CWParseMessageElementStart(pm);
	switch (type) {
	case BINDING_MSG_ELEMENT_TYPE_WTP_QOS: {
		unsigned char tagPackets;
		if (!*valuesPtr) {
			if (!(auxBindingPtr = ralloc(ctx, CWBindingConfigurationUpdateRequestValues)))
				return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

			*valuesPtr = (void *)auxBindingPtr;
		}

		if ((auxBindingPtr->qosCount % CW_BLOCK_ALLOC) == 0) {
			auxBindingPtr->radioQosValues =
				reralloc(ctx, auxBindingPtr->radioQosValues, RadioQosValues,
					 auxBindingPtr->qosCount + CW_BLOCK_ALLOC);
		}

		if (!CWParseWTPQoS(pm, len, &auxBindingPtr->radioQosValues[auxBindingPtr->qosCount].radioID, &tagPackets,
				   auxBindingPtr->radioQosValues[auxBindingPtr->qosCount].qosValues))
			return CW_FALSE;
		auxBindingPtr->qosCount++;
		break;

	case BINDING_MSG_ELEMENT_TYPE_OFDM_CONTROL:
		if (!(ofdmBindingPtr = ralloc(ctx, CWBindingConfigurationUpdateRequestValuesOFDM)) ||
		    !(ofdmBindingPtr->radioOFDMValues = ralloc(ofdmBindingPtr, OFDMControlValues)))
			return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

		*valuesPtr = (void *)ofdmBindingPtr;

		if (!CWParseWTPOFDM(pm, len, &ofdmBindingPtr->radioID, ofdmBindingPtr->radioOFDMValues)) {
			CW_FREE_OBJECT(valuesPtr);
			return CW_FALSE;
		}
		break;
	}

	default:
		CWParseSkipElement(pm, len);
		break;
	}
	return CWParseMessageElementEnd(pm, len);
}

CWBool CWBindingSaveConfigureResponse(void *bindingValuesPtr, CWProtocolResultCode * resultCode)
{
	if (bindingValuesPtr == NULL) {
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	}
	*resultCode = CW_PROTOCOL_SUCCESS;

	CWBindingConfigurationRequestValues *bindingPtr = (CWBindingConfigurationRequestValues *) bindingValuesPtr;

	if (bindingPtr->qosCount > 0) {
		if (!CWBindingSetQosValues(bindingPtr->qosCount, bindingPtr->radioQosValues, resultCode)) {
			CW_FREE_OBJECT(bindingPtr->radioQosValues);
			return CW_FALSE;
		}
		CW_FREE_OBJECT(bindingPtr->radioQosValues);
	}
	return CW_TRUE;
}

CWBool CWBindingParseConfigureResponseElement(const void *ctx, CWProtocolMessage *pm,
					      unsigned short int type, unsigned short int len,
					      void **valuesPtr)
{
	CWBindingConfigurationRequestValues *auxBindingPtr;

	assert(pm != NULL);
	assert(valuesPtr != NULL);

	CWLog("Parsing Binding Configure Response Element...");

	if (!*valuesPtr)
		if (!(*valuesPtr = rzalloc(ctx, CWBindingConfigurationRequestValues)))
			return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	auxBindingPtr = (CWBindingConfigurationRequestValues *)*valuesPtr;

	CWParseMessageElementStart(pm);
	switch (type) {
	case BINDING_MSG_ELEMENT_TYPE_WTP_QOS:
	{
		unsigned char tagPackets;
		if ((auxBindingPtr->qosCount % CW_BLOCK_ALLOC) == 0) {
			auxBindingPtr->radioQosValues =
				reralloc(ctx, auxBindingPtr->radioQosValues, RadioQosValues,
					 auxBindingPtr->qosCount + CW_BLOCK_ALLOC);
		}
		if (!auxBindingPtr->radioQosValues)
			return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

		if (!CWParseWTPQoS(pm, len, &auxBindingPtr->radioQosValues[auxBindingPtr->qosCount].radioID, &tagPackets,
				   auxBindingPtr->radioQosValues[auxBindingPtr->qosCount].qosValues))
			return CW_FALSE;
		auxBindingPtr->qosCount++;
		break;
	}
	default:
		CWParseSkipElement(pm, len);
		break;
	}
	return CWParseMessageElementEnd(pm, len);
}
