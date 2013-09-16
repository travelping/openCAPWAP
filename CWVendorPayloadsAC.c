/************************************************************************************************
 * Copyright (c) 2006-2009 Laboratorio di Sistemi di Elaborazione e Bioingegneria Informatica   *
 *                          Universita' Campus BioMedico - Italy                                *
 *                                                                                              *
 * This program is free software; you can redistribute it and/or modify it under the terms      *
 * of the GNU General Public License as published by the free Software Foundation; either       *
 * version 2 of the License, or (at your option) any later version.                             *
 *                                                                                              *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY              *
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A         *
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
 * Authors : Matteo Latini (mtylty@gmail.com)                                                   *
 *
 ************************************************************************************************/

#include "CWVendorPayloads.h"
#include "WUM.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <signal.h>

CWBool CWAssembleWTPVendorPayloadUCI(const void *ctx, CWProtocolMessage *pm)
{
	int *iPtr;
	unsigned short msgType;
	CWProtocolVendorSpecificValues *valuesPtr;
	CWVendorUciValues *uciPtr;

	CWLog("Assembling Protocol Configuration Update Request [VENDOR CASE]...");

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if ((iPtr = ((int *)CWThreadGetSpecific(&gIndexSpecific))) == NULL) {
		return CW_FALSE;
	}

	valuesPtr = gWTPs[*iPtr].vendorValues;
	switch (valuesPtr->vendorPayloadType) {
	case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_UCI:
		msgType = CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_UCI;
		uciPtr = (CWVendorUciValues *) valuesPtr->payload;
		if (uciPtr->commandArgs != NULL) {
			CWInitMsgElem(ctx, pm,
				      sizeof(short) + sizeof(char) + sizeof(int) +
				      (strlen(uciPtr->commandArgs) * sizeof(char)),
				      CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE);
			CWProtocolStore16(pm, (unsigned short)msgType);
			CWProtocolStore8(pm, (unsigned char)uciPtr->command);
			CWProtocolStore32(pm, (unsigned int)strlen(uciPtr->commandArgs));
			CWProtocolStoreStr(pm, uciPtr->commandArgs);
			CWFinalizeMsgElem(pm);
		} else {
			CWInitMsgElem(ctx, pm, sizeof(short) + sizeof(char) + sizeof(int),
				      CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE);
			CWProtocolStore16(pm, (unsigned short)msgType);
			CWProtocolStore8(pm, (unsigned char)uciPtr->command);
			CWProtocolStore32(pm, 0);
			CWFinalizeMsgElem(pm);
		}
		break;
	default:
		return CW_FALSE;
		break;
	}
	CWLog("Assembling Protocol Configuration Update Request [VENDOR CASE]: Message Assembled.");

	return CW_TRUE;
}

CWBool CWAssembleWTPVendorPayloadWUM(const void *ctx, CWProtocolMessage *pm)
{
	int *iPtr;
	unsigned short msgType;
	unsigned int payloadSize = 0;
	CWProtocolVendorSpecificValues *valuesPtr;
	CWVendorWumValues *wumPtr;

	CWLog("Assembling Protocol Configuration Update Request [VENDOR CASE]...");

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if ((iPtr = ((int *)CWThreadGetSpecific(&gIndexSpecific))) == NULL) {
		return CW_FALSE;
	}

	valuesPtr = gWTPs[*iPtr].vendorValues;
	switch (valuesPtr->vendorPayloadType) {
	case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_WUM:
		/*
		 * Here we assemble the WTP Update Messages.
		 */
		msgType = CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_WUM;
		wumPtr = (CWVendorWumValues *) valuesPtr->payload;

		switch (wumPtr->type) {
		case WTP_VERSION_REQUEST:
		case WTP_COMMIT_UPDATE:
		case WTP_CANCEL_UPDATE_REQUEST:
			payloadSize = sizeof(short) + sizeof(char);
			break;
		case WTP_UPDATE_REQUEST:
			payloadSize = sizeof(short) + 4 * sizeof(char) + sizeof(unsigned int);
			break;
		case WTP_CUP_FRAGMENT:
			payloadSize = sizeof(short) + sizeof(char) + 2 * sizeof(int) + wumPtr->_cup_fragment_size_;
			break;
		default:
			CWLog("Error! unknown WUM message type!!!");
			return CW_FALSE;
		}

		CWInitMsgElem(ctx, pm, payloadSize, CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE);
		CWProtocolStore16(pm, (unsigned short)msgType);
		CWProtocolStore8(pm, (unsigned char)wumPtr->type);
		if (wumPtr->type == WTP_UPDATE_REQUEST) {
			CWProtocolStore8(pm, wumPtr->_major_v_);
			CWProtocolStore8(pm, wumPtr->_minor_v_);
			CWProtocolStore8(pm, wumPtr->_revision_v_);
			CWProtocolStore32(pm, wumPtr->_pack_size_);
		} else if (wumPtr->type == WTP_CUP_FRAGMENT) {
			CWProtocolStore32(pm, wumPtr->_seq_num_);
			CWProtocolStore32(pm, wumPtr->_cup_fragment_size_);
			CWProtocolStoreRawBytes(pm, wumPtr->_cup_, wumPtr->_cup_fragment_size_);
			CW_FREE_OBJECT(wumPtr->_cup_);
		}
		CWFinalizeMsgElem(pm);
		break;
	default:
		return CW_FALSE;
		break;
	}

	CWLog("Assembling Protocol Configuration Update Request [VENDOR CASE]: Message Assembled.");
	return CW_TRUE;
}
