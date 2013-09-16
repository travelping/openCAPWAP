/************************************************************************************************
 * Copyright (c) 2006-2009 Laboratorio di Sistemi di Elaborazione e Bioingegneria Informatica   *
 *                          Universita' Campus BioMedico - Italy                                *
 *                                                                                              *
 * This program is free software; you can redistribute it and/or modify it under the terms      *
 * of the GNU General Public License as published by the Free Software Foundation; either       *
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
 * Authors : Ludovico Rossi (ludo@bluepixysw.com)                                               *
 *           Del Moro Andrea (andrea_delmoro@libero.it)                                         *
 *           Giovannini Federica (giovannini.federica@gmail.com)                                *
 *           Massimo Vellucci (m.vellucci@unicampus.it)                                         *
 *           Mauro Bisson (mauro.bis@gmail.com)                                                 *
 *           Antonio Davoli (antonio.davoli@gmail.com)                                          *
 ************************************************************************************************/

#include "CWCommon.h"

CWThreadMutex gWTPsMutex;

static const int gMaxDTLSHeaderSize = 25;	// see http://crypto.stanford.edu/~nagendra/papers/dtls.pdf
const int gMaxCAPWAPHeaderSizeBinding = 16;	// note: this include optional Wireless field

/*
 * Assemble a CAPWAP Data Packet creating Transport Header.
 */
CWBool CWAssembleDataMessage(CWTransportMessage *tm, int PMTU,
			     unsigned int rid, CWBindingProtocol wbid,
			     CWBool keepAlive, CWBool isNative, CWMAC *radio_mac,
			     CWBindingTransportHeaderValues *binding,
			     CWProtocolMessage *msg)
{
	size_t frag_size;
	unsigned int i;
	unsigned int frag_id = 0, is_frag = 0;
	CWProtocolMessage *m;

	assert(tm != NULL);
	assert(msg != NULL);

	CWDebugLog("PMTU: %d", PMTU);

	frag_size = msg->pos;
	tm->count = 1;

	/*
	 * handle fragmentation
	 *
	 * very small PMTU values are used as DONT FRAGMENT indication!
	 */
	if (PMTU > gMaxDTLSHeaderSize + gMaxCAPWAPHeaderSizeBinding) {
		frag_size = ((PMTU - gMaxDTLSHeaderSize - gMaxCAPWAPHeaderSizeBinding) / 8) * 8;
		tm->count = (msg->pos + frag_size - 1) / frag_size;
	}

	CWDebugLog("Aligned PMTU: %zd", frag_size);
	CWDebugLog("Fragments #: %d", tm->count);

	tm->parts = m = rzalloc_array(NULL, CWProtocolMessage, tm->count);
	if (!m)
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	if (tm->count > 1) {
		frag_id = CWGetFragmentID();
		is_frag = 1;
	}

	for (i = 0; i < tm->count; i++) {
		int last;
		size_t flen;
		size_t offs;

		offs = frag_size * i;
		flen = (frag_size * (i + 1) > msg->pos) ? msg->pos % frag_size : frag_size;
		last = (tm->count > 1 && i == tm->count - 1) ? 1 : 0;

		if (!CWInitTransportMessagePart(m, m + i, flen, rid, wbid, is_frag, last, frag_id, offs)) {
			CWReleaseTransportMessage(tm);
			return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
		}
		if (keepAlive)
			CWTransportMessageSetKeepAlive(m + i);
		if (isNative)
			CWTransportMessageSetNative(m + i);

		/* optional fields */
		if (radio_mac) {
			CWTransportMessageSetMFlag(m + i);
			CWProtocolStoreRawBytes(m + i, (void *)radio_mac, radio_mac->length + 1);
			CWMessageAlignTo(m + i, 4);
		}
		if (binding) {
			CWTransportMessageSetWFlag(m + i);
			CWProtocolStoreRawBytes(m + i, (void *)binding, binding->length + 1);
			CWMessageAlignTo(m + i, 4);
		}
		CWFinalizeTransportMessageHeader(m + i);

		if (keepAlive)
			CWProtocolStore16(m + i, msg->pos);

		/* message body */
		CWProtocolStoreRawBytes(m + i, msg->data + offs, flen);
		CWFinalizeTransportMessagePart(m + i);

		CWDebugLog("Fragment #:%d, offset:%zd, bytes stored:%zd/%zd", i, offs, flen, msg->pos);
	}

	CWReleaseMessage(msg);
	return CW_TRUE;
}

CWBool CWParseTransportHeaderMACAddress(CWProtocolMessage *pm, unsigned char *mac_ptr)
{
	assert(pm);

	unsigned char *vval;
	vval = ralloc_size(NULL, 7);

	//CWDebugLog("Parse Transport Header");
	int Mac_len = CWProtocolRetrieve8(pm);

	vval = (unsigned char *)CWProtocolRetrieveRawBytes(NULL, pm, 7);

	if (mac_ptr != NULL) {

		CWThreadMutexLock(&gWTPsMutex);
		memcpy(mac_ptr, vval, Mac_len);
		CWThreadMutexUnlock(&gWTPsMutex);

	}

	return CW_TRUE;
}

CWBindingTransportHeaderValues *CWParseTransportHeaderBinding(CWProtocolMessage *pm)
{
	CWBindingTransportHeaderValues *b;
	assert(pm != NULL);

	CWDebugLog("Parse Transport Header");

	b = (CWBindingTransportHeaderValues *)CWProtocolRetrievePtr(pm);
	if (CWProtocolRetrieve8(pm) != CW_BINDING_DATALENGTH) {
		CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Wrong Binding Data Field Length");
		return NULL;
	}

	CWProtocolRetrieve32(pm);
	CWMessageAlignTo(pm, 4);

	CWDebugLog("RSSI: %d", b->ieee80211.RSSI);
	CWDebugLog("SNR: %d", b->ieee80211.SNR);
	CWDebugLog("DATARATE: %d", ntohl(b->ieee80211.dataRate));

	/**
	 * For distinguish between the two types of "specials" data messages
	 * (QoS stats and Frequency Stats) we used the following values:
	 *      dataRate == 255 && SNR = 1 -> Frequency Stats Packet
	 *      dataRate == 255            -> QoS Stats Packet
	 */

	if (b->ieee80211.dataRate == 255) {
		if (b->ieee80211.SNR == 1)
			pm->data_msgType = CW_DATA_MSG_FREQ_STATS_TYPE;
		else
			pm->data_msgType = CW_DATA_MSG_STATS_TYPE;
	} else if (ntohl(b->ieee80211.dataRate) == 0)
		pm->data_msgType = CW_DATA_MSG_FRAME_TYPE;

	/* opencapwap did something strange here, Data Rate is a 16bit int, but it did
	   read it in two steps, maybe an oversight?

	valuesPtr->ieee80211.dataRate =
	    ((valuesPtr->ieee80211.dataRate) << 8) | CWGetField32(val, CW_TRANSPORT_HEADER_DATARATE_1_START,
							CW_TRANSPORT_HEADER_DATARATE_1_LEN);
	*/

	return b;
}
