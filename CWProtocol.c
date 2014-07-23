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

#include "CWCommon.h"
#include "CWVendorPayloads.h"
#include "WUM.h"
pthread_mutex_t gRADIO_MAC_mutex;

static const int gCWIANATimes256 = CW_IANA_ENTERPRISE_NUMBER * 256;
static const int gMaxDTLSHeaderSize = 25;	// see http://crypto.stanford.edu/~nagendra/papers/dtls.pdf
static const int gMaxCAPWAPHeaderSize = 8;	// note: this include optional Wireless field
unsigned char gRADIO_MAC[6];			// note: this include optional Wireless field

CWBool CWMessageEnsureSpace(const void *ctx, CWProtocolMessage *pm, size_t size)
{
	if (sizeof(CWProtocolMessage) + pm->pos + size > pm->space) {
		pm->space = RND_TO(sizeof(CWProtocolMessage) + pm->pos + size, MSG_BLOCK_SIZE);
		pm->data = reralloc_size(ctx, pm->data, pm->space);
		if (!pm->data)
			return CW_FALSE;
		CW_ZERO_MEMORY(pm->data + pm->pos, pm->space - pm->pos);
	}
	return CW_TRUE;
}

/**
 * retrieves a string (not null-terminated) from the message, increments the current offset in bytes.
 * Adds the '\0' char at the end of the string which is returned
 */
char *CWProtocolRetrieveStr(const void *ctx, CWProtocolMessage *pm, int len)
{
	char *str;

	if (!(str = ralloc_strndup(ctx, (char *)pm->data + pm->pos, len)))
		return NULL;

	pm->pos += len;
	return str;
}

/**
 * retrieves len bytes from the message, increments the current offset in bytes.
 */
unsigned char *CWProtocolRetrieveRawBytes(const void *ctx, CWProtocolMessage *pm, int len)
{
	unsigned char *bytes;

	if (!(bytes = ralloc_memdup(ctx, pm->data + pm->pos, len)))
		return NULL;

	pm->pos += len;
	return bytes;
}

/**
 * retrieves len bytes from the message, increments the current offset in bytes.
 */
void CWProtocolCopyRawBytes(void *dest, CWProtocolMessage *pm, int len)
{
	CW_COPY_MEMORY(dest, pm->data + pm->pos, len);
	pm->pos += len;
}

void CWProtocolDestroyMsgElemData(void *f)
{
	CW_FREE_OBJECT(f);
}

CWBool CWAssembleVendorMsgElemResultCodeWithPayload(const void *ctx, CWProtocolMessage *pm,
						    CWProtocolResultCode code,
						    CWProtocolVendorSpecificValues * payload)
{
	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	int payloadSize = 0;

	CWVendorUciValues *uciPayload = NULL;
	CWVendorWumValues *wumPayload = NULL;

	switch (payload->vendorPayloadType) {
	case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_UCI:
		uciPayload = (CWVendorUciValues *) payload->payload;
		if (uciPayload->response != NULL)
			payloadSize = (strlen(uciPayload->response) * sizeof(unsigned char));
		break;
	case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_WUM:
		wumPayload = (CWVendorWumValues *) payload->payload;
		payloadSize = sizeof(unsigned char);	/* default, only type */
		if (wumPayload->type == WTP_VERSION_RESPONSE)
			payloadSize = sizeof(unsigned char) * 4;
		break;
	}

	CWInitMsgElem(ctx, pm, 4 + 8 + payloadSize, CW_MSG_ELEMENT_RESULT_CODE_CW_TYPE);

	CWProtocolStore32(pm, code);
	//  CWDebugLog("Result Code: %d", code);

	switch (payload->vendorPayloadType) {
	case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_UCI:
		/*Store what type of payload we have */
		CWProtocolStore16(pm, CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE);
		/*Store what type of vendor payload we have */
		CWProtocolStore16(pm, CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_UCI);
		/*Store payload size */
		CWProtocolStore32(pm, payloadSize);
		if (uciPayload->response != NULL)
			/*Store the payload */
			CWProtocolStoreStr(pm, uciPayload->response);
		break;

	case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_WUM:
		/* Store what type of payload we have */
		CWProtocolStore16(pm, CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE);
		/* Store what type of vendor payload we have */
		CWProtocolStore16(pm, CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_WUM);
		/* Store payload size */
		CWProtocolStore32(pm, payloadSize);

		CWProtocolStore8(pm, wumPayload->type);

		if (wumPayload->type == WTP_VERSION_RESPONSE) {
			CWProtocolStore8(pm, wumPayload->_major_v_);
			CWProtocolStore8(pm, wumPayload->_minor_v_);
			CWProtocolStore8(pm, wumPayload->_revision_v_);
		}
		break;
	}

	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemResultCode(const void *ctx, CWProtocolMessage *pm, CWProtocolResultCode code)
{
	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CWInitMsgElem(ctx, pm, 4, CW_MSG_ELEMENT_RESULT_CODE_CW_TYPE);
	CWProtocolStore32(pm, code);
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

/**
 * Assemble a CAPWAP Control Packet, with the given Message Elements, Sequence Number and Message Type.
 * Create Transport and Control Headers.
 *
 * completeMsgPtr is an array of fragments (can be of size 1 if the packet doesn't need fragmentation
 */
CWBool CWAssembleMessage(CWTransportMessage *tm, int PMTU, CWProtocolMessage *msg)
{
	return CWAssembleDataMessage(tm, PMTU, 1, BINDING_IEEE_802_11, CW_FALSE, CW_FALSE, NULL, NULL, msg);
#if 0
	size_t frag_size;
	unsigned int i;
	unsigned int frag_id = 0, is_frag = 0;
	CWProtocolMessage *m;

	assert(tm != NULL);
	assert(msg != NULL);
	assert(msg->level == 0);

	CWDebugLog("PMTU: %d", PMTU);

	frag_size = msg->pos;
	tm->count = 1;

	/* handle fragmentation */
	if (PMTU > gMaxDTLSHeaderSize + gMaxCAPWAPHeaderSize) {
		frag_size = ((PMTU - gMaxDTLSHeaderSize - gMaxCAPWAPHeaderSize) / 8) * 8;
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

		if (!CWInitTransportMessagePart(m, m + i, flen, is_frag, last, frag_id, offs / 8)) {
			CWReleaseTransportMessage(tm);
			return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
		}
		/*
		 * optional fields.....
		 */
		CWProtocolStoreRawBytes(m + i, msg->data + offs, flen);
		CWFinalizeTransportMessagePart(m + i);

		CWDebugLog("Fragment #:%d, offset:%zd, bytes stored:%zd/%zd", i, offs, flen, msg->pos);
	}
	return CW_TRUE;
#endif
}

#define THDR_ROOM  64
#define FRGMT_BUFFER (3 * 1024)
#define FRGMT_MAX 16

#define in_range_s(v, start, end)		\
	(((v) >= (start)) && ((v) < (end)))
#define in_range_e(v, start, end)		\
	(((v) > (start)) && ((v) <= (end)))

#define overlap(s1, e1, s2, e2)					\
	(in_range_s(s1, s2, e2) || in_range_e(e1, s2, e2) ||	\
	 in_range_s(s2, s1, e1) || in_range_e(e2, s1, e1))

static
CWBool CWAddFragment(CWFragmentBuffer *b, CWProtocolMessage *pm)
{
	int i;
	unsigned int start = CWTransportHeaderFragmentOffset(pm) * 8;
	unsigned int end = start + (pm->space - pm->pos);

	if (end > FRGMT_BUFFER)
		return CW_FALSE;

	printf("CWAddFragment: New start: %d, end: %d\n", start, end);
	for (i = 0; i < b->count; i++)
		printf("   before:[%2d]: %8d/%8d\n", i, b->parts[i].start, b->parts[i].end);
	printf("\nAction: ");

	for (i = 0; i < b->count; i++) {
		if (overlap(b->parts[i].start, b->parts[i].end, start, end)) {
			printf("skip due to overlap\n");
			return CW_FALSE;
		}

		if (b->parts[i].end == start) {
			/* append to current fragment */
			printf("append to current fragment\n");
			b->parts[i].end = end;

			if (i + 1 < b->count)
				if (b->parts[i].end == b->parts[i + 1].start) {
					/* merge current to next fragment */
					printf("merge current to next fragment\n");
					b->parts[i].end = b->parts[i + 1].end;
					b->count--;

					if (i + 1 < b->count)
						memmove(&b->parts[i + 1], &b->parts[i + 2], sizeof(b->parts[i]) * (b->count - (i + 2)));
				}
			break;
		}
		else if (b->parts[i].start == end) {
			/* prepend to current fragment */
			printf("prepend to current fragment\n");
			b->parts[i].start = start;

			break;
		}
		else if (b->parts[i].start > start) {
			/* insert before */
			printf("insert before current fragment\n");
			if (b->count >= FRGMT_MAX)
				return CW_FALSE;

			memmove(&b->parts[i + 1], &b->parts[i], sizeof(b->parts[i]) * (b->count - i));
			b->parts[i].start = start;
			b->parts[i].end = end;
			b->count++;

			break;
		}
	}
	if (i == b->count) {
		printf("append to list\n");
		if (b->count >= FRGMT_MAX)
			return CW_FALSE;

		b->parts[i].start = start;
		b->parts[i].end = end;
		b->count++;
	}

	printf("\n");
	for (i = 0; i < b->count; i++)
		printf("   before:[%2d]: %8d/%8d\n", i, b->parts[i].start, b->parts[i].end);
	printf("\n");

	if (CWTransportHeaderIsLast(pm))
		b->length = end;

	if (start == 0) {
		if (pm->pos > THDR_ROOM)
			/* make sure the transport header fits the reserved space */
			return CW_FALSE;

		/* first packet - take everything, including the transport header */
		b->start = THDR_ROOM - pm->pos;
		memcpy(b->data + b->start, pm->data, pm->space);
	} else
		/* fragment - only take the payload */
		memcpy(b->data + THDR_ROOM + start, pm->data + pm->pos, end - start);

	return CW_TRUE;
}

/*
 * parse a sigle fragment. If it is the last fragment we need or the only fragment, return the reassembled message in
 * *reassembleMsg. If we need at lest one more fragment, save this fragment in the buffer. You then call this function again
 * with a new fragment and the same buffer until we got all the fragments.
 */
CWBool CWProtocolParseFragment(CWProtocolMessage *msg, CWFragmentBufferList* frag_buffer, CWProtocolMessage *pm)
{
	assert(msg != NULL);
	assert(frag_buffer != NULL);
	assert(pm != NULL);

	if (!CWParseInitTransportHeader(msg)) {
		CWDebugLog("CWParseTransportHeader failed");
		return CW_FALSE;
	}

	if (!CWTransportHeaderIsFragment(msg)) {	// single fragment
		/* consume msg */
		if (!msg->is_static) {
			ralloc_steal(NULL, msg->data);
			CWInitTransportMessage(pm, msg->data, msg->space, 0);
		} else {
			unsigned char *buf;

			buf = ralloc_memdup(NULL, msg->data, msg->space);
			CWInitTransportMessage(pm, buf, msg->space, 0);
		}

#ifdef HAVE_VALGRIND_MEMCHECK_H
		VALGRIND_MAKE_MEM_UNDEFINED(msg, sizeof(CWProtocolMessage));
#endif
	} else {
		CWFragmentBuffer *b;
		CWBool done;
		unsigned int base = frag_buffer->base;
		unsigned int frag_id = CWTransportHeaderFragmentId(msg);

		CWDebugLog("Received Fragment ID:%d, offset:%d, notLast:%d",
			   CWTransportHeaderFragmentId(msg),
			   CWTransportHeaderFragmentOffset(msg) * 8,
			   CWTransportHeaderIsLast(msg));

		if (base > 0x8000 && frag_id < (base - 0x8000))
			/* 16bit wrap */
			frag_id += 0x10000;

		CWDebugLog("Fragment Buffer: base: %d, Id: %d", base, frag_id);

		if (frag_id < base) {
			/* fragment to old */
			CWDebugLog("Fragment too old");
			return CW_FALSE;
		}

		if (frag_id - base > MAX_FRAGMENTS)
			base = frag_id - MAX_FRAGMENTS;

		b = frag_buffer->slot + frag_id % MAX_FRAGMENTS;
		if (b->fragment_id != CWTransportHeaderFragmentId(msg)) {
			ralloc_free(b->data);
			CW_ZERO_MEMORY(b, sizeof(CWFragmentBuffer));
		}
		if (!b->data)
			if (!(b->data = rzalloc_size(NULL, FRGMT_BUFFER)))
				CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

		b->fragment_id = CWTransportHeaderFragmentId(msg);

		done = CWAddFragment(b, msg);
		CWReleaseMessage(msg);

		if (!done || b->length == 0 || b->count  != 1 ||
		    b->parts[0].start != 0 || b->parts[0].end != b->length)
			/* we need at least one mpre fragment */
			return CWErrorRaise(CW_ERROR_NEED_RESOURCE, NULL);

		CWInitTransportMessage(pm, b->data, b->parts[0].end, 0);
		pm->pos = b->start;
		ralloc_steal(NULL, b->data);

		/* nuke the old buffer and advance base fragment id */
		CW_ZERO_MEMORY(b, sizeof(CWFragmentBuffer));
		if (frag_buffer->base == b->fragment_id)
			frag_buffer->base++;
	}

	return CW_TRUE;
}

CWBool CWParseTransportHeader(CWProtocolMessage *pm, CWProtocolTransportHeaderValues *th, unsigned char *RadioMAC)
{
       assert(pm != NULL);
       assert(th != NULL);

       if (pm->space - pm->pos < sizeof(CWTransportHeader))
	       return CW_FALSE;

       pm->start[pm->level++] = pm->pos;
       pm->pos += sizeof(CWTransportHeader);         /* skip fixed header part */

       if (CWTransportHeaderVersion(pm) != CW_PROTOCOL_VERSION)
               return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Wrong Protocol Version");
       CWDebugLog("VERSION: %d", CWTransportHeaderVersion(pm));

       if (CWTransportHeaderMFlag(pm)) {
	       unsigned char length;

	       length = CWProtocolRetrieve8(pm);
	       if (length != 6)
		       return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Invalid MAC length");

	       if (RadioMAC)
		       CWProtocolCopyRawBytes(RadioMAC, pm, length);
	       else
		       pm->pos += length;

	       CWMessageAlignTo(pm, 4);
       }

       if (CWTransportHeaderWFlag(pm))
	       th->bindingValuesPtr = CWParseTransportHeaderBinding(pm);

       if (pm->pos - pm->start[0] != CWTransportHeaderHeaderLen(pm) * 4)
	       return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Invalid Header");

       return CW_TRUE;
}

// Parse Control Header
CWBool CWParseControlHeader(CWProtocolMessage *pm, CWControlHeaderValues * valPtr)
{
	unsigned char flags;

	if (pm == NULL || valPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	valPtr->messageTypeValue = CWProtocolRetrieve32(pm);
	valPtr->seqNum = CWProtocolRetrieve8(pm);
	valPtr->msgElemsLen = CWProtocolRetrieve16(pm);
	if ((flags = CWProtocolRetrieve8(pm)) != 0)			/* Flags, should be 0 */
		CWLog("CWParseControlHeader, Flags should be 0 (zero), actual value: %02x", flags);

#if 0
	CWDebugLog("Parse Control Header");
	CWDebugLog("MESSAGE_TYPE: %u",  valPtr->messageTypeValue);
	CWDebugLog("SEQUENCE_NUMBER: %u", valPtr->seqNum );
	CWDebugLog("MESSAGE_ELEMENT_LENGTH: %u", valPtr->msgElemsLen );
	CWDebugLog("FLAGS: %u", flags);
	CWDebugLog(NULL);
#endif

	return CW_TRUE;
}

//## Assemble a Message Response containing a Failure (Unrecognized Message) Result Code
CWBool CWAssembleUnrecognizedMessageResponse(CWTransportMessage *tm, int PMTU,
					     int seqNum, int msgType)
{
	CWProtocolMessage msg;

	assert(tm);

	CWLog("Assembling Unrecognized Message Response...");
	if (!CWInitMessage(NULL, &msg, msgType, seqNum) ||
	    !CWAssembleMsgElemResultCode(NULL, &msg, CW_PROTOCOL_FAILURE_UNRECOGNIZED_REQ))
		goto cw_assemble_error;
	CWFinalizeMessage(&msg);

	if (!CWAssembleMessage(tm, PMTU, &msg))
		goto cw_assemble_error;

	CWLog("Unrecognized Message Response Assembled");
	return CW_TRUE;

 cw_assemble_error:
	CWReleaseMessage(&msg);
        return CW_FALSE;
}

CWBool CWAssembleMsgElemSessionID(const void *ctx, CWProtocolMessage *pm, unsigned char *sessionID)
{
	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CWInitMsgElem(ctx, pm, 16, CW_MSG_ELEMENT_SESSION_ID_CW_TYPE);
	CWProtocolStoreRawBytes(pm, sessionID, 16);
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWParseACName(const void *ctx, CWProtocolMessage *pm, int len, char **valPtr)
{
	CWParseMessageElementStart(pm);

	*valPtr = CWProtocolRetrieveStr(ctx, pm, len);
	if (valPtr == NULL)
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
//  CWDebugLog("AC Name:%s", *valPtr);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseWTPRadioAdminState(CWProtocolMessage *pm, int len, CWRadioAdminInfoValues * valPtr)
{
	CWParseMessageElementStart(pm);

	valPtr->ID = CWProtocolRetrieve8(pm);
	valPtr->state = CWProtocolRetrieve8(pm);
	//valPtr->cause = CWProtocolRetrieve8(pm);

//  CWDebugLog("WTP Radio Admin State: %d - %d - %d", valPtr->ID, valPtr->state, valPtr->cause);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseWTPRadioOperationalState(CWProtocolMessage *pm, int len, CWRadioOperationalInfoValues * valPtr)
{
	CWParseMessageElementStart(pm);

	valPtr->ID = CWProtocolRetrieve8(pm);
	valPtr->state = CWProtocolRetrieve8(pm);
	valPtr->cause = CWProtocolRetrieve8(pm);

//  CWDebugLog("WTP Radio Operational State: %d - %d - %d", valPtr->ID, valPtr->state, valPtr->cause);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseFormatMsgElem(CWProtocolMessage * completeMsg, unsigned short int *type, unsigned short int *len)
{
	*type = CWProtocolRetrieve16(completeMsg);
	*len = CWProtocolRetrieve16(completeMsg);
	return CW_TRUE;
}

CWBool CWParseResultCode(CWProtocolMessage *pm, int len, CWProtocolResultCode * valPtr)
{
	CWParseMessageElementStart(pm);

	*valPtr = CWProtocolRetrieve32(pm);
//  CWDebugLog("Result Code: %d",   *valPtr);

	return CWParseMessageElementEnd(pm, len);
}

void CWWTPResetRadioStatistics(WTPRadioStatisticsInfo * radioStatistics)
{
	radioStatistics->lastFailureType = UNKNOWN_TYPE;
	radioStatistics->resetCount = 0;
	radioStatistics->SWFailureCount = 0;
	radioStatistics->HWFailuireCount = 0;
	radioStatistics->otherFailureCount = 0;
	radioStatistics->unknownFailureCount = 0;
	radioStatistics->configUpdateCount = 0;
	radioStatistics->channelChangeCount = 0;
	radioStatistics->bandChangeCount = 0;
	radioStatistics->currentNoiseFloor = 0;
}

unsigned char *CWParseSessionID(CWProtocolMessage *pm, int len)
{
	return CWProtocolRetrieveRawBytes(NULL, pm, 16);
}

CWBool CWParseTPIEEE80211WLanHoldTime(CWProtocolMessage *pm, int len, unsigned short int * valPtr)
{
	CWParseMessageElementStart(pm);

	CWProtocolRetrieve8(pm);   // skip RADIO Id
	CWProtocolRetrieve8(pm);   // skip WLAN Id
	*valPtr = CWProtocolRetrieve16(pm);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseTPDataChannelDeadInterval(CWProtocolMessage *pm, int len, unsigned short int * valPtr)
{
	CWParseMessageElementStart(pm);

	*valPtr = CWProtocolRetrieve16(pm);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseTPACJoinTimeout(CWProtocolMessage *pm, int len, unsigned short int * valPtr)
{
	CWParseMessageElementStart(pm);

	*valPtr = CWProtocolRetrieve16(pm);

	return CWParseMessageElementEnd(pm, len);
}
