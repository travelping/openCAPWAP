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
#include "WTPipcHostapd.h"

struct ntp_time_t {
	uint32_t   second;
	uint32_t   fraction;
};

static inline void convert_ntp_time_into_unix_time(struct ntp_time_t *ntp, struct timeval *tv)
{
    tv->tv_sec = ntp->second - 0x83AA7E80; // the seconds from Jan 1, 1900 to Jan 1, 1970
    tv->tv_usec = (uint32_t)( (double)ntp->fraction * 1.0e6 / (double)(1LL<<32) );
}

static inline void convert_unix_time_into_ntp_time(struct timeval *tv, struct ntp_time_t *ntp)
{
    ntp->second = tv->tv_sec + 0x83AA7E80;
    ntp->fraction = (uint32_t)( (double)(tv->tv_usec+1) * (double)(1LL<<32) * 1.0e-6 );
}

/*____________________________________________________________________________*/
/*  *****************************___ASSEMBLE___*****************************  */
CWBool CWAssembleMsgElemACName(const void *ctx, CWProtocolMessage *pm)
{
	char *name;
	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	name = CWWTPGetACName();
	//  CWDebugLog("AC Name: %s", name);

	CWInitMsgElem(ctx, pm, strlen(name), CW_MSG_ELEMENT_AC_NAME_CW_TYPE);
	CWProtocolStoreStr(pm, name);
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemACNameWithIndex(const void *ctx, CWProtocolMessage *pm)
{
	CWACNamesWithIndex ACsinfo;
	int i;

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if (!CWWTPGetACNameWithIndex(&ACsinfo))
		return CW_FALSE;

	for (i = 0; i < ACsinfo.count; i++) {
		//      CWDebugLog("AC Name with index: %d - %s", ACsinfo.ACNameIndex[i].index, ACsinfo.ACNameIndex[i].ACName);
		CWInitMsgElem(ctx, pm, 1 + strlen(ACsinfo.ACNameIndex[i].ACName), CW_MSG_ELEMENT_AC_NAME_INDEX_CW_TYPE);
		CWProtocolStore8(pm, ACsinfo.ACNameIndex[i].index);	// ID of the AC
		CWProtocolStoreStr(pm, ACsinfo.ACNameIndex[i].ACName);	// name of the AC
		CWFinalizeMsgElem(pm);
	}

	CW_FREE_OBJECT(ACsinfo.ACNameIndex);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemDataTransferData(const void *ctx, CWProtocolMessage *pm, int data_type)
{
	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	char *debug_data = " #### DATA DEBUG INFO #### ";	//to be changed...

	CWInitMsgElem(ctx, pm, 2 + strlen(debug_data), CW_MSG_ELEMENT_DATA_TRANSFER_DATA_CW_TYPE);
	CWProtocolStore8(pm, data_type);
	CWProtocolStore8(pm, strlen(debug_data));
	CWProtocolStoreStr(pm, debug_data);
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemDiscoveryType(const void *ctx, CWProtocolMessage *pm)
{
	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	//  CWDebugLog("Discovery Type: %d", CWWTPGetDiscoveryType());
	CWInitMsgElem(ctx, pm, 1, CW_MSG_ELEMENT_DISCOVERY_TYPE_CW_TYPE);
	CWProtocolStore8(pm, CWWTPGetDiscoveryType());
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemLocationData(const void *ctx, CWProtocolMessage *pm)
{
	char *location;

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	location = CWWTPGetLocation();

	//  CWDebugLog("Location Data: %s", location);
	CWInitMsgElem(ctx, pm, strlen(location), CW_MSG_ELEMENT_LOCATION_DATA_CW_TYPE);
	CWProtocolStoreStr(pm, location);
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemStatisticsTimer(const void *ctx, CWProtocolMessage *pm)
{
	//  CWDebugLog("Statistics Timer: %d", CWWTPGetStatisticsTimer());
	CWInitMsgElem(ctx, pm, 2,  CW_MSG_ELEMENT_STATISTICS_TIMER_CW_TYPE);
	CWProtocolStore16(pm, CWWTPGetStatisticsTimer());
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemWTPBoardData(const void *ctx, CWProtocolMessage *pm)
{
	assert(pm != NULL);

	CWInitMsgElem(ctx, pm, 4, CW_MSG_ELEMENT_WTP_BOARD_DATA_CW_TYPE);
	CWProtocolStore32(pm, WTP_VENDOR_IANA_ENTERPRISE_NUMBER);
	if (!CWAssembleMsgElemWTPBoardData_User(ctx, pm))
		return CW_FALSE;
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemVendorSpecificPayload(const void *ctx, CWProtocolMessage *pm)
{
	const int VENDOR_ID_LENGTH = 4;	//Vendor Identifier is 4 bytes long
	const int ELEMENT_ID = 2;	//Type and Length of a TLV field is 4 byte long
	const int DATA_LEN = 2;
	int size = 0;
	int element_id_zero = 0;
	int data_zero = 0;

	assert(pm != NULL);

	//Calculate msg elem size
	size = VENDOR_ID_LENGTH + ELEMENT_ID + DATA_LEN;

	// create message
	CWInitMsgElem(ctx, pm, size, CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_BW_CW_TYPE);
	CWProtocolStore32(pm, WTP_VENDOR_IANA_ENTERPRISE_NUMBER);
	CWProtocolStore16(pm, element_id_zero);
	CWProtocolStore16(pm, data_zero);
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemWTPDescriptor(const void *ctx, CWProtocolMessage *pm)
{
	const int GENERIC_RADIO_INFO_LENGTH = 5;	//First 4 bytes for Max Radios, Radios In Use and Num Encryption Capability
	const int VENDOR_ID_LENGTH = 4;	//Vendor Identifier is 4 bytes long
	const int TLV_HEADER_LENGTH = 4;	//Type and Length of a TLV field is 4 byte long
	CWWTPEncryptCaps encc;
	CWWTPVendorInfos infos;
	int i, size = 0;

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	// get infos
	if (!CWWTPGetVendorInfos(&infos))
		return CW_FALSE;

	if (!CWWTPGetEncCapabilities(&encc)) {       // encryption capabilities
		CWWTPDestroyVendorInfos(&infos);
		return CW_FALSE;
	}

	//Calculate msg elem size
	size = GENERIC_RADIO_INFO_LENGTH;
	for (i = 0; i < encc.encryptCapsCount; i++)
		size += 3;

	for (i = 0; i < infos.vendorInfosCount; i++)
		size += (VENDOR_ID_LENGTH + TLV_HEADER_LENGTH + ((infos.vendorInfos)[i]).length);

	CWInitMsgElem(ctx, pm, size, CW_MSG_ELEMENT_WTP_DESCRIPTOR_CW_TYPE);
	CWProtocolStore8(pm, CWWTPGetMaxRadios());	// number of radios supported by the WTP
	CWProtocolStore8(pm, CWWTPGetRadiosInUse());	// number of radios present in the WTP
	CWProtocolStore8(pm, encc.encryptCapsCount);

	for (i = 0; i < encc.encryptCapsCount; i++) {
		CWProtocolStore8(pm, (encc.encryptCaps)[i].WBID & 0x1f);
		CWProtocolStore16(pm, (encc.encryptCaps)[i].encryptionCapabilities);
	}

	for (i = 0; i < infos.vendorInfosCount; i++) {
		CWProtocolStore32(pm, infos.vendorInfos[i].vendorIdentifier);
		CWProtocolStore16(pm, infos.vendorInfos[i].type);
		CWProtocolStore16(pm, infos.vendorInfos[i].length);
		CWProtocolStoreRawBytes(pm, (unsigned char *)infos.vendorInfos[i].valuePtr,
					infos.vendorInfos[i].length);

#if 0
		CWDebugLog("WTP Descriptor Vendor ID: %d", infos.vendorInfos[i].vendorIdentifier);
		CWDebugLog("WTP Descriptor Type: %d",      infos.vendorInfos[i].type);
		CWDebugLog("WTP Descriptor Length: %d",    infos.vendorInfos[i].length);
		CWDebugLog("WTP Descriptor Value: %s",     infos.vendorInfos[i].valuePtr);

		CWDebugLog("Vendor Info \"%d\" = %d - %d - %d", i, infos.vendorInfos[i].vendorIdentifier, infos.vendorInfos[i].type, infos.vendorInfos[i].length);
#endif
	}
	CWFinalizeMsgElem(pm);

	CWWTPDestroyVendorInfos(&infos);
	CWWTPDestroyEncCapabilities(&encc);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemWTPFrameTunnelMode(const void *ctx, CWProtocolMessage *pm)
{
	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	//  CWDebugLog("Frame Tunnel Mode: %d", CWWTPGetFrameTunnelMode());
	CWInitMsgElem(ctx, pm, 1, CW_MSG_ELEMENT_WTP_FRAME_TUNNEL_MODE_CW_TYPE);
	CWProtocolStore8(pm, CWWTPGetFrameTunnelMode());	// frame encryption
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemWTPIPv4Address(const void *ctx, CWProtocolMessage *pm)
{
	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	//  CWDebugLog("WTP IPv4 Address: %d", CWWTPGetIPv4Address());
	CWInitMsgElem(ctx, pm, 4, CW_MSG_ELEMENT_WTP_IPV4_ADDRESS_CW_TYPE);
	CWProtocolStore32(pm, CWWTPGetIPv4Address());
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemWTPMACType(const void *ctx, CWProtocolMessage *pm)
{

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	//  CWDebugLog("WTP MAC Type: %d", CWWTPGetMACType());
	CWInitMsgElem(ctx, pm, 1, CW_MSG_ELEMENT_WTP_MAC_TYPE_CW_TYPE);
	CWProtocolStore8(pm, CWWTPGetMACType());	// mode of operation of the WTP (local, split, ...)
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemWTPRadioInformation(const void *ctx, CWProtocolMessage *pm)
{
	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	unsigned char wtp_r_info;
	wtp_r_info = CWTP_get_WTP_Radio_Information();
	int radioID = 0;

	CWInitMsgElem(ctx, pm, 5, CW_MSG_ELEMENT_IEEE80211_WTP_RADIO_INFORMATION_CW_TYPE);
	CWProtocolStore8(pm, radioID);
	CWProtocolStore8(pm, 0);
	CWProtocolStore8(pm, 0);
	CWProtocolStore8(pm, 0);
	CWProtocolStore8(pm, wtp_r_info);
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

#if 0
/**
 * assemble IEEE 802.11 WTP Radio Information message element
 *
 * multi radio version - currently unsused
 */
CWBool CWAssembleMsgElemWTPRadioInformation(const void *ctx, CWProtocolMessage *pm)
{
     CWRadiosInformation infos;

    int i;

    if(pm == NULL)
	    return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

    CWDebugLog("Assemble WTP Radio Info");

    if(!CWWTPGetRadiosInformation(&infos))
        return CW_FALSE;

    for (i = 0; i < infos.radiosCount; i++) {
	    CWDebugLog("WTPRadioInformation: %d - %d", infos.radios[i].ID, infos.radios[i].type);
	    CWInitMsgElem(ctx, pm, 5, CW_MSG_ELEMENT_WTP_RADIO_INFO_CW_TYPE);
	    CWProtocolStore8(pm, infos.radios[i].ID);		 /* ID of the radio */
	    CWProtocolStore32(pm, infos.radios[i].type);	 /* type of the radio */
	    CWFinalizeMsgElem(pm);
    }

    CW_FREE_OBJECT(infos.radios);

    return CW_TRUE;
}
#endif

CWBool CWAssembleMsgElemSupportedRates(const void *ctx, CWProtocolMessage *pm)
{

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CWInitMsgElem(ctx, pm, 9, CW_MSG_ELEMENT_IEEE80211_SUPPORTED_RATES_CW_TYPE);

	unsigned char tmp_sup_rate[8];
	CWWTP_get_WTP_Rates(tmp_sup_rate);

	int radioID = 0;

	CWProtocolStore8(pm, radioID);
	CWProtocolStore8(pm, tmp_sup_rate[0]);
	CWProtocolStore8(pm, tmp_sup_rate[1]);
	CWProtocolStore8(pm, tmp_sup_rate[2]);
	CWProtocolStore8(pm, tmp_sup_rate[3]);
	CWProtocolStore8(pm, tmp_sup_rate[4]);
	CWProtocolStore8(pm, tmp_sup_rate[5]);
	CWProtocolStore8(pm, tmp_sup_rate[6]);
	CWProtocolStore8(pm, tmp_sup_rate[7]);

	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemMultiDomainCapability(const void *ctx, CWProtocolMessage *pm)
{

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CWInitMsgElem(ctx, pm, 8, CW_MSG_ELEMENT_IEEE80211_MULTI_DOMAIN_CAPABILITY_CW_TYPE);

	unsigned char tmp_mdc[6];
	CWWTP_get_WTP_MDC(tmp_mdc);

	int radioID = 0;

	CWProtocolStore8(pm, radioID);
	CWProtocolStore8(pm, 0);

	CWProtocolStore8(pm, tmp_mdc[0]);
	CWProtocolStore8(pm, tmp_mdc[1]);
	CWProtocolStore8(pm, tmp_mdc[2]);
	CWProtocolStore8(pm, tmp_mdc[3]);
	CWProtocolStore8(pm, tmp_mdc[4]);
	CWProtocolStore8(pm, tmp_mdc[5]);

	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemWTPName(const void *ctx, CWProtocolMessage *pm)
{
	char *name;

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	name = CWWTPGetName();

	CWInitMsgElem(ctx, pm, strlen(name), CW_MSG_ELEMENT_WTP_NAME_CW_TYPE);
	//  CWDebugLog("WTPName: %s", name);
	CWProtocolStoreStr(pm, name);
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemWTPOperationalStatistics(const void *ctx, CWProtocolMessage *pm, int radio)
{
	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if (radio < 0 || radio >= gRadiosInfo.radioCount)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CWInitMsgElem(ctx, pm, 4, CW_MSG_ELEMENT_WTP_OPERAT_STATISTICS_CW_TYPE);
	CWProtocolStore8(pm, radio);
	CWProtocolStore8(pm, gRadiosInfo.radiosInfo[radio].TxQueueLevel);
	CWProtocolStore16(pm, gRadiosInfo.radiosInfo[radio].wirelessLinkFramesPerSec);

	//  CWDebugLog("");
	//  CWDebugLog("WTPOperationalStatistics of radio \"%d\": %d - %d", radio,gRadiosInfo.radiosInfo[radio].TxQueueLevel,  gRadiosInfo.radiosInfo[radio].wirelessLinkFramesPerSec);
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemWTPRadioStatistics(const void *ctx, CWProtocolMessage *pm, int radio)
{
	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if (radio < 0 || radio > gRadiosInfo.radioCount)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CWInitMsgElem(ctx, pm, 20, CW_MSG_ELEMENT_WTP_RADIO_STATISTICS_CW_TYPE);
	CWProtocolStore8(pm, radio);
	CWProtocolStore8(pm, gRadiosInfo.radiosInfo[radio].statistics.lastFailureType);
	CWProtocolStore16(pm, gRadiosInfo.radiosInfo[radio].statistics.resetCount);
	CWProtocolStore16(pm, gRadiosInfo.radiosInfo[radio].statistics.SWFailureCount);
	CWProtocolStore16(pm, gRadiosInfo.radiosInfo[radio].statistics.HWFailuireCount);
	CWProtocolStore16(pm, gRadiosInfo.radiosInfo[radio].statistics.otherFailureCount);
	CWProtocolStore16(pm, gRadiosInfo.radiosInfo[radio].statistics.unknownFailureCount);
	CWProtocolStore16(pm, gRadiosInfo.radiosInfo[radio].statistics.configUpdateCount);
	CWProtocolStore16(pm, gRadiosInfo.radiosInfo[radio].statistics.channelChangeCount);
	CWProtocolStore16(pm, gRadiosInfo.radiosInfo[radio].statistics.bandChangeCount);
	CWProtocolStore16(pm, gRadiosInfo.radiosInfo[radio].statistics.currentNoiseFloor);

#if 0
	CWDebugLog("");
	CWDebugLog("WTPRadioStatistics of radio: \"%d\"", radio);
	CWDebugLog("WTPRadioStatistics(1): %d - %d - %d",
		   gRadiosInfo.radiosInfo[radio].statistics.lastFailureType,
		   gRadiosInfo.radiosInfo[radio].statistics.resetCount,
		   gRadiosInfo.radiosInfo[radio].statistics.SWFailureCount);
	CWDebugLog("WTPRadioStatistics(2): %d - %d - %d",
		   gRadiosInfo.radiosInfo[radio].statistics.HWFailuireCount,
		   gRadiosInfo.radiosInfo[radio].statistics.otherFailureCount,
		   gRadiosInfo.radiosInfo[radio].statistics.unknownFailureCount);
	CWDebugLog("WTPRadioStatistics(3): %d - %d - %d - %d",
		   gRadiosInfo.radiosInfo[radio].statistics.configUpdateCount,
		   gRadiosInfo.radiosInfo[radio].statistics.channelChangeCount,
		   gRadiosInfo.radiosInfo[radio].statistics.bandChangeCount,
		   gRadiosInfo.radiosInfo[radio].statistics.currentNoiseFloor);
#endif
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemWTPRebootStatistics(const void *ctx, CWProtocolMessage *pm)
{
	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CWInitMsgElem(ctx, pm, 15, CW_MSG_ELEMENT_WTP_REBOOT_STATISTICS_CW_TYPE);
	CWProtocolStore16(pm, gWTPRebootStatistics.rebootCount);
	CWProtocolStore16(pm, gWTPRebootStatistics.ACInitiatedCount);
	CWProtocolStore16(pm, gWTPRebootStatistics.linkFailurerCount);
	CWProtocolStore16(pm, gWTPRebootStatistics.SWFailureCount);
	CWProtocolStore16(pm, gWTPRebootStatistics.HWFailuireCount);
	CWProtocolStore16(pm, gWTPRebootStatistics.otherFailureCount);
	CWProtocolStore16(pm, gWTPRebootStatistics.unknownFailureCount);
	CWProtocolStore8(pm, gWTPRebootStatistics.lastFailureType);

#if 0
	CWDebugLog("");
	CWDebugLog("WTPRebootStat(1): %d - %d - %d",
		   gWTPRebootStatistics.rebootCount,
		   gWTPRebootStatistics.ACInitiatedCount,
		   gWTPRebootStatistics.linkFailurerCount);
	CWDebugLog("WTPRebootStat(2): %d - %d - %d",
		   gWTPRebootStatistics.SWFailureCount,
		   gWTPRebootStatistics.HWFailuireCount,
		   gWTPRebootStatistics.otherFailureCount);
	CWDebugLog("WTPRebootStat(3): %d - %d",
		   gWTPRebootStatistics.unknownFailureCount,
		   gWTPRebootStatistics.lastFailureType);
#endif
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

//test version
CWBool CWAssembleMsgElemDuplicateIPv4Address(const void *ctx, CWProtocolMessage *pm)
{
	unsigned char macAddress[6] = {103, 204, 204, 190, 180, 0};

	//  CWDebugLog("");
	//  CWDebugLog("Duplicate IPv4 Address: %d", CWWTPGetIPv4Address());

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CWInitMsgElem(ctx, pm, 11, CW_MSG_ELEMENT_DUPLICATE_IPV4_ADDRESS_CW_TYPE);
	CWProtocolStore32(pm, CWWTPGetIPv4Address());
	CWProtocolStore8(pm, CWWTPGetIPv4StatusDuplicate());
	CWProtocolStore8(pm, 6);
	CWProtocolStoreRawBytes(pm, macAddress, 6);
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

//test version
CWBool CWAssembleMsgElemDuplicateIPv6Address(const void *ctx, CWProtocolMessage *pm)
{
	unsigned char macAddress[6] = {103, 204, 204, 190, 180, 0};
	struct sockaddr_in6 myAddr;

	//  CWDebugLog("");
	//  CWDebugLog("Duplicate IPv6 Address");

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CWWTPGetIPv6Address(&myAddr);

	CWInitMsgElem(ctx, pm, 23, CW_MSG_ELEMENT_DUPLICATE_IPV6_ADDRESS_CW_TYPE);
	CWProtocolStoreRawBytes(pm, (unsigned char *)myAddr.sin6_addr.s6_addr, 16);
	CWProtocolStore8(pm, CWWTPGetIPv6StatusDuplicate());
	CWProtocolStore8(pm, 6);
	CWProtocolStoreRawBytes(pm, macAddress, 6);
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemRadioAdminState(const void *ctx, CWProtocolMessage *pm)
{
	CWRadiosAdminInfo infos;
	int i;

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if (!CWGetWTPRadiosAdminState(&infos))
		return CW_FALSE;

	for (i = 0; i < infos.radiosCount; i++) {
		//      CWDebugLog("Radio Admin State: %d - %d - %d", infos.radios[i].ID, infos.radios[i].state, infos.radios[i].cause);
		CWInitMsgElem(ctx, pm, 2, CW_MSG_ELEMENT_RADIO_ADMIN_STATE_CW_TYPE);
		CWProtocolStore8(pm, infos.radios[i].ID);	// ID of the radio
		CWProtocolStore8(pm, infos.radios[i].state);	// state of the radio
		CWFinalizeMsgElem(pm);
	}

	CW_FREE_OBJECT(infos.radios);

	return CW_TRUE;
}

//if radioID is negative return Radio Operational State for all radios
CWBool CWAssembleMsgElemRadioOperationalState(const void *ctx, int radioID, CWProtocolMessage *pm)
{
	CWRadiosOperationalInfo infos;
	int i;

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if (!CWGetWTPRadiosOperationalState(radioID, &infos))
		return CW_FALSE;

	for (i = 0; i < infos.radiosCount; i++) {
		//      CWDebugLog("Radio Operational State: %d - %d - %d", infos.radios[i].ID, infos.radios[i].state, infos.radios[i].cause);
		CWInitMsgElem(ctx, pm, 3, CW_MSG_ELEMENT_RADIO_OPERAT_STATE_CW_TYPE);
		CWProtocolStore8(pm, infos.radios[i].ID);	// ID of the radio
		CWProtocolStore8(pm, infos.radios[i].state);	// state of the radio
		CWProtocolStore8(pm, infos.radios[i].cause);
		CWFinalizeMsgElem(pm);
	}

	CW_FREE_OBJECT(infos.radios);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemDecryptErrorReport(const void *ctx, CWProtocolMessage *pm, int radioID)
{
	int decrypy_Error_Report_Length = 0;
	CWDecryptErrorReportInfo infos;
	int i;

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if (!(CWGetDecryptErrorReport(radioID, &infos))) {
		return CW_FALSE;
	}

	for (i = 0; i < infos.radiosCount; i++) {
		//      CWDebugLog("Radio Decrypt Error Report of radio \"%d\" = %d", infos.radios[i].ID, infos.radios[i].numEntries);
		decrypy_Error_Report_Length = 2 + sizeof(CWMACAddress) * (infos.radios[i].numEntries);

		CWInitMsgElem(ctx, pm, decrypy_Error_Report_Length, CW_MSG_ELEMENT_CW_DECRYPT_ER_REPORT_CW_TYPE);
		CWProtocolStore8(pm, infos.radios[i].ID);               // ID of the radio
		CWProtocolStore8(pm, infos.radios[i].numEntries);       // state of the radio
		CWProtocolStore8(pm, (unsigned char)sizeof(CWMACAddress) * (infos.radios[i].numEntries));
		CWProtocolStoreRawBytes(pm, (unsigned char *)*(infos.radios[i].decryptErrorMACAddressList),
					sizeof(CWMACAddress) * (infos.radios[i].numEntries));

		/*
		   CWDebugLog("###numEntries = %d", infos.radios[i].numEntries);
		   CWDebugLog("j = %d", sizeof(CWMACAddress)*(infos.radios[i].numEntries));

		   int j;
		   for (j=(sizeof(CWMACAddress)*(infos.radios[i].numEntries)); j>0; j--)
		   CWDebugLog("##(%d/6) = %d", j, msgs[i].msg[(msgs[i].offset)-j]);
		 */
		CWFinalizeMsgElem(pm);
	}

	CW_FREE_OBJECT(infos.radios);

	return CW_TRUE;

}

CWBool CWAssembleMsgElemVendorTPWTPTimestamp(const void *ctx, CWProtocolMessage *pm, struct timeval *tv)
{
	struct ntp_time_t ntp_time;

	if (pm == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);


	convert_unix_time_into_ntp_time(tv, &ntp_time);

	CWInitMsgElem(ctx, pm, 14, CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_BW_CW_TYPE);
	CWProtocolStore32(pm, CW_IANA_ENTERPRISE_NUMBER_VENDOR_TRAVELPING);
	CWProtocolStore16(pm, CW_MSG_ELEMENT_TRAVELPING_WTP_TIMESTAMP);
	CWProtocolStore32(pm, ntp_time.second);
	CWProtocolStore32(pm, ntp_time.fraction);
	CWFinalizeMsgElem(pm);

	return CW_TRUE;
}

/*_________________________________________________________________________*/
/*  *****************************___PARSE___*****************************  */
CWBool CWParseWTPRadioInformation_FromAC(CWProtocolMessage *pm, int len, char *valPtr)
{
	//CWParseMessageElementStart(pm);

	CWProtocolRetrieve8(pm);

	CWProtocolRetrieve8(pm);
	CWProtocolRetrieve8(pm);
	CWProtocolRetrieve8(pm);
	*valPtr = CWProtocolRetrieve8(pm);
	return CW_TRUE;
	//return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseACDescriptor(const void *ctx, CWProtocolMessage *pm, int len, CWACInfoValues * valPtr)
{
	CWParseMessageElementStart(pm);

	valPtr->stations = CWProtocolRetrieve16(pm);
	valPtr->limit = CWProtocolRetrieve16(pm);
	valPtr->activeWTPs = CWProtocolRetrieve16(pm);
	valPtr->maxWTPs = CWProtocolRetrieve16(pm);
	valPtr->security = CWProtocolRetrieve8(pm);
	valPtr->RMACField = CWProtocolRetrieve8(pm);
	CWProtocolRetrieve8(pm);					/* Reserved */
	valPtr->DTLSPolicy = CWProtocolRetrieve8(pm);		/* DTLS Policy */

#if 0
	CWDebugLog("AC Descriptor Stations: %d",        valPtr->stations);
	CWDebugLog("AC Descriptor Limit: %d",           valPtr->limit);
	CWDebugLog("AC Descriptor Active WTPs: %d",     valPtr->activeWTPs);
	CWDebugLog("AC Descriptor Max WTPs: %d",        valPtr->maxWTPs);
	CWDebugLog("AC Descriptor Security: %d",        valPtr->security);
	CWDebugLog("AC Descriptor Radio MAC Field: %d", valPtr->RMACField);
	CWDebugLog("AC Descriptor Wireless Field: %d",  valPtr->security);
	CWDebugLog("AC Descriptor DTLS Policy: %d",     valPtr->DTLSPolicy);
#endif

	valPtr->vendorInfos.vendorInfosCount = 0;

	CWParseMessageElementWhile(pm, len) {
		CWACVendorInfoValues *vi;

		if ((valPtr->vendorInfos.vendorInfosCount % CW_BLOCK_ALLOC) == 0) {
			valPtr->vendorInfos.vendorInfos =
				reralloc(ctx, valPtr->vendorInfos.vendorInfos, CWACVendorInfoValues,
					 valPtr->vendorInfos.vendorInfosCount + CW_BLOCK_ALLOC);
		}
		if (!valPtr->vendorInfos.vendorInfos)
			return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

		vi = &valPtr->vendorInfos.vendorInfos[valPtr->vendorInfos.vendorInfosCount];

		vi->vendorIdentifier = CWProtocolRetrieve32(pm);
		vi->type = CWProtocolRetrieve16(pm);
		vi->length = CWProtocolRetrieve16(pm);
		vi->valuePtr = CWProtocolRetrieveRawBytes(valPtr, pm, vi->length);

		if (vi->valuePtr == NULL)
			return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

#if 0
		CWDebugLog("vendorInfosCount %d", valPtr->vendorInfos.vendorInfosCount);
		CWDebugLog("AC Descriptor Vendor ID: %d", vi->vendorIdentifier);
		CWDebugLog("AC Descriptor Type: %d", vi->type);
		CWDebugLog("AC Descriptor Length: %d", vi->length);
		CWDebugLog("AC Descriptor Value: %.*s", vi->length, vi->valuePtr);
#endif

		valPtr->vendorInfos.vendorInfosCount++;
	}

#if 0
	CWDebugLog("len %d", len);
	CWDebugLog("vendorInfosCount %d", valPtr->vendorInfos.vendorInfosCount);
#endif

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseACIPv4List(const void *ctx, CWProtocolMessage *pm, int len, ACIPv4ListValues * valPtr)
{
	int i;
	CWParseMessageElementStart(pm);

	if (len == 0 || ((len % 4) != 0))
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Malformed AC IPv4 List Messame Element");

	valPtr->ACIPv4ListCount = (len / 4);

	if (!(valPtr->ACIPv4List = ralloc_array(NULL, int, valPtr->ACIPv4ListCount)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	for (i = 0; i < valPtr->ACIPv4ListCount; i++) {
		struct sockaddr_in addr;
		(valPtr->ACIPv4List)[i] = CWProtocolRetrieve32(pm);
//      CWDebugLog("AC IPv4 List (%d): %d", i+1, (valPtr->ACIPv4List)[i]);
		addr.sin_addr.s_addr = (valPtr->ACIPv4List)[i];
		addr.sin_family = AF_INET;
		addr.sin_port = 1024;
		CWUseSockNtop(&addr, CWDebugLog("CWParseACIPv4List: %s", str); );
	}

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseACIPv6List(const void *ctx, CWProtocolMessage *pm, int len, ACIPv6ListValues * valPtr)
{
	int i;
	CWParseMessageElementStart(pm);

	if (len == 0 || ((len % 16) != 0))
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Malformed AC IPv6 List Messame Element");

	valPtr->ACIPv6ListCount = (len / 16);

	if (!(valPtr->ACIPv6List = ralloc_array(ctx, struct in6_addr, valPtr->ACIPv6ListCount)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	for (i = 0; i < valPtr->ACIPv6ListCount; i++) {
		struct sockaddr_in6 addr;

		/*
		 * BUG ML09
		 * 19/10/2009 - Donato Capitella
		 */
		void *ptr;
		ptr = CWProtocolRetrieveRawBytes(NULL, pm, 16);
		CW_COPY_MEMORY(&((valPtr->ACIPv6List)[i]), ptr, 16);
		CW_FREE_OBJECT(ptr);
		CW_COPY_MEMORY(&(addr.sin6_addr), &((valPtr->ACIPv6List)[i]), 16);
		addr.sin6_family = AF_INET6;
		addr.sin6_port = htons(CW_CONTROL_PORT);

//      CWUseSockNtop(&addr, CWDebugLog("AC IPv6 List: %s",str););
	}

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseDeleteStation(CWProtocolMessage *pm, int len)
{
	__attribute__ ((unused)) int radioID = 0;			/* TODO: support multiple radios */
	int Length = 0;

	CWParseMessageElementStart(pm);

	radioID = CWProtocolRetrieve8(pm);
	Length = CWProtocolRetrieve8(pm);

	unsigned char mac[Length + 1];
	CWProtocolCopyRawBytes(mac + 1, pm, Length);

	//CWDebugLog("radio ID %d",radioID);
	//CWDebugLog("Length of mac address field %d",Length);

	CWDebugLog("DEL MAC: %02X:%02X:%02X:%02X:%02X:%02X",
		   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	CWWTPsend_command_to_hostapd_DEL_ADDR(mac, 7);

	CWDebugLog("STATION'S MAC ADDRESS TO FORWARD TRAFFIC: %02X:%02X:%02X:%02X:%02X:%02X",
		   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseDeleteWLAN(CWProtocolMessage *pm, int len)
{
	CWParseMessageElementStart(pm);

	__attribute__((unused)) int radioID = CWProtocolRetrieve8(pm);			/* TODO: support multiple radios */
	__attribute__((unused)) int wlanID = CWProtocolRetrieve8(pm);			/* TODO: support multiple WLANs */

	unsigned char tmp_ssid[3] = {0, };
	CWWTPsend_command_to_hostapd_DEL_WLAN(tmp_ssid, 3);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseAddWLAN(CWProtocolMessage *pm, int len)
{
	unsigned char tmp_buf[len + 1];

	CWParseMessageElementStart(pm);

	CWProtocolCopyRawBytes(tmp_buf + 1, pm, 6);
	unsigned short keyLength = CWProtocolRetrieve16(pm);

	tmp_buf[7] = keyLength >> 8;
	tmp_buf[8] = keyLength & 0xff;

	if (keyLength)
		/* PSK */
		CWProtocolCopyRawBytes(tmp_buf + 9, pm, keyLength);

	tmp_buf[9 + keyLength] = CWProtocolRetrieve8(pm);
	tmp_buf[10 + keyLength] = CWProtocolRetrieve8(pm);
	tmp_buf[11 + keyLength] = CWProtocolRetrieve8(pm);
	tmp_buf[12 + keyLength] = CWProtocolRetrieve8(pm);
	tmp_buf[13 + keyLength] = CWProtocolRetrieve8(pm);
	tmp_buf[14 + keyLength] = CWProtocolRetrieve8(pm);

	tmp_buf[15 + keyLength] = CWProtocolRetrieve8(pm);

	tmp_buf[16 + keyLength] = CWProtocolRetrieve8(pm);			/* Auth Type */
	tmp_buf[17 + keyLength] = gWTPMACMode = CWProtocolRetrieve8(pm);	/* MAC Mode */
	tmp_buf[18 + keyLength] = gWTPTunnelMode = CWProtocolRetrieve8(pm);	/* Tunnel Mode */
	tmp_buf[19 + keyLength] = CWProtocolRetrieve8(pm);			/* Suppress SSID */

	/* SSID */
	CWProtocolCopyRawBytes(tmp_buf + 20 + keyLength, pm, len - (19 + keyLength));

	CWWTPsend_command_to_hostapd_ADD_WLAN(tmp_buf, len + 1);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseAddStation(CWProtocolMessage *pm, int len)
{
	__attribute__ ((unused)) int radioID = 0;			/* TODO: support multiple radios */
	int Length = 0;

	CWParseMessageElementStart(pm);

	radioID = CWProtocolRetrieve8(pm);
	Length = CWProtocolRetrieve8(pm);

	unsigned char mac[Length + 1];
	CWProtocolCopyRawBytes(mac + 1, pm, Length);

	//CWDebugLog("radio ID %d",radioID);
	//CWDebugLog("Length of mac address field %d",Length);

	CWDebugLog("ADD MAC: %02X:%02X:%02X:%02X:%02X:%02X",
		   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	CWWTPsend_command_to_hostapd_SET_ADDR(mac, 7);

	CWDebugLog("STATION'S MAC ADDRESS TO FORWARD TRAFFIC: %02X:%02X:%02X:%02X:%02X:%02X",
		   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	return CWParseMessageElementEnd(pm, len);
}


static void CWParseCWControlIPv4Address(CWProtocolMessage *pm, CWProtocolIPv4NetworkInterface * valPtr)
{
	valPtr->addr.sin_addr.s_addr = htonl(CWProtocolRetrieve32(pm));
	valPtr->addr.sin_family = AF_INET;
	valPtr->addr.sin_port = htons(CW_CONTROL_PORT);

	CWUseSockNtop((&(valPtr->addr)), CWDebugLog("Interface Address: %s", str); );

	valPtr->WTPCount = CWProtocolRetrieve16(pm);
	//  CWDebugLog("WTP Count: %d", valPtr->WTPCount);
}

CWBool CWParseCWControlIPv4Addresses(const void *ctx, CWProtocolMessage *pm, int len, CWACInfoValues *ACInfoPtr)
{
	CWParseMessageElementStart(pm);

	if ((ACInfoPtr->IPv4AddressesCount % CW_BLOCK_ALLOC) == 0) {
		ACInfoPtr->IPv4Addresses =
			reralloc(ctx, ACInfoPtr->IPv4Addresses, CWProtocolIPv4NetworkInterface,
				 ACInfoPtr->IPv4AddressesCount + CW_BLOCK_ALLOC);
	}
	if (!ACInfoPtr->IPv4Addresses)
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	CWParseCWControlIPv4Address(pm, &(ACInfoPtr->IPv4Addresses[ACInfoPtr->IPv4AddressesCount]));
	ACInfoPtr->IPv4AddressesCount++;

	return CWParseMessageElementEnd(pm, len);
}

static void CWParseCWControlIPv6Address(CWProtocolMessage *pm, CWProtocolIPv6NetworkInterface * valPtr)
{
	CWProtocolCopyRawBytes(&valPtr->addr.sin6_addr, pm, 16);
	valPtr->addr.sin6_family = AF_INET6;
	valPtr->addr.sin6_port = htons(CW_CONTROL_PORT);

	CWUseSockNtop((&(valPtr->addr)), CWDebugLog("Interface Address: %s", str); );

	valPtr->WTPCount = CWProtocolRetrieve16(pm);
	//  CWDebugLog("WTP Count: %d", valPtr->WTPCount);
}

CWBool CWParseCWControlIPv6Addresses(const void *ctx, CWProtocolMessage *pm, int len, CWACInfoValues *ACInfoPtr)
{
	CWParseMessageElementStart(pm);

	if ((ACInfoPtr->IPv6AddressesCount % CW_BLOCK_ALLOC) == 0) {
		ACInfoPtr->IPv6Addresses =
			reralloc(ctx, ACInfoPtr->IPv6Addresses, CWProtocolIPv6NetworkInterface,
				 ACInfoPtr->IPv6AddressesCount + CW_BLOCK_ALLOC);
	}
	if (!ACInfoPtr->IPv6Addresses)
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	CWParseCWControlIPv6Address(pm, &(ACInfoPtr->IPv6Addresses[ACInfoPtr->IPv6AddressesCount]));
	ACInfoPtr->IPv6AddressesCount++;

	return CWParseMessageElementEnd(pm, len);
}


CWBool CWParseCWTimers(CWProtocolMessage *pm, int len, CWTimersValues * valPtr)
{
	CWParseMessageElementStart(pm);

	valPtr->discoveryTimer = CWProtocolRetrieve8(pm);
//  CWDebugLog("Discovery Timer: %d", valPtr->discoveryTimer);
	valPtr->echoRequestTimer = CWProtocolRetrieve8(pm);
//  CWDebugLog("Echo Timer: %d", valPtr->echoRequestTimer);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseDecryptErrorReportPeriod(CWProtocolMessage *pm, int len, WTPDecryptErrorReportValues * valPtr)
{
	CWParseMessageElementStart(pm);

	valPtr->radioID = CWProtocolRetrieve8(pm);
	valPtr->reportInterval = CWProtocolRetrieve16(pm);
//  CWDebugLog("Decrypt Error Report Period: %d - %d", valPtr->radioID, valPtr->reportInterval);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseIdleTimeout(CWProtocolMessage *pm, int len, CWProtocolConfigureResponseValues * valPtr)
{
	CWParseMessageElementStart(pm);

	valPtr->idleTimeout = CWProtocolRetrieve32(pm);
//  CWDebugLog("Idle Timeout: %d", valPtr->idleTimeout);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseWTPFallback(CWProtocolMessage *pm, int len, CWProtocolConfigureResponseValues * valPtr)
{
	CWParseMessageElementStart(pm);

	valPtr->fallback = CWProtocolRetrieve8(pm);
//  CWDebugLog("WTP Fallback: %d", valPtr->fallback);

	return CWParseMessageElementEnd(pm, len);
}

CWBool CWParseVendorTPWTPTimestamp(CWProtocolMessage *pm, int len, struct timeval * valPtr)
{
	struct ntp_time_t ntp_time;

	CWDebugLog("WTP Timestamp: %d", len);
	CWParseMessageElementStart(pm);

	ntp_time.second = CWProtocolRetrieve32(pm);
	ntp_time.fraction = CWProtocolRetrieve32(pm);
	convert_ntp_time_into_unix_time(&ntp_time, valPtr);

	return CWParseMessageElementEnd(pm, len);
}

void CWWTPResetRebootStatistics(WTPRebootStatisticsInfo * rebootStatistics)
{
	rebootStatistics->rebootCount = 0;
	rebootStatistics->ACInitiatedCount = 0;
	rebootStatistics->linkFailurerCount = 0;
	rebootStatistics->SWFailureCount = 0;
	rebootStatistics->HWFailuireCount = 0;
	rebootStatistics->otherFailureCount = 0;
	rebootStatistics->unknownFailureCount = 0;
	rebootStatistics->lastFailureType = NOT_SUPPORTED;
}
