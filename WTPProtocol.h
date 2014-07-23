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

#ifndef __CAPWAP_WTPProtocol_HEADER__
#define __CAPWAP_WTPProtocol_HEADER__

#define WTP_VENDOR_IANA_ENTERPRISE_NUMBER CW_IANA_ENTERPRISE_NUMBER_VENDOR_TRAVELPING

/*_____________________________________________________*/
/*  *******************___TYPES___*******************  */
typedef struct {
	int ACIPv4ListCount;
	int *ACIPv4List;
} ACIPv4ListValues;

typedef struct {
	int ACIPv6ListCount;
	struct in6_addr *ACIPv6List;
} ACIPv6ListValues;

typedef struct {
	unsigned char priority;
	unsigned char type;
	unsigned char data[];
} CWProtocolACAddressListWithPrio;

typedef struct {
	int stations;
	int limit;
	int activeWTPs;
	int maxWTPs;
	CWAuthSecurity security;
	int RMACField;
//  int WirelessField;
	int DTLSPolicy;
	CWACVendorInfos vendorInfos;
	char *name;
	CWProtocolIPv4NetworkInterface *IPv4Addresses;
	int IPv4AddressesCount;
	CWProtocolIPv6NetworkInterface *IPv6Addresses;
	int IPv6AddressesCount;
	ACIPv4ListValues ACIPv4ListInfo;
	ACIPv6ListValues ACIPv6ListInfo;
	CWNetworkLev4Address preferredAddress;
	CWNetworkLev4Address incomingAddress;
} CWACInfoValues;

typedef struct {
	CWACInfoValues ACInfoPtr;
	CWProtocolResultCode code;
	ACIPv4ListValues ACIPv4ListInfo;
	ACIPv6ListValues ACIPv6ListInfo;
} CWProtocolJoinResponseValues;

typedef struct {
	ACIPv4ListValues ACIPv4ListInfo;
	ACIPv6ListValues ACIPv6ListInfo;
	int radioOperationalInfoCount;
	CWRadioOperationalInfoValues *radioOperationalInfo;
	WTPDecryptErrorReport radiosDecryptErrorPeriod;
	int idleTimeout;
	int fallback;
	void *bindingValues;
	CWTimersValues CWTimers;

	unsigned short int vendorTP_IEEE80211WLanHoldTime;
	unsigned short int vendorTP_DataChannelDeadInterval;
	unsigned short int vendorTP_ACJoinTimeout;
} CWProtocolConfigureResponseValues;

typedef struct {
	void *bindingValues;
	/*Update 2009:
	   add new non-binding specific values */
	void *protocolValues;
	uint32_t timeStamp;
	CWTimersValues CWTimers;

	unsigned short int vendorTP_IEEE80211WLanHoldTime;
	unsigned short int vendorTP_DataChannelDeadInterval;
	unsigned short int vendorTP_ACJoinTimeout;
} CWProtocolConfigurationUpdateRequestValues;

/*__________________________________________________________*/
/*  *******************___PROTOTYPES___*******************  */
CWBool CWAssembleMsgElemACName(const void *ctx, CWProtocolMessage *pm);                                    /*  4 */
CWBool CWAssembleMsgElemACNameWithIndex(const void *ctx, CWProtocolMessage *pm);                           /*  5 */
CWBool CWAssembleMsgElemDataTransferData(const void *ctx, CWProtocolMessage *pm, int data_type);           /* 13 */
CWBool CWAssembleMsgElemDiscoveryType(const void *ctx, CWProtocolMessage *pm);                             /* 20 */
CWBool CWAssembleMsgElemDuplicateIPv4Address(const void *ctx, CWProtocolMessage *pm);                      /* 21 */
CWBool CWAssembleMsgElemLocationData(const void *ctx, CWProtocolMessage *pm);                              /* 27 */
CWBool CWAssembleMsgElemStatisticsTimer(const void *ctx, CWProtocolMessage *pm);                           /* 33 */
CWBool CWAssembleMsgElemWTPBoardData(const void *ctx, CWProtocolMessage *pm);                              /* 35 */
CWBool CWAssembleMsgElemWTPDescriptor(const void *ctx, CWProtocolMessage *pm);                             /* 36 */
CWBool CWAssembleMsgElemWTPFrameTunnelMode(const void *ctx, CWProtocolMessage *pm);                        /* 38 */
CWBool CWAssembleMsgElemWTPIPv4Address(const void *ctx, CWProtocolMessage *pm);                            /* 39 */
CWBool CWAssembleMsgElemWTPMACType(const void *ctx, CWProtocolMessage *pm);                                /* 40 */
CWBool CWAssembleMsgElemWTPRadioInformation(const void *ctx, CWProtocolMessage *pm);                       /* 1048 */
CWBool CWAssembleMsgElemSupportedRates(const void *ctx, CWProtocolMessage *pm);                            /* 1040 */
CWBool CWAssembleMsgElemMultiDomainCapability(const void *ctx, CWProtocolMessage *pm);                     /* 1032 */
CWBool CWAssembleMsgElemWTPName(const void *ctx, CWProtocolMessage *pm);                                   /* 41 */
CWBool CWAssembleMsgElemWTPOperationalStatistics(const void *ctx, CWProtocolMessage *pm, int radio);       /* 42 */
CWBool CWAssembleMsgElemWTPRadioStatistics(const void *ctx, CWProtocolMessage *pm, int radio);             /* 43 */
CWBool CWAssembleMsgElemWTPRebootStatistics(const void *ctx, CWProtocolMessage *pm);                       /* 44 */
// CWBool CWAssembleMsgElemWTPStaticIPInfo(const void *ctx, CWProtocolMessage *msgPtr);                         /* 45 */

// CWBool CWAssembleMsgElemWTPRadioInformation(const void *ctx, CWProtocolMessage *msgPtr);

//---------------------------------------------------------/
CWBool CWParseACDescriptor(const void *ctx, CWProtocolMessage *pm, int len, CWACInfoValues * valPtr);	// 1
CWBool CWParseACIPv4List(const void *ctx, CWProtocolMessage *pm, int len, ACIPv4ListValues * valPtr);	// 2
CWBool CWParseACIPv6List(const void *ctx, CWProtocolMessage *pm, int len, ACIPv6ListValues * valPtr);	// 3
CWBool CWParseAddStation(CWProtocolMessage *pm, int len);	// 8
CWBool CWParseDeleteStation(CWProtocolMessage *pm, int len);	// 18
CWBool CWParseCWControlIPv4Addresses(const void *ctx, CWProtocolMessage *pm, int len, CWACInfoValues *ACInfoPtr);	//10
CWBool CWParseCWControlIPv6Addresses(const void *ctx, CWProtocolMessage *pm, int len, CWACInfoValues *ACInfoPtr);	//11
CWBool CWParseCWTimers(CWProtocolMessage *pm, int len, CWTimersValues * valPtr);	//12
CWBool CWParseDecryptErrorReportPeriod(CWProtocolMessage *pm, int len, WTPDecryptErrorReportValues * valPtr);	//16
CWBool CWParseIdleTimeout(CWProtocolMessage *pm, int len, CWProtocolConfigureResponseValues * valPtr);	//26
CWBool CWParseWTPFallback(CWProtocolMessage *pm, int len, CWProtocolConfigureResponseValues * valPtr);	//37
CWBool CWParseWTPRadioInformation_FromAC(CWProtocolMessage *pm, int len, char *valPtr);	// 1048

//si trova in CWProtocol.h
//CWBool CWParseACName(CWProtocolMessage *msgPtr, int len, char **valPtr);                      // 4
CWBool CWAssembleMsgElemVendorTPWTPTimestamp(const void *ctx, CWProtocolMessage *pm, struct timeval *tv);

//---------------------------------------------------------/
void CWWTPResetRebootStatistics(WTPRebootStatisticsInfo * rebootStatistics);

int CWWTPGetDiscoveryType(void);
int CWWTPGetMaxRadios(void);
int CWWTPGetRadiosInUse(void);
CWBool CWWTPGetEncCapabilities(CWWTPEncryptCaps * encc);
void CWWTPDestroyEncCapabilities(CWWTPEncryptCaps * encc);
CWBool CWAssembleMsgElemWTPBoardData_User(const void *ctx, CWProtocolMessage *pm);
CWBool CWWTPGetVendorInfos(CWWTPVendorInfos * valPtr);
int CWWTPGetMACType(void);
char *CWWTPGetLocation(void);
int CWWTPGetSessionID(void);
int CWWTPGetIPv4Address(void);
int CWWTPGetIPv4StatusDuplicate(void);
int CWWTPGetIPv6StatusDuplicate(void);
char *CWWTPGetName(void);
CWBool CWWTPGetRadiosInformation(CWRadiosInformation * valPtr);
int CWWTPGetACIndex();
char *CWWTPGetACName();
int CWWTPGetFrameTunnelMode();
CWBool CWGetWTPRadiosOperationalState(int radioID, CWRadiosOperationalInfo * valPtr);
CWBool CWAssembleMsgElemDecryptErrorReport(const void *ctx, CWProtocolMessage *pm, int radioID);
CWBool CWAssembleMsgElemDuplicateIPv6Address(const void *ctx, CWProtocolMessage *pm);
CWBool CWAssembleMsgElemVendorSpecificPayload(const void *ctx, CWProtocolMessage *pm);

CWBool CWParseAddWLAN(CWProtocolMessage *pm, int len);
CWBool CWParseDeleteWLAN(CWProtocolMessage *pm, int len);

CWBool CWParseVendorTPWTPTimestamp(CWProtocolMessage *pm, int len, struct timeval *tv);

//---------------------------------------------------------/
void CWWTPDestroyVendorInfos(CWWTPVendorInfos * valPtr);

#endif
