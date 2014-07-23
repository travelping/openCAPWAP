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
 *
 * In addition, as a special exception, the copyright holders give permission to link the  *
 * code of portions of this program with the OpenSSL library under certain conditions as   *
 * described in each individual source file, and distribute linked combinations including  *
 * the two. You must obey the GNU General Public License in all respects for all of the    *
 * code used other than OpenSSL.  If you modify file(s) with this exception, you may       *
 * extend this exception to your version of the file(s), but you are not obligated to do   *
 * so.  If you do not wish to do so, delete this exception statement from your version.    *
 * If you delete this exception statement from all source files in the program, then also  *
 * delete it here.                                                                         *
 *
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

#ifndef __CAPWAP_ACProtocol_HEADER__
#define __CAPWAP_ACProtocol_HEADER__

//#define UNUSED_RADIO_ID   1000

typedef struct {
	char *locationData;
	char *name;
	unsigned char *sessionID;
	CWWTPDescriptor descriptor;
	struct sockaddr_in ipv4Address;

	CWWTPRadiosInfo radiosInfo;

	char *ACName;
	CWACNamesWithIndex ACNameIndex;
	CWRadiosAdminInfo radioAdminInfo;
	int StatisticsTimer;
	CWWTPVendorInfos WTPBoardData;
	//CWRadiosInformation WTPRadioInfo;
	WTPRebootStatisticsInfo *WTPRebootStatistics;

	void *bindingValuesPtr;
} CWWTPProtocolManager;

typedef struct {
	char *location;
	char *name;
	CWWTPVendorInfos WTPBoardData;
	unsigned char *sessionID;
	CWWTPDescriptor WTPDescriptor;
	struct sockaddr_in addr;
	CWframeTunnelMode frameTunnelMode;
	CWMACType MACType;

} CWProtocolJoinRequestValues;

typedef struct {
	char *ACName;
	CWACNamesWithIndex ACinWTP;
	int radioAdminInfoCount;
	CWRadioAdminInfoValues *radioAdminInfo;
	int StatisticsTimer;
	WTPRebootStatisticsInfo *WTPRebootStatistics;

} CWProtocolConfigureRequestValues;

typedef struct {
	CWRadiosOperationalInfo radioOperationalInfo;
	CWProtocolResultCode resultCode;
} CWProtocolChangeStateEventRequestValues;

typedef struct {
	unsigned int radioID;
	unsigned int TxQueueLevel;
	unsigned int wirelessLinkFramesPerSec;
} WTPOperationalStatisticsValues;

typedef struct {
	unsigned int radioID;
	WTPRadioStatisticsInfo WTPRadioStatistics;
} WTPRadioStatisticsValues;

typedef struct {
	int ipv4Address;
	unsigned int length;
	unsigned char *MACoffendingDevice_forIpv4;
	int status;
} WTPDuplicateIPv4;

typedef struct {
	struct in6_addr ipv6Address;
	unsigned int length;
	unsigned char *MACoffendingDevice_forIpv6;
	int status;
} WTPDuplicateIPv6;

typedef struct {
	int errorReportCount;
	CWDecryptErrorReportValues *errorReport;
	WTPDuplicateIPv4 *duplicateIPv4;
	WTPDuplicateIPv6 *duplicateIPv6;
	int WTPOperationalStatisticsCount;
	WTPOperationalStatisticsValues *WTPOperationalStatistics;
	int WTPRadioStatisticsCount;
	WTPRadioStatisticsValues *WTPRadioStatistics;
	WTPRebootStatisticsInfo *WTPRebootStatistics;
} CWProtocolWTPEventRequestValues;

typedef struct {

	int data;
	int length;
	char *debug_info;
} CWProtocolWTPDataTransferRequestValues;

/*__________________________________________________________*/
/*  *******************___PROTOTYPES___*******************  */
CWBool CWAssembleChangeStateEventResponse(CWTransportMessage *tm, int PMTU, int seqNum);

CWBool CWAssembleMsgElemACDescriptor(const void *ctx, CWProtocolMessage *pm);	// 1
CWBool CWAssembleMsgElemACIPv4List(const void *ctx, CWProtocolMessage *pm);	// 2
CWBool CWAssembleMsgElemACIPv6List(const void *ctx, CWProtocolMessage *pm);	// 3
CWBool CWAssembleMsgElemACName(const void *ctx, CWProtocolMessage *pm);	// 4
CWBool CWAssembleMsgElemAddStation(const void *ctx, int radioID, CWProtocolMessage *pm, unsigned char *StationMacAddr);	// 8
CWBool CWAssembleMsgElemDeleteStation(const void *ctx, int radioID, CWProtocolMessage *pm, unsigned char *StationMacAddr);	// 8
CWBool CWAssembleMsgElemCWControlIPv4Addresses(const void *ctx, CWProtocolMessage *pm);	//10
CWBool CWAssembleMsgElemCWControlIPv6Addresses(const void *ctx, CWProtocolMessage *pm);	//11
CWBool CWAssembleMsgElemCWTimer(const void *ctx, CWProtocolMessage *pm);	//12
CWBool CWAssembleMsgElemDecryptErrorReportPeriod(const void *ctx, CWProtocolMessage *pm);	//16
CWBool CWAssembleMsgElemIdleTimeout(const void *ctx, CWProtocolMessage *pm);	//23
CWBool CWAssembleMsgElemWTPFallback(const void *ctx, CWProtocolMessage *pm);	//37
CWBool CWAssembleWLANConfigurationRequest(CWTransportMessage *tm, int PMTU, int seqNum,
					  unsigned char *recv_packet, int Operation, int len_packet);
CWBool CWAssembleMsgElemACWTPRadioInformation(const void *ctx, CWProtocolMessage *pm);
CWBool CWAssembleMsgElemAddWLAN(const void *ctx, int radioID, CWProtocolMessage *pm, unsigned char *recv_packet, int len_packet);
CWBool CWAssembleMsgElemDeleteWLAN(const void *ctx, int radioID, CWProtocolMessage *pm, unsigned char *recv_packet, int len_packet);

//---------------------------------------------------------/

//CWBool CWParseACName(CWProtocolMessage *msgPtr, int len, char **valPtr);
CWBool CWParseACNameWithIndex(CWProtocolMessage *pm, int len, CWACNameWithIndexValues * valPtr);	// 5
CWBool CWParseMsgElemDataTransferData(CWProtocolMessage *pm, int len, CWProtocolWTPDataTransferRequestValues * valPtr);	//13
CWBool CWParseDiscoveryType(CWProtocolMessage *pm, int len, CWDiscoveryRequestValues * valPtr);	//20
CWBool CWParseMsgElemDuplicateIPv4Address(CWProtocolMessage *pm, int len, WTPDuplicateIPv4 * valPtr);	//21
CWBool CWParseLocationData(CWProtocolMessage *pm, int len, char **valPtr);	//27
CWBool CWParseWTPRadioAdminState(CWProtocolMessage *pm, int len, CWRadioAdminInfoValues * valPtr);	//29
CWBool CWParseWTPStatisticsTimer(CWProtocolMessage *pm, int len, int *valPtr);	//33
CWBool CWParseWTPBoardData(CWProtocolMessage *pm, int len, CWWTPVendorInfos * valPtr);	//35
CWBool CWParseWTPDescriptor(CWProtocolMessage *pm, int len, CWWTPDescriptor * valPtr);	//37
CWBool CWParseWTPFrameTunnelMode(CWProtocolMessage *pm, int len, CWframeTunnelMode * valPtr);	//38
CWBool CWParseWTPIPv4Address(CWProtocolMessage *pm, int len, CWProtocolJoinRequestValues * valPtr);	//39
CWBool CWParseWTPMACType(CWProtocolMessage *pm, int len, CWMACType * valPtr);	//40
CWBool CWParseWTPName(CWProtocolMessage *pm, int len, char **valPtr);	//41
CWBool CWParseWTPOperationalStatistics(CWProtocolMessage *pm, int len, WTPOperationalStatisticsValues * valPtr);	//42
CWBool CWParseWTPRadioStatistics(CWProtocolMessage *pm, int len, WTPRadioStatisticsValues * valPtr);	//43
CWBool CWParseWTPRebootStatistics(CWProtocolMessage *pm, int len, WTPRebootStatisticsInfo * valPtr);	//44
CWBool CWParseMsgElemDecryptErrorReport(CWProtocolMessage *pm, int len, CWDecryptErrorReportValues * valPtr);
CWBool CWParseMsgElemDuplicateIPv6Address(CWProtocolMessage *pm, int len, WTPDuplicateIPv6 * valPtr);
CWBool CWParseWTPRadioInformation(CWProtocolMessage *pm, int len, unsigned char *valPtr);	//1048
CWBool CWParseWTPSupportedRates(CWProtocolMessage *pm, int len, unsigned char *valPtr);	//1040
CWBool CWParseWTPMultiDomainCapability(CWProtocolMessage *pm, int len, unsigned char *valPtr);	//1032
//CWBool CWParseWTPRadioInfo(CWProtocolMessage *msgPtr, int len, CWRadiosInformation *valPtr, int radioIndex);

//---------------------------------------------------------/
CWBool CWACGetACIPv4List(int **listPtr, int *countPtr);
CWBool CWACGetACIPv6List(struct in6_addr **listPtr, int *countPtr);
char *CWACGetName(void);
int CWACGetHWVersion(void);
int CWACGetSWVersion(void);
int CWACGetStations(void);
int CWACGetLimit(void);
int CWACGetActiveWTPs(void);
int CWACGetMaxWTPs(void);
int CWACGetSecurity(void);
int CWACGetInterfacesCount(void);
int CWACGetInterfaceIPv4AddressAtIndex(int i);
unsigned char *CWACGetInterfaceIPv6AddressAtIndex(int i);
int CWACGetInterfaceWTPCountAtIndex(int i);
CWBool CWACGetDiscoveryTimer(int *timer);
CWBool CWACGetEchoRequestTimer(int *timer);
CWBool CWACGetIdleTimeout(int *timer);
CWBool CWGetWTPRadiosOperationalState(int radioID, CWRadiosOperationalInfo * valPtr);

//---------------------------------------------------------/
CWBool CWACSupportIPv6();
void CWDestroyDiscoveryRequestValues(CWDiscoveryRequestValues * valPtr);

CWBool CWProtocolAssembleConfigurationUpdateRequest(CWProtocolMessage *msgElems,
						    int MsgElementType);

#endif
