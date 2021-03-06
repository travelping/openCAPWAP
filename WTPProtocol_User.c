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

#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include "common.h"

#include "CWWTP.h"

#define MAC_ADDR_LEN        6

__inline__ int CWWTPGetDiscoveryType()
{
	return CW_MSG_ELEMENT_DISCOVERY_TYPE_CONFIGURED;
}

__inline__ int CWWTPGetMaxRadios()
{
	return 1;
}

__inline__ int CWWTPGetRadiosInUse()
{
	/*for (i=0; i<gRadiosInfo.radioCount; i++)
	   {
	   if((gRadiosInfo.radiosInfo[i].operationalState) == ENABLED)
	   active++;
	   }
	   return active;
	 */
	return gRadiosInfo.radioCount;
}

CWBool CWWTPGetEncCapabilities(CWWTPEncryptCaps * encc)
{
	if (encc == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	encc->encryptCapsCount = 1;
	if (!((encc->encryptCaps) = ralloc_array(NULL, CWWTPEncryptCapValues, encc->encryptCapsCount)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	(encc->encryptCaps)[0].WBID = 1;
	(encc->encryptCaps)[0].encryptionCapabilities = 2569;

	return CW_TRUE;
}

void CWWTPDestroyEncCapabilities(CWWTPEncryptCaps * encc)
{
	if (encc == NULL)
		return;

	CW_FREE_OBJECT(encc->encryptCaps);
}

static
CWBool CWAssembleMsgElemWTPBoardDataElem(const void *ctx, CWProtocolMessage *pm,
					 uint16_t type, uint16_t length, unsigned char *data)
{
	assert(pm != NULL);

	if (!CWMessageEnsureSpace(ctx, pm, length + 4))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	CWProtocolStore16(pm, type);
	CWProtocolStore16(pm, length);
	CWProtocolStoreRawBytes(pm, data, length);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemWTPBoardData_User(const void *ctx, CWProtocolMessage *pm)
{
	assert(pm != NULL);

	if (!CWAssembleMsgElemWTPBoardDataElem(ctx, pm, CW_WTP_MODEL_NUMBER,
					       strlen(gWtpModelNumber),  (unsigned char *)gWtpModelNumber) ||
	    !CWAssembleMsgElemWTPBoardDataElem(ctx, pm, CW_WTP_SERIAL_NUMBER,
					       strlen(gWtpSerialNumber), (unsigned char *)gWtpSerialNumber))
		return CW_FALSE;

	return CW_TRUE;
}

CWBool CWWTPGetVendorInfos(CWWTPVendorInfos * valPtr)
{
	CWWTPVendorInfoValues *Infos;
	if (valPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	valPtr->vendorInfosCount = 4;	// we fill 3 information (just the required ones)
	if (!(valPtr->vendorInfos = Infos =
	      ralloc_array(NULL, CWWTPVendorInfoValues, valPtr->vendorInfosCount)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	Infos[0] = (CWWTPVendorInfoValues){
		.vendorIdentifier = 0,
		.type             = CW_WTP_HARDWARE_VERSION,
		.length           = strlen(gWtpHardwareVersion),
		.valuePtr         = ralloc_strdup(Infos, gWtpHardwareVersion)
	};
	Infos[1] = (CWWTPVendorInfoValues){
		.vendorIdentifier = 0,
		.type             = CW_WTP_SOFTWARE_VERSION,
		.length           = strlen(gWtpActiveSoftwareVersion),
		.valuePtr         = ralloc_strdup(Infos, gWtpActiveSoftwareVersion)
	};
	Infos[2] = (CWWTPVendorInfoValues){
		.vendorIdentifier = 0,
		.type             = CW_BOOT_VERSION,
		.length           = strlen(gWtpBootVersion),
		.valuePtr         = ralloc_strdup(Infos, gWtpBootVersion)
	};
	Infos[3] = (CWWTPVendorInfoValues){
		.vendorIdentifier = CW_IANA_ENTERPRISE_NUMBER_VENDOR_TRAVELPING,
		.type             = TP_WTP_VERSION,
		.length           = strlen(gWtpVersion),
		.valuePtr         = ralloc_strdup(Infos, gWtpVersion)
	};

	if (!Infos[0].valuePtr || !Infos[1].valuePtr ||
	    !Infos[2].valuePtr || !Infos[3].valuePtr) {
		ralloc_free(Infos);
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
	}

	return CW_TRUE;
}

__inline__ void CWWTPDestroyVendorInfos(CWWTPVendorInfos * valPtr)
{
	if (valPtr == NULL)
		return;
	CW_FREE_OBJECT(valPtr->vendorInfos);
}

__inline__ int CWWTPGetFrameTunnelMode()
{
	//it may be also 802.3_FrameTunnelMode - NativeFrameTunnelMode - All

#ifdef SOFTMAC
	return CW_NATIVE_BRIDGING | CW_802_DOT_3_BRIDGING;
#else
	return CW_LOCAL_BRIDGING;
#endif

}

__inline__ int CWWTPGetMACType()
{

#ifdef SOFTMAC
	return CW_BOTH;
#else
	return CW_LOCAL_MAC;
#endif

}

__inline__ char *CWWTPGetLocation()
{
	return gWTPLocation;
}

__inline__ int CWWTPGetSessionID()
{
	return CWRandomIntInRange(0, INT_MAX);
}

__inline__ int CWWTPGetIPv4Address()
{
	struct sockaddr_in myAddr;
	unsigned int len = sizeof(myAddr);

	//CWDebugLog("WTPGetIPv4Address");

	/* assume the socket is connected */
	getsockname(gWTPSocket, (struct sockaddr *)&myAddr, &len);

	return ntohl(myAddr.sin_addr.s_addr);	// TO-DO: this is garbage if we are an IPv6 client
}

__inline__ void CWWTPGetIPv6Address(struct sockaddr_in6 *myAddr)
{

	unsigned int len = sizeof(*myAddr);

	/* assume the socket is connected */
	getsockname(gWTPSocket, (struct sockaddr *)myAddr, &len);
}

__inline__ int CWWTPGetIPv4StatusDuplicate()
{
	return gIPv4StatusDuplicate;
}

__inline__ int CWWTPGetIPv6StatusDuplicate()
{
	return gIPv6StatusDuplicate;
}

__inline__ char *CWWTPGetName()
{
	return gWTPName;
}

/*CWBool CWWTPGetRadiosInformation(CWRadiosInformation *valPtr) {
    if(valPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

    valPtr->radiosCount = 2;

    if (!(valPtr->radios = ralloc_array(NULL, CWRadioInformationValues, valPtr->radiosCount))) return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

    (valPtr->radios)[0].ID = 0; // first radio
    (valPtr->radios)[0].type = CW_802_DOT_11b;

    (valPtr->radios)[1].ID = 1; // second radio
    (valPtr->radios)[1].type = CW_802_DOT_11b;

    return CW_TRUE;
}
*/

/* L'AC ha la funzione ridefinita */
CWBool CWGetWTPRadiosAdminState(CWRadiosAdminInfo * valPtr)
{
	int i;

	if (valPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	valPtr->radiosCount = gRadiosInfo.radioCount;

	if (!(valPtr->radios = ralloc_array(NULL, CWRadioAdminInfoValues, valPtr->radiosCount)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	for (i = 0; i < gRadiosInfo.radioCount; i++) {
		(valPtr->radios)[i].ID = gRadiosInfo.radiosInfo[i].radioID;	// first radio
		(valPtr->radios)[i].state = gRadiosInfo.radiosInfo[i].adminState;
		(valPtr->radios)[i].cause = gRadiosInfo.radiosInfo[i].adminCause;
	}

	return CW_TRUE;
}

CWBool CWGetWTPRadiosOperationalState(int radioID, CWRadiosOperationalInfo * valPtr)
{
	int i;
	CWBool found = CW_FALSE;

	if (valPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if (radioID < 0) {

		valPtr->radiosCount = gRadiosInfo.radioCount;

		if (!(valPtr->radios = ralloc_array(NULL, CWRadioOperationalInfoValues, valPtr->radiosCount)))
			return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

		for (i = 0; i < gRadiosInfo.radioCount; i++) {
			(valPtr->radios)[i].ID = gRadiosInfo.radiosInfo[i].radioID;
			(valPtr->radios)[i].state = gRadiosInfo.radiosInfo[i].operationalState;
			(valPtr->radios)[i].cause = gRadiosInfo.radiosInfo[i].operationalCause;
		}
		return CW_TRUE;
	} else {
		for (i = 0; i < gRadiosInfo.radioCount; i++) {
			if (gRadiosInfo.radiosInfo[i].radioID == radioID) {
				found = CW_TRUE;
				valPtr->radiosCount = 1;
				if (!(valPtr->radios = ralloc_array(NULL, CWRadioOperationalInfoValues, valPtr->radiosCount)))
					return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

				(valPtr->radios)[0].ID = gRadiosInfo.radiosInfo[i].radioID;
				(valPtr->radios)[0].state = gRadiosInfo.radiosInfo[i].operationalState;
				(valPtr->radios)[0].cause = gRadiosInfo.radiosInfo[i].operationalCause;
				break;
			}
		}
		return found;
	}
}

CWBool CWGetDecryptErrorReport(int radioID, CWDecryptErrorReportInfo * valPtr)
{
	int i;
	CWBool found = CW_FALSE;

	/*
	   CWMACAddress add, add2;
	   for(i=0; i<6; i++) add[i]=i;
	   for(i=0; i<6; i++) add2[i]=99;
	   CWListElement elem,elem2;
	   elem.data = add;
	   elem.next = &elem2;
	   elem2.data = &add2;
	   elem2.next = NULL;
	   gRadiosInfo.radiosInfo[0].decryptErrorMACAddressList = &elem;
	 */

	if (valPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	valPtr->radios = NULL;

	if (radioID < 0) {

		valPtr->radiosCount = gRadiosInfo.radioCount;

		if (!(valPtr->radios = ralloc_array(NULL, CWDecryptErrorReportValues, valPtr->radiosCount)))
			return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

		for (i = 0; i < gRadiosInfo.radioCount; i++) {
			(valPtr->radios)[i].ID = gRadiosInfo.radiosInfo[i].radioID;
			(valPtr->radios)[i].numEntries =
			    CWCountElementInList(gRadiosInfo.radiosInfo[i].decryptErrorMACAddressList);
			(valPtr->radios[i]).decryptErrorMACAddressList = NULL;
			if (!((valPtr->radios[i]).decryptErrorMACAddressList =
			      ralloc_array(valPtr->radios, CWMACAddress, valPtr->radios[i].numEntries)))
				return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

			int j;
			CWListElement *temp;
			temp = gRadiosInfo.radiosInfo[i].decryptErrorMACAddressList;
			for (j = 0; j < (valPtr->radios[i]).numEntries; j++) {
				CW_COPY_MEMORY((valPtr->radios[i]).decryptErrorMACAddressList[j], temp->data,
					       sizeof(CWMACAddress));
				temp = temp->next;
			}
		}
		return CW_TRUE;
	} else {
		for (i = 0; i < gRadiosInfo.radioCount; i++) {
			if (gRadiosInfo.radiosInfo[i].radioID == radioID) {
				found = CW_TRUE;
				valPtr->radiosCount = 1;
				if (!(valPtr->radios = ralloc_array(NULL, CWDecryptErrorReportValues, valPtr->radiosCount)))
					return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

				(valPtr->radios)[0].ID = gRadiosInfo.radiosInfo[i].radioID;
				(valPtr->radios)[0].numEntries =
				    CWCountElementInList(gRadiosInfo.radiosInfo[i].decryptErrorMACAddressList);
				(valPtr->radios[0]).decryptErrorMACAddressList = NULL;
				if (!((valPtr->radios[0]).decryptErrorMACAddressList = ralloc_array(valPtr->radios,
												    CWMACAddress,
												    (valPtr->radios[0]).numEntries)))
					return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

				int j;
				CWListElement *temp;
				temp = gRadiosInfo.radiosInfo[0].decryptErrorMACAddressList;
				for (j = 0; j < (valPtr->radios[0]).numEntries; j++) {
					CW_COPY_MEMORY((valPtr->radios[0]).decryptErrorMACAddressList[j], temp->data,
						       6);
					temp = temp->next;
				}
			}
		}
		return found;
	}
}

int CWWTPGetACIndex()
{
	return 1;		//valore predefinito
}

char *CWWTPGetACName()
{
	return gACInfoPtr->name;
}

int CWWTPGetStatisticsTimer()
{
	return gWTPStatisticsTimer;
}

CWBool CWWTPGetACNameWithIndex(CWACNamesWithIndex * ACsInfo)
{
	if (ACsInfo == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	ACsInfo->count = 2;

	if (!(ACsInfo->ACNameIndex = ralloc_array(NULL, CWACNameWithIndexValues, ACsInfo->count)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	ACsInfo->ACNameIndex[0].index = 0;	// first radio
	if (!(ACsInfo->ACNameIndex[0].ACName = ralloc_strdup(ACsInfo->ACNameIndex, "ACPrimary")))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	ACsInfo->ACNameIndex[1].index = 1;	// first radio
	if (!(ACsInfo->ACNameIndex[1].ACName = ralloc_strdup(ACsInfo->ACNameIndex, "ACSecondary")))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	return CW_TRUE;
}

int getInterfaceMacAddr(char *interface, unsigned char *macAddr)
{
	struct ifreq ethreq;
	int i, sock;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		CWLog("Error Creating Socket for ioctl");
		return -1;
	}

	memset(&ethreq, 0, sizeof(ethreq));
	strncpy(ethreq.ifr_name, interface, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFHWADDR, &ethreq) == -1) {
		return -1;
	}

	for (i = 0; i < MAC_ADDR_LEN; i++) {
		macAddr[i] = (unsigned char)ethreq.ifr_hwaddr.sa_data[i];
	}

	return 0;
}

int initWTPSessionID(unsigned char *sessionID)
{
	unsigned char macAddr0[MAC_ADDR_LEN];
	unsigned char macAddr1[MAC_ADDR_LEN];
	int i, randomInteger;
	unsigned char *buffer = sessionID;

	getInterfaceMacAddr(gEthInterfaceName, macAddr0);
	getInterfaceMacAddr(gRadioInterfaceName_0, macAddr1);
	randomInteger = CWRandomIntInRange(0, INT_MAX);
	randomInteger = htonl(randomInteger);

	CW_COPY_MEMORY(sessionID, macAddr0, MAC_ADDR_LEN);
	CW_COPY_MEMORY(&(sessionID[MAC_ADDR_LEN]), macAddr1, MAC_ADDR_LEN);
	CW_COPY_MEMORY(&(sessionID[MAC_ADDR_LEN + MAC_ADDR_LEN]), &(randomInteger), 4);

	for (i = 0; i < 16; i++) {
		if (i % 16 == 0)
			printf("\n%04x:   ", i);
		printf("%02x:", (unsigned char)buffer[i]);
	}
	printf("\n");

	return 0;
}
