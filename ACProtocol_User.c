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
 *
 * --------------------------------------------------------------------------------------- *
 * Project:  Capwap                                                                        *
 *                                                                                         *
 * Author :  Ludovico Rossi (ludo@bluepixysw.com)                                          *
 *           Del Moro Andrea (andrea_delmoro@libero.it)                                    *
 *           Giovannini Federica (giovannini.federica@gmail.com)                           *
 *           Massimo Vellucci (m.vellucci@unicampus.it)                                    *
 *           Mauro Bisson (mauro.bis@gmail.com)                                            *
 *******************************************************************************************/

#include "CWAC.h"

CWBool CWACSupportIPv6()
{
	return (gNetworkPreferredFamily == CW_IPv6);
}

char *CWACGetName()
{
	return gACName;
}

int CWACGetStations()
{
	return gActiveStations;
}

int CWACGetLimit()
{
	return gLimit;
}

int CWACGetActiveWTPs()
{
	int tmp;
	if (!CWErr(CWThreadMutexLock(&gActiveWTPsMutex)))
		return 0;
	tmp = gActiveWTPs;
	CWThreadMutexUnlock(&gActiveWTPsMutex);

	return tmp;
}

int CWACGetMaxWTPs()
{
	return gMaxWTPs;
}

int CWACGetSecurity()
{
	return gACDescriptorSecurity;
}

int CWACGetRMACField()
{
	return gRMACField;
}

int CWACGetWirelessField()
{
	return gWirelessField;
}

int CWACGetDTLSPolicy()
{
	return gDTLSPolicy;
}

int CWACGetHWVersion()
{
	return gACHWVersion;
}

int CWACGetSWVersion()
{
	return gACSWVersion;
}

int CWACGetInterfacesCount()
{
	return gInterfacesCount;
}

int CWACGetInterfaceIPv4AddressAtIndex(int i)
{
	struct sockaddr_in *addrPtr;

	if (gNetworkPreferredFamily == CW_IPv4) {
		addrPtr = (struct sockaddr_in *)&(gInterfaces[i].addr);
	} else {
		addrPtr = (struct sockaddr_in *)&(gInterfaces[i].addrIPv4);
	}

	return ntohl(addrPtr->sin_addr.s_addr);
}

unsigned char *CWACGetInterfaceIPv6AddressAtIndex(int i)
{
	struct sockaddr_in6 *addrPtr;

	addrPtr = (struct sockaddr_in6 *)&(gInterfaces[i].addr);

	return (unsigned char *)addrPtr->sin6_addr.s6_addr;
}

int CWACGetInterfaceWTPCountAtIndex(int i)
{
	return gInterfaces[i].WTPCount;
}

CWBool CWACGetVendorInfos(CWACVendorInfos * valPtr)
{
	if (valPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	valPtr->vendorInfosCount = 2;
	if (!(valPtr->vendorInfos = ralloc_array(NULL, CWACVendorInfoValues, valPtr->vendorInfosCount)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	// my vendor identifier (IANA assigned "SMI Network Management Private Enterprise Code")
	valPtr->vendorInfos[0].vendorIdentifier = 65432;
	valPtr->vendorInfos[0].type = CW_AC_HARDWARE_VERSION;
	valPtr->vendorInfos[0].length = 4;	// just one int
	if (!(valPtr->vendorInfos[0].valuePtr = ralloc_size(NULL, 4)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
	*valPtr->vendorInfos[0].valuePtr = CWACGetHWVersion();	// HW version - TODO: wrong, should be string

	// my vendor identifier (IANA assigned "SMI Network Management Private Enterprise Code")
	valPtr->vendorInfos[1].vendorIdentifier = 65432;
	valPtr->vendorInfos[1].type = CW_AC_SOFTWARE_VERSION;
	valPtr->vendorInfos[1].length = 4;	// just one int
	if (!(valPtr->vendorInfos[1].valuePtr = ralloc_size(NULL, 4)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
	*valPtr->vendorInfos[1].valuePtr = CWACGetSWVersion();	// SW version - TODO: wrong, should be string

	return CW_TRUE;
}

void CWACDestroyVendorInfos(CWACVendorInfos * valPtr)
{
	int i;

	if (valPtr == NULL)
		return;

	for (i = 0; i < valPtr->vendorInfosCount; i++) {
		CW_FREE_OBJECT((valPtr->vendorInfos)[i].valuePtr);
	}

	CW_FREE_OBJECT(valPtr->vendorInfos);
}

CWBool CWACGetACIPv4List(int **listPtr, int *countPtr)
{
	struct in_addr addr;

	// TO-DO this func should return the addresses of eventual other ACs in a cluster. Hey, what? What is the WTP
	// supposed to do with that?
	if (listPtr == NULL || countPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	*countPtr = 2;

	if (!((*listPtr) = ralloc_array(NULL, int, (*countPtr))))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	inet_pton(AF_INET, "192.168.1.2", &addr);	// TO-DO take the addresses from config file?
	(*listPtr)[0] = addr.s_addr;
	inet_pton(AF_INET, "192.168.1.66", &addr);
	(*listPtr)[1] = addr.s_addr;

	return CW_TRUE;
}

CWBool CWACGetACIPv6List(struct in6_addr ** listPtr, int *countPtr)
{
	// TO-DO this func should return the addresses of eventual other ACs in a cluster. Hey, what? What is the WTP
	// supposed to do with that?
	if (listPtr == NULL || countPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	*countPtr = 2;

	if (!(*listPtr = ralloc_array(NULL, struct in6_addr, (*countPtr))))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	inet_pton(AF_INET6, "5f1b:df00:ce3e:e200:0020:0800:2078:e3e3", &((*listPtr)[0]));	// TO-DO take the addresses from config file?
	inet_pton(AF_INET6, "5f1b:df00:ce3e:e200:0020:0800:2078:e3e4", &((*listPtr)[1]));

	return CW_TRUE;
}

CWBool CWACGetDiscoveryTimer(int *timer)
{
	*timer = gDiscoveryTimer;
	return CW_TRUE;
}

CWBool CWACGetEchoRequestTimer(int *timer)
{
	*timer = gEchoRequestTimer;
	return CW_TRUE;
}

CWBool CWACGetIdleTimeout(int *timer)
{
	*timer = gIdleTimeout;
	return CW_TRUE;
}

/* Il WTP ha la funzione ridefinita */
CWBool CWGetWTPRadiosAdminState(CWRadiosAdminInfo * valPtr)
{
	int *WTPIndexPtr;

	if (valPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if ((WTPIndexPtr = ((int *)CWThreadGetSpecific(&gIndexSpecific))) == NULL) {
		return CW_FALSE;
	}

	valPtr->radiosCount = gWTPs[*WTPIndexPtr].WTPProtocolManager.radiosInfo.radioCount;

	if (!(valPtr->radios = ralloc_array(NULL, CWRadioAdminInfoValues, valPtr->radiosCount)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	int i;
	for (i = 0; i < valPtr->radiosCount; i++) {
		(valPtr->radios)[i].ID = gWTPs[*WTPIndexPtr].WTPProtocolManager.radiosInfo.radiosInfo[i].radioID;
		(valPtr->radios)[i].state = gWTPs[*WTPIndexPtr].WTPProtocolManager.radiosInfo.radiosInfo[i].adminState;
		(valPtr->radios)[i].cause = gWTPs[*WTPIndexPtr].WTPProtocolManager.radiosInfo.radiosInfo[i].adminCause;
	}

	return CW_TRUE;
}

CWBool CWGetWTPRadiosOperationalState(int radioID, CWRadiosOperationalInfo * valPtr)
{
	int i;
	CWBool found = CW_FALSE;
	int *WTPIndexPtr;

	if (valPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if ((WTPIndexPtr = ((int *)CWThreadGetSpecific(&gIndexSpecific))) == NULL) {
		return CW_FALSE;
	}

	if (radioID < 0) {
		valPtr->radiosCount = gWTPs[*WTPIndexPtr].WTPProtocolManager.radiosInfo.radioCount;

		if (!(valPtr->radios = ralloc_array(NULL, CWRadioOperationalInfoValues, valPtr->radiosCount)))
			return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

		for (i = 0; i < valPtr->radiosCount; i++) {
			(valPtr->radios)[i].ID =
			    gWTPs[*WTPIndexPtr].WTPProtocolManager.radiosInfo.radiosInfo[i].radioID;
			(valPtr->radios)[i].state =
			    gWTPs[*WTPIndexPtr].WTPProtocolManager.radiosInfo.radiosInfo[i].operationalState;
			(valPtr->radios)[i].cause =
			    gWTPs[*WTPIndexPtr].WTPProtocolManager.radiosInfo.radiosInfo[i].operationalCause;
		}
		return CW_TRUE;
	} else {
		for (i = 0; i < valPtr->radiosCount; i++) {
			if (gWTPs[*WTPIndexPtr].WTPProtocolManager.radiosInfo.radiosInfo[i].radioID == radioID) {
				found = CW_TRUE;
				valPtr->radiosCount = 1;
				if (!(valPtr->radios = ralloc_array(NULL, CWRadioOperationalInfoValues, valPtr->radiosCount)))
					return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

				(valPtr->radios)[i].ID =
				    gWTPs[*WTPIndexPtr].WTPProtocolManager.radiosInfo.radiosInfo[i].radioID;
				(valPtr->radios)[i].state =
				    gWTPs[*WTPIndexPtr].WTPProtocolManager.radiosInfo.radiosInfo[i].operationalState;
				(valPtr->radios)[i].cause =
				    gWTPs[*WTPIndexPtr].WTPProtocolManager.radiosInfo.radiosInfo[i].operationalCause;
				break;
			}
		}
		return found;
	}
}
