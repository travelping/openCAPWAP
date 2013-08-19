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
 * --------------------------------------------------------------------------------------- *
 * Project:  Capwap                                                                        *
 *                                                                                         *
 * Author :  Ludovico Rossi (ludo@bluepixysw.com)                                          *
 *           Del Moro Andrea (andrea_delmoro@libero.it)                                    *
 *           Giovannini Federica (giovannini.federica@gmail.com)                           *
 *           Massimo Vellucci (m.vellucci@unicampus.it)                                    *
 *           Mauro Bisson (mauro.bis@gmail.com)                                            *
 *******************************************************************************************/

#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include "CWCommon.h"

#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

char *gCWSettingsFileName = SYSCONFDIR "/settings.wtp.txt";

FILE *gSettingsFile = NULL;
char *gInterfaceName = NULL;
char *gEthInterfaceName = NULL;
char *gRadioInterfaceName_0 = NULL;
char *gBaseMACInterfaceName = NULL;
char gBoardReversionNo;
char *gWtpModelNumber = NULL;
char *gWtpSerialNumber = NULL;

char *gWtpHardwareVersion = NULL;
char *gWtpActiveSoftwareVersion = NULL;
char *gWtpBootVersion = NULL;

int gHostapd_port;
char *gHostapd_unix_path;

#define ltrim(s) ({							\
	while (*s != '\0' && *s == ' ' && *s == '\t' && *s == '\n' && *s == '\r') \
		s++;							\
	s;								\
})

CWBool CWParseSettingsFile()
{
	char *line = NULL;

	gSettingsFile = fopen(gCWSettingsFileName, "rb");
	if (gSettingsFile == NULL) {
		CWErrorRaiseSystemError(CW_ERROR_GENERAL);
	}

	while ((line = (char *)CWGetCommand(gSettingsFile)) != NULL) {
		char *startTag = NULL;
		char *endTag = NULL;
		char *Value = NULL;

		if ((startTag = strchr(line, '<')) == NULL) {
			CW_FREE_OBJECT(line);
			continue;
		}
		startTag++;

		if ((endTag = strchr(startTag, '>')) == NULL) {
			CW_FREE_OBJECT(line);
			continue;
		}
		*endTag++ = '\0';

		Value = ltrim(endTag);

		if (!strcmp(startTag, "IF_NAME")) {
			CW_CREATE_STRING_FROM_STRING_ERR(gInterfaceName, Value, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
				);
			CWLog(": %s", gInterfaceName);
		}
		else if (!strcmp(startTag, "WTP_ETH_IF_NAME")) {
			CW_CREATE_STRING_FROM_STRING_ERR(gEthInterfaceName, Value, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
				);
			CWLog(": %s", gEthInterfaceName);
		}
		else if (!strcmp(startTag, "RADIO_0_IF_NAME")) {
			CW_CREATE_STRING_FROM_STRING_ERR(gRadioInterfaceName_0, Value, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
				);
			CWLog(": %s", gRadioInterfaceName_0);
		}
		else if (!strcmp(startTag, "BASE_MAC_IF_NAME")) {
			CW_CREATE_STRING_FROM_STRING_ERR(gBaseMACInterfaceName, Value, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
				);
			CWLog(": %s", gBaseMACInterfaceName);
		}
		else if (!strcmp(startTag, "BOARD_REVISION_NO")) {
			gBoardReversionNo = atoi(Value);
			CWLog(": %d", gBoardReversionNo);
		}
		else if (!strcmp(startTag, "WTP_HOSTAPD_PORT")) {
			gHostapd_port = atoi(Value);
			CWLog(": %d", gHostapd_port);
		}
		else if (!strcmp(startTag, "WTP_HOSTAPD_UNIX_PATH")) {
			CW_CREATE_STRING_FROM_STRING_ERR(gHostapd_unix_path, Value, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
				);
			CWLog(": %s", gHostapd_unix_path);
		}
		else if (!strcmp(startTag, "WTP_MODEL_NUM")) {
			CW_CREATE_STRING_FROM_STRING_ERR(gWtpModelNumber, Value, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
			    );
			CWLog(": %s", gWtpModelNumber);
		}
		else if (!strcmp(startTag, "WTP_SERIAL_NUM")) {
			CW_CREATE_STRING_FROM_STRING_ERR(gWtpSerialNumber, Value, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
				);
			CWLog(": %s", gWtpSerialNumber);
		}
		else if (!strcmp(startTag, "WTP_HARDWARE_VERSION")) {
			CW_CREATE_STRING_FROM_STRING_ERR(gWtpHardwareVersion, Value, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
				);
			CWLog(": %s", gWtpHardwareVersion);
		}
		else if (!strcmp(startTag, "WTP_ACTIVE_SOFTWARE_VERSION")) {
			CW_CREATE_STRING_FROM_STRING_ERR(gWtpActiveSoftwareVersion, Value, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
				);
			CWLog(": %s", gWtpActiveSoftwareVersion);
		}
		else if (!strcmp(startTag, "WTP_BOOT_VERSION")) {
			CW_CREATE_STRING_FROM_STRING_ERR(gWtpBootVersion, Value, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
				);
			CWLog(": %s", gWtpBootVersion);
		}
		else
			CWLog(": unknown Tag: %s = %s", startTag, Value);

		CW_FREE_OBJECT(line);
	}
	return CW_TRUE;
}
