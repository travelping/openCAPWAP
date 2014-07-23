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
 *											   *
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

#include "CWAC.h"
#include "CWConfigFile.h"

char *gCWConfigFileName = SYSCONFDIR "/config.ac";
CWConfigValue gConfigValues[] = {
	{ .type = CW_INTEGER,
	  .code = "</AC_HW_VERSION>",
	  .value.int_value = 0
	},
	{ .type = CW_INTEGER,
	  .code = "</AC_SW_VERSION>",
	  .value.int_value = 0,
	},
	{ .type = CW_INTEGER,
	  .code = "</AC_MAX_STATIONS>",
	  .value.int_value = 0,
	},
	{ .type = CW_INTEGER,
	  .code = "</AC_MAX_WTPS>",
	  .value.int_value = 0,
	},
	{ .type = CW_STRING,
	  .code = "</AC_SECURITY>",
	  .value.str_value = NULL,
	},
	{ .type = CW_STRING,
	  .code = "</AC_NAME>",
	  .value.str_value = NULL,
	},
	{ .type = CW_STRING_ARRAY,
	  .code = "<AC_MCAST_GROUPS>",
	  .endCode = "</AC_MCAST_GROUPS>",
	  .value.str_array_value = NULL,
	  .count = 0,
	},
	{ .type = CW_INTEGER,
	  .code = "</AC_FORCE_MTU>",
	  .value.int_value = 0,

	},
	{ .type = CW_STRING,
	  .code = "</AC_LEV3_PROTOCOL>",
	  .value.str_value = NULL,
	},
	{ .type = CW_INTEGER,
	  .code = "</AC_LOG_FILE_ENABLE>",
	  .value.int_value = 0,
	},
	{ .type = CW_INTEGER,
	  .code = "</AC_LOG_FILE_SIZE>",
	  .value.int_value = DEFAULT_LOG_SIZE,
	},
};

int gConfigValuesCount = sizeof(gConfigValues) / sizeof(CWConfigValue);

CWBool CWConfigFileDestroyLib()
{
	int i;

	/* save the preferences we read */
	gACHWVersion = gConfigValues[0].value.int_value;
	gACSWVersion = gConfigValues[1].value.int_value;
	gLimit = gConfigValues[2].value.int_value;
	gMaxWTPs = gConfigValues[3].value.int_value;

#ifndef CW_NO_DTLS
	if (gConfigValues[4].value.str_value != NULL && !strcmp(gConfigValues[4].value.str_value, "PRESHARED")) {
		gACDescriptorSecurity = CW_PRESHARED;
	} else {
		/* default */
		gACDescriptorSecurity = CW_X509_CERTIFICATE;
	}
#endif

	if (gConfigValues[5].value.str_value != NULL) {
		if (!(gACName = ralloc_strdup(NULL, gConfigValues[5].value.str_value)))
			return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
		//CW_FREE_OBJECT(gACName);
	}

	/* avoid to allocate 0 bytes */
	if (gConfigValues[6].count) {

		if (!(gMulticastGroups = ralloc_array(NULL, char *, gConfigValues[6].count)))
			return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

		for (i = 0; i < gConfigValues[6].count; i++)
			if (!(gMulticastGroups[i] = ralloc_strdup(gMulticastGroups, gConfigValues[6].value.str_array_value[i])))
				ralloc_free(gMulticastGroups);
				return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
	}

	gMulticastGroupsCount = gConfigValues[6].count;
	CW_PRINT_STRING_ARRAY(gMulticastGroups, gMulticastGroupsCount);

	gCWForceMTU = gConfigValues[7].value.int_value;

	if (gConfigValues[8].value.str_value != NULL && !strcmp(gConfigValues[8].value.str_value, "IPv6")) {

		gNetworkPreferredFamily = CW_IPv6;
	} else {
		/* default */
		gNetworkPreferredFamily = CW_IPv4;
	}

	for (i = 0; i < gConfigValuesCount; i++) {
		if (gConfigValues[i].type == CW_STRING) {
			CW_FREE_OBJECT(gConfigValues[i].value.str_value);
		} else if (gConfigValues[i].type == CW_STRING_ARRAY) {
			CW_FREE_OBJECTS_ARRAY((gConfigValues[i].value.str_array_value), gConfigValues[i].count);
		}
	}

	gEnabledLog = gConfigValues[9].value.int_value;
	gMaxLogFileSize = gConfigValues[10].value.int_value;

	return CW_TRUE;
}
