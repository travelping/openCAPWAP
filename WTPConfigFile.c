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

#include "CWWTP.h"
#include "CWConfigFile.h"

#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

char *gCWConfigFileName   = SYSCONFDIR "/config.wtp";
CWConfigValue gConfigValues[] = {
	{ .type = CW_STRING_ARRAY,
	  .code = "<AC_ADDRESSES>",
	  .endCode = "</AC_ADDRESSES>",
	  .value.str_array_value = NULL,
	  .count = 0
	},
	{ .type = CW_INTEGER,
	  .code = "</WTP_FORCE_MTU>",
	  .value.int_value = 0
	},
	{ .type = CW_STRING,
	  .code = "</WTP_LEV3_PROTOCOL>",
	  .value.str_value = NULL
	},
	{ .type = CW_STRING,
	  .code = "</WTP_NAME>",
	  .value.str_value = NULL
	},
	{ .type = CW_STRING,
	  .code = "</WTP_LOCATION>",
	  .value.str_value = NULL
	},
	{ .type = CW_STRING,
	  .code = "</WTP_FORCE_AC_ADDRESS>",
	  .value.str_value = NULL
	},
	{ .type = CW_STRING,
	  .code = "</WTP_FORCE_SECURITY>",
	  .value.str_value = NULL
	},
	{ .type = CW_INTEGER,
	  .code = "</AC_LOG_FILE_ENABLE>",
	  .value.int_value = 0
	},
	{ .type = CW_INTEGER,
	  .code = "</AC_LOG_FILE_SIZE>",
	  .value.int_value = DEFAULT_LOG_SIZE
	},
};

int gConfigValuesCount = sizeof(gConfigValues) / sizeof(CWConfigValue);

CWBool CWConfigFileInitLib()
{
	return CW_TRUE;
}

CWBool CWConfigFileDestroyLib()
{
	int i;

	// save the preferences we read

	CW_CREATE_ARRAY_ERR(gCWACAddresses, gConfigValues[0].count, char *,
			    return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
	    );

	for (i = 0; i < gConfigValues[0].count; i++) {
		CW_CREATE_STRING_FROM_STRING_ERR(gCWACAddresses[i], (gConfigValues[0].value.str_array_value)[i],
						 return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
		    );
	}

	gCWACCount = gConfigValues[0].count;

#ifdef CW_DEBUGGING
	CW_PRINT_STRING_ARRAY(gCWACAddresses, gCWACCount);
#endif

	gCWForceMTU = gConfigValues[1].value.int_value;

	if (gConfigValues[2].value.str_value != NULL && !strcmp(gConfigValues[2].value.str_value, "IPv6")) {
		gNetworkPreferredFamily = CW_IPv6;
	} else {		// default
		gNetworkPreferredFamily = CW_IPv4;
	}

	if (gConfigValues[3].value.str_value != NULL) {
		CW_CREATE_STRING_FROM_STRING_ERR(gWTPName, (gConfigValues[3].value.str_value),
						 return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
		    );
	}
	if (gConfigValues[4].value.str_value != NULL) {
		CW_CREATE_STRING_FROM_STRING_ERR(gWTPLocation, (gConfigValues[4].value.str_value),
						 return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
		    );
	}
	if (gConfigValues[5].value.str_value != NULL) {
		CW_CREATE_STRING_FROM_STRING_ERR(gWTPForceACAddress, (gConfigValues[5].value.str_value),
						 return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
		    );
	}

	if (gConfigValues[6].value.str_value != NULL && !strcmp(gConfigValues[6].value.str_value, "PRESHARED")) {
		gWTPForceSecurity = CW_PRESHARED;
	} else {		// default
		gWTPForceSecurity = CW_X509_CERTIFICATE;
	}

	for (i = 0; i < gConfigValuesCount; i++) {
		if (gConfigValues[i].type == CW_STRING) {
			CW_FREE_OBJECT(gConfigValues[i].value.str_value);
		} else if (gConfigValues[i].type == CW_STRING_ARRAY) {
			CW_FREE_OBJECTS_ARRAY((gConfigValues[i].value.str_array_value), gConfigValues[i].count);
		}
	}

	gEnabledLog = gConfigValues[7].value.int_value;
	gMaxLogFileSize = gConfigValues[8].value.int_value;

	return CW_TRUE;
}
