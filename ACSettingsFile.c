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

char *gCWSettingsFileName = SYSCONFDIR "/settings.ac.txt";

#define CWMIN_DEFAULT   3
#define CWMAX_DEFAULT   10
#define AIFS_DEFAULT    1

FILE *gSettingsFile = NULL;
WTPQosValues *gDefaultQosValues = NULL;
int gHostapd_port;
char *gHostapd_unix_path;

void CWExtractValue(char *start, char **startValue, char **endValue, int *offset)
{
	*offset = strspn(start + 1, " \t\n\r");
	*startValue = start + 1 + *offset;

	*offset = strcspn(*startValue, " \t\n\r");
	*endValue = *startValue + *offset - 1;
}

CWBool CWParseSettingsFile()
{
	char line[CW_BUFFER_SIZE];

	gSettingsFile = fopen(gCWSettingsFileName, "rb");
	if (gSettingsFile == NULL) {
		CWErrorRaiseSystemError(CW_ERROR_GENERAL);
	}

	gDefaultQosValues = CW_CREATE_ARRAY_ERR(NUM_QOS_PROFILES, WTPQosValues,
			    return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
	    );

	while (CWGetCommand(gSettingsFile, line, sizeof(line)) == CW_TRUE) {
		char *startTag = NULL;
		char *endTag = NULL;

		if ((startTag = strchr(line, '<')) == NULL)
			continue;

		if ((endTag = strchr(line, '>')) == NULL)
			continue;

		if (!strncmp(startTag + 1, "CWMIN_VOICE", endTag - startTag - 1)) {
			int value = atoi(endTag + 1);

			if (value == 0)
				value = CWMIN_DEFAULT;
			gDefaultQosValues[VOICE_QUEUE_INDEX].cwMin = value;
			CWDebugLog("CWMIN_VOICE: %d", gDefaultQosValues[VOICE_QUEUE_INDEX].cwMin);
			continue;
		}
		if (!strncmp(startTag + 1, "CWMAX_VOICE", endTag - startTag - 1)) {
			int value = atoi(endTag + 1);

			if (value == 0)
				value = CWMAX_DEFAULT;
			gDefaultQosValues[VOICE_QUEUE_INDEX].cwMax = value;
			CWDebugLog("CWMAX_VOICE: %d", gDefaultQosValues[VOICE_QUEUE_INDEX].cwMax);
			continue;
		}
		if (!strncmp(startTag + 1, "AIFS_VOICE", endTag - startTag - 1)) {
			int value = atoi(endTag + 1);

			if (value == 0)
				value = AIFS_DEFAULT;
			gDefaultQosValues[VOICE_QUEUE_INDEX].AIFS = value;
			CWDebugLog("AIFS_VOICE: %d", gDefaultQosValues[VOICE_QUEUE_INDEX].AIFS);
			continue;
		}

		if (!strncmp(startTag + 1, "CWMIN_VIDEO", endTag - startTag - 1)) {
			int value = atoi(endTag + 1);

			if (value == 0)
				value = CWMIN_DEFAULT;
			gDefaultQosValues[VIDEO_QUEUE_INDEX].cwMin = value;
			CWDebugLog("CWMIN_VIDEO: %d", gDefaultQosValues[VIDEO_QUEUE_INDEX].cwMin);
			continue;
		}
		if (!strncmp(startTag + 1, "CWMAX_VIDEO", endTag - startTag - 1)) {
			int value = atoi(endTag + 1);

			if (value == 0)
				value = CWMAX_DEFAULT;
			gDefaultQosValues[VIDEO_QUEUE_INDEX].cwMax = value;
			CWDebugLog("CWMAX_VIDEO: %d", gDefaultQosValues[VIDEO_QUEUE_INDEX].cwMax);
			continue;
		}
		if (!strncmp(startTag + 1, "AIFS_VIDEO", endTag - startTag - 1)) {
			int value = atoi(endTag + 1);

			if (value == 0)
				value = AIFS_DEFAULT;
			gDefaultQosValues[VIDEO_QUEUE_INDEX].AIFS = value;
			CWDebugLog("AIFS_VIDEO: %d", gDefaultQosValues[VIDEO_QUEUE_INDEX].AIFS);
			continue;
		}

		if (!strncmp(startTag + 1, "CWMIN_BEST_EFFORT", endTag - startTag - 1)) {
			int value = atoi(endTag + 1);

			if (value == 0)
				value = CWMIN_DEFAULT;
			gDefaultQosValues[BESTEFFORT_QUEUE_INDEX].cwMin = value;
			CWDebugLog("CWMIN_BEST_EFFORT: %d", gDefaultQosValues[BESTEFFORT_QUEUE_INDEX].cwMin);
			continue;
		}
		if (!strncmp(startTag + 1, "CWMAX_BEST_EFFORT", endTag - startTag - 1)) {
			int value = atoi(endTag + 1);

			if (value == 0)
				value = CWMAX_DEFAULT;
			gDefaultQosValues[BESTEFFORT_QUEUE_INDEX].cwMax = value;
			CWDebugLog("CWMAX_BEST_EFFORT: %d", gDefaultQosValues[BESTEFFORT_QUEUE_INDEX].cwMax);
			continue;
		}
		if (!strncmp(startTag + 1, "AIFS_BEST_EFFORT", endTag - startTag - 1)) {
			int value = atoi(endTag + 1);

			if (value == 0)
				value = AIFS_DEFAULT;
			gDefaultQosValues[BESTEFFORT_QUEUE_INDEX].AIFS = value;
			CWDebugLog("AIFS_BEST_EFFORT: %d", gDefaultQosValues[BESTEFFORT_QUEUE_INDEX].AIFS);
			continue;
		}

		if (!strncmp(startTag + 1, "CWMIN_BACKGROUND", endTag - startTag - 1)) {
			int value = atoi(endTag + 1);

			if (value == 0)
				value = CWMIN_DEFAULT;
			gDefaultQosValues[BACKGROUND_QUEUE_INDEX].cwMin = value;
			CWDebugLog("CWMIN_BACKGROUND: %d", gDefaultQosValues[BACKGROUND_QUEUE_INDEX].cwMin);
			continue;
		}
		if (!strncmp(startTag + 1, "CWMAX_BACKGROUND", endTag - startTag - 1)) {
			int value = atoi(endTag + 1);

			if (value == 0)
				value = CWMAX_DEFAULT;
			gDefaultQosValues[BACKGROUND_QUEUE_INDEX].cwMax = value;
			CWDebugLog("CWMAX_BACKGROUND: %d", gDefaultQosValues[BACKGROUND_QUEUE_INDEX].cwMax);
			continue;
		}
		if (!strncmp(startTag + 1, "AIFS_BACKGROUND", endTag - startTag - 1)) {
			int value = atoi(endTag + 1);

			if (value == 0)
				value = AIFS_DEFAULT;
			gDefaultQosValues[BACKGROUND_QUEUE_INDEX].AIFS = value;
			CWDebugLog("AIFS_BACKGROUND: %d", gDefaultQosValues[BACKGROUND_QUEUE_INDEX].AIFS);
			continue;
		}
		if (!strncmp(startTag + 1, "AC_HOSTAPD_PORT", endTag - startTag - 1)) {

			gHostapd_port = atoi(endTag + 1);

			CWDebugLog("Hostapd Port connection: %d", gHostapd_port);
			continue;
		}
		if (!strncmp(startTag + 1, "AC_HOSTAPD_UNIX_PATH", endTag - startTag - 1)) {
			char *startValue = NULL;
			char *endValue = NULL;
			int offset = 0;

			CWExtractValue(endTag, &startValue, &endValue, &offset);

			if (!((gHostapd_unix_path = ralloc_strndup(NULL, startValue, offset))))
				return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

			CWDebugLog("Hostapd Unix Domain Path: %s", gHostapd_unix_path);
			continue;

		}
	}
	return CW_TRUE;
}
