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

#include "CWCommon.h"

FILE *gCWConfigFile = NULL;

/*
 * Replacement for std fgets which seems to dislike windows return character
 */
char *CWFgets(char *buf, int bufSize, FILE * f)
{
	int c, i = -1;

	if (buf == NULL || f == NULL || bufSize <= 0)
		return NULL;

	CW_ZERO_MEMORY(buf, bufSize);

	do {
		if ((c = getc(f)) == EOF)
			break;

		buf[++i] = (char)c;
	} while (i < bufSize && buf[i] != '\n' && buf[i] != '\r');

	if (i == -1)
		return NULL;

	buf[++i] = '\0';

	return buf;
}

#define rtrim(s)							\
	({								\
		char *c = (s) + strlen((s)) - 1;			\
		while ((c > (s)) && (*c == '\n' || *c == '\r' || *c == '\t' || *c == ' ')) \
			*c-- = '\0';					\
		s;							\
	})

/*
 * Get one "useful" (not a comment, not blank) line from the config file
 */
CWBool CWGetCommand(FILE * configFile, char *buf, size_t size)
{
	do {
		if (CWFgets(buf, size, configFile) == NULL)
			return CW_FALSE;
		rtrim(buf);
	} while (buf[0] == '#' || buf[0] == '\0');	/* skip comments and empty lines */

	return CW_TRUE;
}

/*
 * Parses the configuration file.
 *
 * Params: isCount  CW_TRUE to just count ACAddresses and paths;
 *          CW_FALSE to actually parse them.
 *
 * Return: CW_TRUE if the operation is succesful; CW_FALSE otherwise.
 */
CWBool CWParseTheFile(CWBool isCount)
{
	char line[CW_BUFFER_SIZE];
	int i;

	if (!isCount) {

		for (i = 0; i < gConfigValuesCount; i++) {

			if (gConfigValues[i].type == CW_STRING_ARRAY) {

				/* avoid to allocate 0 bytes */
				if (gConfigValues[i].count) {
					if (!(gConfigValues[i].value.str_array_value =
						ralloc_array(NULL, char *, gConfigValues[i].count)))
						return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
				}
			}
		}
	} else {

		for (i = 0; i < gConfigValuesCount; i++) {

			if (gConfigValues[i].type == CW_STRING_ARRAY) {

				gConfigValues[i].count = 0;
			}
		}
	}

	gCWConfigFile = fopen(gCWConfigFileName, "rb");
	if (gCWConfigFile == NULL)
		CWErrorRaiseSystemError(CW_ERROR_GENERAL);

	while (CWGetCommand(gCWConfigFile, line, sizeof(line)) == CW_TRUE) {

		int i, j;

		CWDebugLog("*** Parsing (%s) ***", line);

		for (i = 0; i < gConfigValuesCount; i++) {

			if (!strncmp(line, gConfigValues[i].code, strlen(gConfigValues[i].code))) {

				char *myLine = line + strlen(gConfigValues[i].code);

				switch (gConfigValues[i].type) {

				case CW_INTEGER:
					gConfigValues[i].value.int_value = atoi(myLine);
					break;
				case CW_STRING:
					/*
					 * BUG - LE02
					 * If this function was called just to count ACAddresses and
					 * paths, we MUST NOT allocate a string value; the actual allocation
					 * will be performed when the function is called with the isCount
					 * argument = CW_FALSE.
					 *
					 * 19/10/2009 - Donato Capitella
					 */

					if (isCount)
						break;

					if (!(gConfigValues[i].value.str_value = ralloc_strdup(NULL, myLine)))
						return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
					break;

				case CW_STRING_ARRAY:
#ifdef CW_DEBUGGING
					CWDebugLog("*** Parsing String Array... *** \n");
#endif
					j = 0;
					while (CWGetCommand(gCWConfigFile, line, sizeof(line)) == CW_TRUE
					       && strcmp(line, gConfigValues[i].endCode)) {
#ifdef CW_DEBUGGING
						CWDebugLog("*** Parsing String (%s) *** \n", line);
#endif

						if (isCount)
							gConfigValues[i].count++;
						else {
							if (!(gConfigValues[i].value.str_array_value[j] = ralloc_strdup(NULL, line)))
								return CWErrorRaise (CW_ERROR_OUT_OF_MEMORY, NULL);
							j++;
						}
					}
					break;
				}
				break;
			}
		}
	}

	CWDebugLog("*** Config File Parsed ***");
	fclose(gCWConfigFile);

	return CW_TRUE;
}

/* parses the configuration file */
CWBool CWParseConfigFile()
{

	/* just count the objects */
	if (!CWParseTheFile(CW_TRUE))
		return CW_FALSE;

	/* actually parse */
	if (!CWParseTheFile(CW_FALSE))
		return CW_FALSE;

#ifdef CW_DEBUGGING
	{
		int i;
		for (i = 0; i < gConfigValuesCount; i++) {

			if (gConfigValues[i].type == CW_INTEGER) {

				CWLog("%s%d", gConfigValues[i].code, gConfigValues[i].value.int_value);
			}
		}
	}
	CWDebugLog("*** Config File END ***");
#endif

	return CWConfigFileDestroyLib();
}
