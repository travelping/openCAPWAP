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

#include "CWCommon.h"
//#define WRITE_STD_OUTPUT 1

static FILE *gLogFile = NULL;

#ifndef CW_SINGLE_THREAD
CWThreadMutex gFileMutex;
#endif

static void CWVLog(const char *format, va_list args);

void CWLogInitFile(char *fileName)
{
	if (fileName == NULL) {
		CWLog("Wrong File Name for Log File");
	}
	if ((gLogFile = fopen(fileName, "w")) == NULL) {
		CWLog("Can't open log file: %s", strerror(errno));
		exit(1);
	}
#ifndef CW_SINGLE_THREAD
	if (!CWCreateThreadMutex(&gFileMutex)) {
		CWLog("Can't Init File Mutex for Log");
		exit(1);
	}
#endif
}

static CWBool checkResetFile()
{
	long fileSize = 0;

	if ((fileSize = ftell(gLogFile)) == -1) {
		CWLog("An error with log file occurred: %s", strerror(errno));
		return 0;
	}
	if (fileSize >= gMaxLogFileSize) {
		fclose(gLogFile);
		if ((gLogFile = fopen(gLogFileName, "w")) == NULL) {
			CWLog("Can't open log file: %s", strerror(errno));
			return 0;
		}
	}
	return 1;
}

void CWVLog(const char *format, va_list args)
{
	static __thread char logStr[256];
	char nowReadable[30];
	time_t now;

	if (format == NULL)
		return;

	now = time(NULL);
	ctime_r(&now, nowReadable);

	nowReadable[strlen(nowReadable) - 1] = '\0';

	snprintf(logStr, sizeof(logStr) - 1, "[CAPWAP::%s]\t%08x\t %s\n", nowReadable, (unsigned int)CWThreadSelf(), format);

	if (gLogFile != NULL) {
		char fileLine[256];

#ifndef CW_SINGLE_THREAD
		CWThreadMutexLock(&gFileMutex);
		fseek(gLogFile, 0L, SEEK_END);
#endif

		vsnprintf(fileLine, sizeof(fileLine) - 1, logStr, args);

		if (!checkResetFile()) {
			CWThreadMutexUnlock(&gFileMutex);
			exit(1);
		}

		fwrite(fileLine, strlen(fileLine), 1, gLogFile);
		fflush(gLogFile);

#ifndef CW_SINGLE_THREAD
		CWThreadMutexUnlock(&gFileMutex);
#endif
	}
#ifdef WRITE_STD_OUTPUT
	vprintf(logStr, args);
#endif
}

void CWLog(const char *format, ...)
{
	int _errno = errno;
	va_list args;

	va_start(args, format);
	if (gEnabledLog) {
		CWVLog(format, args);
	}
	va_end(args);
	errno = _errno;
}

#ifdef CW_DEBUGGING
void CWDebugLog(const char *format, ...)
{
	int _errno = errno;
	va_list args;

	if (!gEnabledLog)
		return;

	if (format == NULL) {
#ifdef WRITE_STD_OUTPUT
		printf("\n");
#endif
		errno = _errno;
		return;
	}

	va_start(args, format);
	CWVLog(format, args);
	va_end(args);

	errno = _errno;
}

static const char *error_str[] = {
	[CW_ERROR_SUCCESS]		= "Success",
	[CW_ERROR_OUT_OF_MEMORY]	= "Out of Memory",
	[CW_ERROR_WRONG_ARG]		= "Wrong Argument",
	[CW_ERROR_INTERRUPTED]		= "Interrupted",
	[CW_ERROR_NEED_RESOURCE]	= "Need Resource",
	[CW_ERROR_COMUNICATING]		= "Comunicating",
	[CW_ERROR_CREATING]		= "Creating",
	[CW_ERROR_GENERAL]		= "General",
	[CW_ERROR_OPERATION_ABORTED]	= "Operation Aborted",
	[CW_ERROR_SENDING]		= "Sending",
	[CW_ERROR_RECEIVING]		= "Receiving",
	[CW_ERROR_INVALID_FORMAT]	= "Invalid Format",
	[CW_ERROR_TIME_EXPIRED]		= "Time Expired",
	[CW_ERROR_NONE]			= "None"
};

void CWDebugErrorLog()
{
	CWErrorCode error;

	if (!(error = CWErrorGetLastErrorCode()))
		return;

	if (error <= CW_ERROR_NONE)
		CWDebugLog("ERROR: %s", error_str[error]);
	else
		CWDebugLog("ERROR: %d", error);
}

#endif
