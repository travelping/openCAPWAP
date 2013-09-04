/*******************************************************************************************
 * Copyright (c) 2006-9 Laboratorio di Sistemi di Elaborazione e Bioingegneria Informatica *
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
 *           Antonio Davoli (antonio.davoli@gmail.com)                                     *
 *******************************************************************************************/

#ifndef __CAPWAP_CWCommon_HEADER__
#define __CAPWAP_CWCommon_HEADER__

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#ifdef MACOSX
#include <netinet/if_ether.h>
#else
#include <linux/if_ether.h>
#endif
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "wireless_copy.h"
#include "ralloc.h"

// make sure the types really have the right sizes
#define CW_COMPILE_TIME_ASSERT(name, x)               typedef int CWDummy_ ## name[(x) * 2 - 1]

// if you get a compile error, change types (NOT VALUES!) according to your system
CW_COMPILE_TIME_ASSERT(int_size, sizeof(int) == 4);
CW_COMPILE_TIME_ASSERT(char_size, sizeof(char) == 1);

#define     CW_BUFFER_SIZE                  65536
#define     CW_ZERO_MEMORY                  bzero
#define     CW_COPY_MEMORY(dst, src, len)           bcopy(src, dst, len)
#define     CW_REPEAT_FOREVER               while(1)

#define DEFAULT_LOG_SIZE                    1000000

typedef enum {
	CW_FALSE = 0,
	CW_TRUE = 1
} CWBool;

typedef enum {
	CW_ENTER_SULKING,
	CW_ENTER_DISCOVERY,
	CW_ENTER_JOIN,
	CW_ENTER_CONFIGURE,
	CW_ENTER_DATA_CHECK,
	CW_ENTER_RUN,
	CW_ENTER_RESET,
	CW_QUIT
} CWStateTransition;

extern char *gCWConfigFileName;
extern char *gCWSettingsFileName;

extern int gCWForceMTU;
extern int gCWRetransmitTimer;
extern int gCWNeighborDeadInterval;
extern int gCWNeighborDeadRestartDelta;
extern int gCWWaitJoin;
extern int gCWMaxRetransmit;
extern int gMaxLogFileSize;
extern int gEnabledLog;
extern int gDataChannelKeepAliveInterval;
extern int gConfigDataChannelKeepAliveInterval;
extern int gAggressiveDataChannelKeepAliveInterval;
extern int gEchoInterval;

#define CW_ON_ERROR(cond, on_err)					\
	do {								\
		if (!(cond)) {						\
			on_err						\
		}							\
	} while (0)

#define CW_FREE_OBJECT(ptr)						\
	do {								\
		ralloc_free((ptr));					\
		(ptr) = NULL;						\
	} while (0)

#define CW_FREE_OBJECTS_ARRAY(array, size)				\
	do {								\
		int _i = 0;						\
		for(_i = ((size)-1); _i >= 0; _i--)			\
			ralloc_free((array)[_i]);			\
		ralloc_free((array));					\
		(array) = NULL;						\
	} while (0)

#define CW_PRINT_STRING_ARRAY(array, size)				\
	do {								\
		int i = 0;						\
		for(i = 0; i < (size); i++)				\
			printf("[%d]: **%s**\n", i, (array)[i]);	\
	} while (0)

static inline void *ralloc_memdup(const void *ctx, void *src, size_t size)
{
	void *dest;

	if (!(dest = ralloc_size(ctx, size)))
		return NULL;
	return memcpy(dest, src, size);
}

#include "CWStevens.h"
#include "config.h"
#include "CWLog.h"
#include "CWErrorHandling.h"

#include "CWRandom.h"
//#include "CWTimer.h"
#include "timerlib.h"
#include "CWThread.h"
#include "CWNetwork.h"
#include "CWList.h"
#include "CWSafeList.h"

#include "CWProtocol.h"
#include "CWSecurity.h"
#include "CWConfigFile.h"

int CWTimevalSubtract(struct timeval *res, const struct timeval *x, const struct timeval *y);
CWBool CWParseSettingsFile();
void CWErrorHandlingInitLib();

#endif
