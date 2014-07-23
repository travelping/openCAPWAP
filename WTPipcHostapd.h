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
 * Author :  Sotiraq Sima (Sotiraq.Sima@gmail.com)                                         *
 *                                                                                         *
 *******************************************************************************************/

#ifndef __WTPipcHostapd_H
#define __WTPipcHostapd_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "smac_code.h"

#include "CWWTP.h"

void CWWTPsend_data_to_hostapd(unsigned char *buf, int len);
void CWWTPsend_command_to_hostapd_SET_TXQ(unsigned char *buf, int len);
void CWWTPsend_command_to_hostapd_SET_ADDR(unsigned char *buf, int len);
void CWWTPsend_command_to_hostapd_ADD_WLAN(unsigned char *buf, int len);
void CWWTPsend_command_to_hostapd_DEL_WLAN(unsigned char *buf, int len);
void CWWTPsend_command_to_hostapd_DEL_ADDR(unsigned char *buf, int len);
void CWWTPsend_command_to_hostapd_CLOSE(unsigned char *buf, int len);
void CWWTP_get_WTP_MDC(unsigned char *buf);
void CWWTP_get_WTP_Rates(unsigned char *buf);
unsigned char CWTP_get_WTP_Radio_Information(void);

#endif
