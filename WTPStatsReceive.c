/*******************************************************************************************
 * Copyright (c) 2008 Laboratorio di Sistemi di Elaborazione e Bioingegneria Informatica *
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
 * Author : Daniele De Sanctis (danieledesanctis@gmail.com)                                *
 *                                                                     *
 *******************************************************************************************/

#include "WTPStatsReceive.h"

CW_THREAD_RETURN_TYPE CWWTPReceiveStats(void *arg)
{

	int sock, rlen, len, k, fromlen;
	struct sockaddr_un servaddr;
	struct sockaddr_un from;
	unsigned char buffer[PACKET_SIZE + 1];
	CWTransportMessage tm;
	CWProtocolMessage pm;
	CWBindingTransportHeaderValues binding;

	CWThreadSetSignals(SIG_BLOCK, 1, SIGALRM);

	/*      Create a UNIX datagram socket for this thread        */
	if ((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
		CWDebugLog("THR STATS: Error creating socket");
		CWExitThread();
	}

	/*      Set up address structure for server socket      */
	bzero(&servaddr, sizeof(servaddr));
	bzero(&from, sizeof(from));
	servaddr.sun_family = AF_UNIX;
	strcpy(servaddr.sun_path, SOCKET_PATH);

	unlink(SOCKET_PATH);

	len = sizeof(servaddr.sun_family) + strlen(servaddr.sun_path);

	if (bind(sock, (const struct sockaddr *)&servaddr, len) < 0) {
		CWDebugLog("THR STATS: Error binding socket");
		CWExitThread();
	}

	fromlen = sizeof(from);

	/*      Receive data */
	CW_REPEAT_FOREVER {
		rlen = recvfrom(sock, buffer, PACKET_SIZE, 0, (struct sockaddr *)&from, (socklen_t *) & fromlen);
		if (rlen == -1) {
			CWDebugLog("THR STATS: Error receiving from unix socket");
			CWExitThread();
		} else {
			CWInitTransportMessage(&pm, buffer, rlen, 1);

			CW_ZERO_MEMORY(&binding, sizeof(binding));
			binding.length = sizeof(binding.ieee80211);
			binding.ieee80211.dataRate = htons(-1);

			if (CWAssembleDataMessage(&tm, gWTPPathMTU, 1, BINDING_IEEE_802_11, CW_TRUE, CW_FALSE, NULL, &binding, &pm)) {
				for (k = 0; k < tm.count; k++) {
#ifdef CW_NO_DTLS
					if (!CWNetworkSendUnsafeConnected
					    (gWTPSocket, tm.parts[k].data, tm.parts[k].pos)) {
#else
					if (!CWSecuritySend
					    (gWTPSession, tm.parts[k].data, tm.parts[k].pos)) {
#endif
						CWDebugLog("Failure sending Request");
						break;
					}
				}
			}

			CWReleaseTransportMessage(&tm);
		}
	}

	close(sock);
	return (NULL);
}
