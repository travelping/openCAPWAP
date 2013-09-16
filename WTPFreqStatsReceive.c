/*******************************************************************************************
 * copyright (c) 2009 Laboratorio di Sistemi di Elaborazione e Bioingegneria Informatica   *
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
 * Author : Antonio Davoli (antonio.davoli@gmail.com)                                      *
 *                                                                                         *
 *******************************************************************************************/

#include "WTPFreqStatsReceive.h"

CW_THREAD_RETURN_TYPE CWWTPReceiveFreqStats(void *arg)
{
	int recSock, rlen, k;

	struct sockaddr_in servaddr, client_addr;
	socklen_t slen = sizeof(client_addr);

	unsigned char buffer[PACKET_SIZE];

	CWTransportMessage tm;
	CWProtocolMessage pm;
	CWBindingTransportHeaderValues binding;

	CWThreadSetSignals(SIG_BLOCK, 1, SIGALRM);

	/* Create an Inet UDP socket for this thread (Receive freq/ack packets) */

	if ((recSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		CWDebugLog("Thread Frequency Receive Stats: Error creating socket");
		CWExitThread();
	}

	/*  Set up address structure for server socket */

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	servaddr.sin_port = htons(SERVER_PORT);

	/* Binding Socket */

	if (bind(recSock, (struct sockaddr *)&servaddr, sizeof(struct sockaddr_in)) < 0) {
		CWDebugLog("Thread Frequency Receive Stats: Binding Socket Error");
		close(recSock);
		CWExitThread();
	}

	CW_REPEAT_FOREVER	/* Receive pm Loop */
	{
		k = 0;
		rlen = 0;

		if ((rlen = recvfrom(recSock, buffer, PACKET_SIZE, 0, (struct sockaddr *)&client_addr, &slen)) > 0) {
			/* Creation of stats/ack message for AC */

			CWInitTransportMessage(&pm, buffer, rlen, 1);

			CW_ZERO_MEMORY(&binding, sizeof(binding));
			binding.length = sizeof(binding.ieee80211);
			binding.ieee80211.dataRate = htons(-1);
			binding.ieee80211.SNR = 1;

			if (CWAssembleDataMessage(&tm, gWTPPathMTU, 1, BINDING_IEEE_802_11, CW_FALSE, CW_FALSE, NULL, &binding, &pm)) {
				for (k = 0; k < tm.count; k++) {
#ifdef CW_NO_DTLS
					if (!CWNetworkSendUnsafeConnected
					    (gWTPSocket, tm.parts[k].data, tm.parts[k].pos)) {
#else
					if (!CWSecuritySend
					    (gWTPSession, tm.parts[k].data, tm.parts[k].pos)) {
#endif
						CWDebugLog("Failure sending Request");
					}
				}
			}

			/* Free used Structures */
			CWReleaseTransportMessage(&tm);
		} else {
			CWDebugLog("Thread Frequency Receive Stats: Error on recvfrom");
			close(recSock);
		}
	}
}
