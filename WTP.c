/************************************************************************************************
 * Copyright (c) 2006-2009 Laboratorio di Sistemi di Elaborazione e Bioingegneria Informatica   *
 *                          Universita' Campus BioMedico - Italy                                *
 *                                                                                              *
 * This program is free software; you can redistribute it and/or modify it under the terms      *
 * of the GNU General Public License as published by the Free Software Foundation; either       *
 * version 2 of the License, or (at your option) any later version.                             *
 *                                                                                              *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY              *
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A              *
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.                     *
 *                                                                                              *
 * You should have received a copy of the GNU General Public License along with this            *
 * program; if not, write to the:                                                               *
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,                         *
 * MA  02111-1307, USA.                                                                         *
 *                                                                                              *
 * In addition, as a special exception, the copyright holders give permission to link the       *
 * code of portions of this program with the OpenSSL library under certain conditions as        *
 * described in each individual source file, and distribute linked combinations including       *
 * the two. You must obey the GNU General Public License in all respects for all of the         *
 * code used other than OpenSSL.  If you modify file(s) with this exception, you may            *
 * extend this exception to your version of the file(s), but you are not obligated to do        *
 * so.  If you do not wish to do so, delete this exception statement from your version.         *
 * If you delete this exception statement from all source files in the program, then also       *
 * delete it here.                                                                              *
 *                                                                                              *
 * -------------------------------------------------------------------------------------------- *
 * Project:  Capwap                                                                             *
 *                                                                                              *
 * Authors : Ludovico Rossi (ludo@bluepixysw.com)                                               *
 *           Del Moro Andrea (andrea_delmoro@libero.it)                                         *
 *           Giovannini Federica (giovannini.federica@gmail.com)                                *
 *           Massimo Vellucci (m.vellucci@unicampus.it)                                         *
 *           Mauro Bisson (mauro.bis@gmail.com)                                                 *
 *           Antonio Davoli (antonio.davoli@gmail.com)                                          *
 ************************************************************************************************/

#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include "CWWTP.h"

#ifdef SOFTMAC
CW_THREAD_RETURN_TYPE CWWTPThread_read_data_from_hostapd(void *arg);
#endif

CW_THREAD_RETURN_TYPE CWWTPReceiveFrame(void *arg);
CW_THREAD_RETURN_TYPE CWWTPReceiveStats(void *arg);
CW_THREAD_RETURN_TYPE CWWTPReceiveFreqStats(void *arg);
CW_THREAD_RETURN_TYPE gogo(void *arg);

const char gWtpVersion[] = PACKAGE_VERSION;

int gEnabledLog;
int gMaxLogFileSize;
char gLogFileName[] = WTP_LOG_FILE_NAME;

/* addresses of ACs for Discovery */
char **gCWACAddresses;
int gCWACCount = 0;

int gIPv4StatusDuplicate = 0;
int gIPv6StatusDuplicate = 0;

char *gWTPLocation = NULL;
char *gWTPName = NULL;
unsigned char gWTPSessionID[16];

/* if not NULL, jump Discovery and use this address for Joining */
char *gWTPForceACAddress = NULL;
CWAuthSecurity gWTPForceSecurity;

/* UDP network socket */
CWSocket gWTPSocket = -1;
CWSocket gWTPDataSocket = -1;
/* DTLS session vars */
CWSecurityContext gWTPSecurityContext = NULL;
CWSecuritySession gWTPSession = NULL;

/* list used to pass frames from wireless interface to main thread */
CWSafeList gFrameList;

/* list used to pass CAPWAP packets from AC to main thread */
CWSafeList gPacketReceiveList;

/* used to synchronize access to the lists */
CWThreadCondition gInterfaceWait;
CWThreadMutex gInterfaceMutex;

/* infos about the ACs to discover */
CWACDescriptor *gCWACList = NULL;
/* infos on the better AC we discovered so far */
CWACInfoValues *gACInfoPtr = NULL;

/* WTP statistics timer */
int gWTPStatisticsTimer = CW_STATISTIC_TIMER_DEFAULT;

WTPRebootStatisticsInfo gWTPRebootStatistics;
CWWTPRadiosInfo gRadiosInfo;

/* path MTU of the current session */
int gWTPPathMTU = 0;

unsigned char gWTPMACMode = CW_SPLIT_MAC;
unsigned char gWTPTunnelMode = CW_TUNNEL_MODE_802_DOT_11_TUNNEL;

int gWTPRetransmissionCount;

CWPendingRequestMessage gPendingRequestMsgs[MAX_PENDING_REQUEST_MSGS];

CWBool WTPExitOnUpdateCommit = CW_FALSE;
#define CW_SINGLE_THREAD

/*
 * Receive a message, that can be fragmented. This is useful not only for the Join State
 */
CWBool CWReceiveMessage(CWProtocolMessage *pm)
{
	int readBytes;
	unsigned char buf[CW_BUFFER_SIZE];
	CWProtocolMessage msg;
	CWFragmentBufferList frag_buffer;

	CW_ZERO_MEMORY(&frag_buffer, sizeof(CWFragmentBufferList));

	CW_REPEAT_FOREVER {
		CW_ZERO_MEMORY(buf, CW_BUFFER_SIZE);
#ifdef CW_NO_DTLS
		unsigned char *pkt;

		CWLockSafeList(gPacketReceiveList);
		while (CWGetCountElementFromSafeList(gPacketReceiveList) == 0)
			CWWaitElementFromSafeList(gPacketReceiveList);

		pkt = CWRemoveHeadElementFromSafeListwithDataFlag(gPacketReceiveList, &readBytes, &dataFlag);
		CWUnlockSafeList(gPacketReceiveList);
		CWInitTransportMessage(&msg, pkt, readBytes, 0);
#else
		if (!CWSecurityReceive(gWTPSession, buf, CW_BUFFER_SIZE, &readBytes))
			return CW_FALSE;

		CWInitTransportMessage(&msg, buf, readBytes, 1);
#endif

		if (CWProtocolParseFragment(&msg, &frag_buffer, pm))
			/* the message is fully reassembled */
			return CW_TRUE;

		if (CWErrorGetLastErrorCode() != CW_ERROR_NEED_RESOURCE) {
			CWDebugErrorLog();
			CWReleaseMessage(&msg);

			return CW_FALSE;
		}

		/* we need at least one more fragment */
	}

	return CW_TRUE;
}

CWBool CWWTPSendAcknowledgedPacket(int seqNum,
				   CWList msgElemlist,
				   CWBool(assembleFunc) (CWTransportMessage *, int, int, CWList),
				   CWBool(parseFunc) (CWProtocolMessage *, int, void *),
				   CWBool(saveFunc) (void *), void *valuesPtr)
{

	CWTransportMessage tm;
	CWProtocolMessage msg;
	int i;

	struct timespec timewait;

	int gTimeToSleep = gCWRetransmitTimer;
	int gMaxTimeToSleep = CW_ECHO_INTERVAL_DEFAULT / 2;

	CW_ZERO_MEMORY(&tm, sizeof(CWTransportMessage));
	CW_ZERO_MEMORY(&msg, sizeof(CWProtocolMessage));

	if (!assembleFunc(&tm, gWTPPathMTU, seqNum, msgElemlist))
		goto cw_failure;

	gWTPRetransmissionCount = 0;

	while (gWTPRetransmissionCount < gCWMaxRetransmit) {
		CWDebugLog("Transmission Num:%d", gWTPRetransmissionCount);
		for (i = 0; i < tm.count; i++) {
#ifdef CW_NO_DTLS
			if (!CWNetworkSendUnsafeConnected(gWTPSocket, tm.parts[i].data, tm.parts[i].pos))
#else
			if (!CWSecuritySend(gWTPSession, tm.parts[i].data, tm.parts[i].pos))
#endif
			{
				CWDebugLog("Failure sending Request");
				goto cw_failure;
			}
		}

		timewait.tv_sec = time(0) + gTimeToSleep;
		timewait.tv_nsec = 0;

		CW_REPEAT_FOREVER {
			CWThreadMutexLock(&gInterfaceMutex);

			if (CWGetCountElementFromSafeList(gPacketReceiveList) > 0)
				CWErrorRaise(CW_ERROR_SUCCESS, NULL);
			else {
				if (CWErr(CWWaitThreadConditionTimeout(&gInterfaceWait, &gInterfaceMutex, &timewait)))
					CWErrorRaise(CW_ERROR_SUCCESS, NULL);
			}

			CWThreadMutexUnlock(&gInterfaceMutex);

			switch (CWErrorGetLastErrorCode()) {

			case CW_ERROR_TIME_EXPIRED:{
					gWTPRetransmissionCount++;
					goto cw_continue_external_loop;
					break;
				}

			case CW_ERROR_SUCCESS:
			{
				CWProtocolTransportHeaderValues transportHeader;

				/* there's something to read */
				if (!(CWReceiveMessage(&msg))) {
					CWReleaseMessage(&msg);
					CWDebugLog("Failure Receiving Response");
					goto cw_failure;
				}

				CWParseTransportHeader(&msg, &transportHeader, NULL);

				if (!(parseFunc(&msg, seqNum, valuesPtr))) {
					if (CWErrorGetLastErrorCode() != CW_ERROR_INVALID_FORMAT) {
						CWReleaseMessage(&msg);
						CWDebugLog("Failure Parsing Response");
						goto cw_failure;
					} else {
						CWErrorHandleLast();
						gWTPRetransmissionCount++;
						goto cw_continue_external_loop;

						break;
					}
				}

				if ((saveFunc(valuesPtr))) {
					CWDebugLog("Success Saving Response");
					goto cw_success;
				}
				if (CWErrorGetLastErrorCode() != CW_ERROR_INVALID_FORMAT) {
					CWReleaseMessage(&msg);
					CWDebugLog("Failure Saving Response");
					goto cw_failure;
				}
				break;
			}

			case CW_ERROR_INTERRUPTED:{
					gWTPRetransmissionCount++;
					goto cw_continue_external_loop;
					break;
				}
			default:{
					CWErrorHandleLast();
					CWDebugLog("Failure");
					goto cw_failure;
					break;
				}
			}
		}

 cw_continue_external_loop:
		CWDebugLog("Retransmission time is over");

		gTimeToSleep <<= 1;
		if (gTimeToSleep > gMaxTimeToSleep)
			gTimeToSleep = gMaxTimeToSleep;
	}

	/* too many retransmissions */
	return CWErrorRaise(CW_ERROR_NEED_RESOURCE, "Peer Dead");

 cw_success:
	CWReleaseTransportMessage(&tm);
	CWReleaseMessage(&msg);

	return CW_TRUE;

 cw_failure:
	CWReleaseTransportMessage(&tm);
	CWReleaseMessage(&msg);

	CWDebugLog("Failure");
	return CW_FALSE;
}

void usage(void)
{
}

int main(int argc, char * const argv[])
{
	int run_daemon = 1;
	int c;

#ifdef CW_DEBUGGING
	const struct rlimit rlim = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY
	};

	/* unlimited size for cores */
	setrlimit(RLIMIT_CORE, &rlim);
#endif

	printf("WTP, v%s, %s, %s\n", PACKAGE_VERSION, __DATE__, __TIME__);

	while (-1 != (c = getopt(argc, argv, "dhfc:s:"))) {
		switch(c) {
		case 'd':
			gEnabledLog = 1;
			break;

		case 'h':
			usage();
			exit(1);
			break;

		case 'f':
			run_daemon = 0;
			break;

		case 'c':
			gCWConfigFileName = optarg;
			break;

		case 's':
			gCWSettingsFileName = optarg;
			break;

		default:
			usage();
			exit(1);
			break;
		}
	}

	/* Daemon Mode */
	if (run_daemon)
		if (daemon(1, 0) != 0) {
			fprintf(stderr, "daemon failed: %s\n", strerror(errno));
			exit(1);

		}

	CWStateTransition nextState = CW_ENTER_DISCOVERY;
	CWLogInitFile(WTP_LOG_FILE_NAME);

#ifndef CW_SINGLE_THREAD
	CWDebugLog("Use Threads");
#else
	CWDebugLog("Don't Use Threads");
#endif
	CWErrorHandlingInitLib();
	if (!CWParseSettingsFile()) {
		CWLog("Can't start WTP");
		exit(1);
	}

	/* Capwap receive packets list */
	if (!CWErr(CWCreateSafeList(&gPacketReceiveList))) {
		CWLog("Can't start WTP");
		exit(1);
	}

	/* Capwap receive frame list */
	if (!CWErr(CWCreateSafeList(&gFrameList))) {
		CWLog("Can't start WTP");
		exit(1);
	}

	CWCreateThreadMutex(&gInterfaceMutex);
	CWSetMutexSafeList(gPacketReceiveList, &gInterfaceMutex);
	CWSetMutexSafeList(gFrameList, &gInterfaceMutex);
	CWCreateThreadCondition(&gInterfaceWait);
	CWSetConditionSafeList(gPacketReceiveList, &gInterfaceWait);
	CWSetConditionSafeList(gFrameList, &gInterfaceWait);

	CWLog("Starting WTP...");

	CWRandomInitLib();

	CWThreadSetSignals(SIG_BLOCK, 1, SIGALRM);

	if (timer_init() == 0) {
		CWLog("Can't init timer module");
		exit(1);
	}

#ifdef CW_NO_DTLS
	if (!CWErr(CWWTPLoadConfiguration())) {
#else
	if (!CWErr(CWSecurityInitLib()) || !CWErr(CWWTPLoadConfiguration())) {
#endif
		CWLog("Can't start WTP");
		exit(1);
	}

	CWDebugLog("Init WTP Radio Info");
	if (!CWWTPInitConfiguration()) {
		CWLog("Error Init Configuration");
		exit(1);
	}
#ifdef SOFTMAC
	CWThread thread_ipc_with_wtp_hostapd;
	if (!CWErr(CWCreateThread(&thread_ipc_with_wtp_hostapd, CWWTPThread_read_data_from_hostapd, NULL))) {
		CWLog("Error starting Thread that receive command and 802.11 frame from hostapd (WTP side)");
		exit(1);
	}
#endif

	CWThread thread_receiveFrame;
	if (!CWErr(CWCreateThread(&thread_receiveFrame, CWWTPReceiveFrame, NULL))) {
		CWLog("Error starting Thread that receive binding frame");
		exit(1);
	}

	CWThread thread_receiveStats;
	if (!CWErr(CWCreateThread(&thread_receiveStats, CWWTPReceiveStats, NULL))) {
		CWLog("Error starting Thread that receive stats on monitoring interface");
		exit(1);
	}

	CWThread thread_receiveFreqStats;
	if (!CWErr(CWCreateThread(&thread_receiveFreqStats, CWWTPReceiveFreqStats, NULL))) {
		CWLog("Error starting Thread that receive frequency stats on monitoring interface");
		exit(1);
	}

	/* if AC address is given jump Discovery and use this address for Joining */
	if (gWTPForceACAddress != NULL)
		nextState = CW_ENTER_JOIN;

	/* start CAPWAP state machine */
	CW_REPEAT_FOREVER {
		switch (nextState) {
		case CW_ENTER_DISCOVERY:
			nextState = CWWTPEnterDiscovery();
			break;
		case CW_ENTER_SULKING:
			nextState = CWWTPEnterSulking();
			break;
		case CW_ENTER_JOIN:
			nextState = CWWTPEnterJoin();
			break;
		case CW_ENTER_CONFIGURE:
			nextState = CWWTPEnterConfigure();
			break;
		case CW_ENTER_DATA_CHECK:
			nextState = CWWTPEnterDataCheck();
			break;
		case CW_ENTER_RUN:
			nextState = CWWTPEnterRun();
			break;
		case CW_ENTER_RESET:
			/*
			 * CWStopHeartbeatTimer();
			 * CWStopNeighborDeadTimer();
			 * CWNetworkCloseSocket(gWTPSocket);
			 * CWSecurityDestroySession(&gWTPSession);
			 * CWSecurityDestroyContext(&gWTPSecurityContext);
			 */
			nextState = CW_ENTER_DISCOVERY;
			break;
		case CW_QUIT:
			CWWTPDestroy();
			return 0;
		}
	}
}

unsigned int CWGetSeqNum()
{
	static unsigned int seqNum = 0;

	if (seqNum == CW_MAX_SEQ_NUM)
		seqNum = 0;
	else
		seqNum++;
	return seqNum;
}

int CWGetFragmentID()
{
	static int fragID = 0;
	return fragID++;
}

/*
 * Parses config file and inits WTP configuration.
 */
CWBool CWWTPLoadConfiguration()
{
	int i;

	CWLog("WTP Loads Configuration");

	/* get saved preferences */
	if (!CWErr(CWParseConfigFile())) {
		CWLog("Can't Read Config File");
		exit(1);
	}

	if (gCWACCount == 0)
		return CWErrorRaise(CW_ERROR_NEED_RESOURCE, "No AC Configured");

	if (!(gCWACList = ralloc_array(NULL, CWACDescriptor, gCWACCount)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);

	for (i = 0; i < gCWACCount; i++) {

		CWDebugLog("Init Configuration for AC at %s", gCWACAddresses[i]);
		if (!(gCWACList[i].address = ralloc_strdup(gCWACList, gCWACAddresses[i]))) {
			ralloc_free(gCWACList);
			return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
		}
	}

	CW_FREE_OBJECTS_ARRAY(gCWACAddresses, gCWACCount);
	return CW_TRUE;
}

void CWWTPDestroy()
{
	int i;

	CWLog("Destroy WTP");

	for (i = 0; i < gCWACCount; i++) {
		CW_FREE_OBJECT(gCWACList[i].address);
	}

	timer_destroy();

	CW_FREE_OBJECT(gCWACList);
	CW_FREE_OBJECT(gRadiosInfo.radiosInfo);
}

CWBool CWWTPInitConfiguration()
{
	CWDebugLog("CWWTPInitConfiguration");
	int i;

	//Generate 128-bit Session ID,
	initWTPSessionID(&gWTPSessionID[0]);

	CWWTPResetRebootStatistics(&gWTPRebootStatistics);

	gRadiosInfo.radioCount = CWWTPGetMaxRadios();

	if (!(gRadiosInfo.radiosInfo = ralloc_array(NULL, CWWTPRadioInfoValues, gRadiosInfo.radioCount)))
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
	gRadiosInfo.radiosInfo[0].radioID = 0;

	/* gRadiosInfo.radiosInfo[0].numEntries = 0; */
	gRadiosInfo.radiosInfo[0].decryptErrorMACAddressList = NULL;
	gRadiosInfo.radiosInfo[0].reportInterval = CW_REPORT_INTERVAL_DEFAULT;
	gRadiosInfo.radiosInfo[0].adminState = ENABLED;
	gRadiosInfo.radiosInfo[0].adminCause = AD_NORMAL;
	gRadiosInfo.radiosInfo[0].operationalState = ENABLED;
	gRadiosInfo.radiosInfo[0].operationalCause = OP_NORMAL;
	gRadiosInfo.radiosInfo[0].TxQueueLevel = 0;
	gRadiosInfo.radiosInfo[0].wirelessLinkFramesPerSec = 0;

	CWWTPResetRadioStatistics(&(gRadiosInfo.radiosInfo[0].statistics));

	if (!CWWTPInitBinding(0)) {
		return CW_FALSE;
	}

	for (i = 1; i < gRadiosInfo.radioCount; i++) {
		gRadiosInfo.radiosInfo[i].radioID = i;
		/* gRadiosInfo.radiosInfo[i].numEntries = 0; */
		gRadiosInfo.radiosInfo[i].decryptErrorMACAddressList = NULL;
		gRadiosInfo.radiosInfo[i].reportInterval = CW_REPORT_INTERVAL_DEFAULT;
		/* Default value for CAPWA� */
		gRadiosInfo.radiosInfo[i].adminState = ENABLED;
		gRadiosInfo.radiosInfo[i].adminCause = AD_NORMAL;
		gRadiosInfo.radiosInfo[i].operationalState = DISABLED;
		gRadiosInfo.radiosInfo[i].operationalCause = OP_NORMAL;
		gRadiosInfo.radiosInfo[i].TxQueueLevel = 0;
		gRadiosInfo.radiosInfo[i].wirelessLinkFramesPerSec = 0;
		CWWTPResetRadioStatistics(&(gRadiosInfo.radiosInfo[i].statistics));
		if (!CWWTPInitBinding(i)) {
			return CW_FALSE;
		}
	}

	return CW_TRUE;
}
