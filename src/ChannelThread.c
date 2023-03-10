/*==============================================================*/
/* 화 일  명: ChannelThread.c                                   */
/* 제  목:                                                      */
/*--------------------------------------------------------------*/
/* 라이브러리:                                                  */
/* 작 성  자: 강영익                                            */
/* 헤더화일: ChannelThread.c                                    */
/* 작 성  일: 20.9.01( 최종수정일 :  .  .)                      */
/*--------------------------------------------------------------*/
/* 기  능:                                                      */
/*                                                              */
/*--------------------------------------------------------------*/
/*
 * $Log: ChannelThread.c,v $
 *
 *                                                              */
/*--------------------------------------------------------------*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>


#include "iwlib.h"
#include "wips.h"
#include "ScanThread.h"
#include "IGIetc.h"


extern ap_t         AccessPoint[];
extern ap_t         AllowedAPDev[];
extern device_t     AllowedDevice[];
extern blocklist_t  BlockList[];
extern ini_t  ini;

char overTime(long lastTime, long curTime, int interval)
{
	long gap;

	gap = curTime - lastTime;

	if (gap > interval) return 1;

	return 0;
}


void delayScanTime(int interval)
{
	usleep(interval);
}


void *ChannelThread(void *arg)
{
	int pos;
	char buf[MAX_STRING_LENGTH];
	long lastTime, curTime;
	int rt;
	int skfd;
	double freq;
	struct iwreq wrq;
	struct iw_range range;
	char buffer[128];
	int ch=0;

	tfunc_t *func = (tfunc_t *) arg;


  printf("[!] Change Channel Thread Starting....\n");


	/*-----------------------------------------------
	 * 최초 실행될 때, 채널을 전체 전환하여, 
	 * SCAN_THREAD에서 SSID를 수집한다.
	 * 강제로 한번은 실행되도록 하였다.
	 */
	skfd = iw_sockets_open();
	if (skfd < 0) { 
		printf("[X] iw_socket_open error\n");
		perror("socket");
		return ((void*)0);
	}
	rt = iw_get_range_info(skfd, ini.dev, &range);
	if (rt < 0)  {
		printf("[X] iw_get_range_info error\n");
		perror("socket");
		return ((void*)0);
	}
	for (int j=0; j<range.num_frequency; j++) {
		freq = iw_freq2float(&(range.freq[j]));
		iw_print_freq_value(buffer, sizeof(buffer), freq);
#ifdef DEBUG_CHANNEL_DETAIL
		printf("[!] Channel Scanning #%.3d : %s\r", range.freq[j].i, buffer);
		fflush(stdout);
#endif

		sprintf(buf, "./%s %s %d %s", ini.sh_chg_channel, ini.dev, range.freq[j].i, ini.logname);
//		printf("%s\n", buf);

		while (ini.deauth) usleep(1000);	

		system(buf);
		delayScanTime(ini.channel_interval);
	}

	pos = -1;
	lastTime = time(0);
	do {
		int channel;

  	printf("[!] Channel Thread Running....\n");
		sleep(0);

		pos++;
		curTime = time(0);

//		if (!isExistBlockAP() || overTime(lastTime, curTime, ini.scan_interval)) {
		if (overTime(lastTime, curTime, ini.scan_interval) || IS0000(AccessPoint[0].mac)) {
			lastTime = curTime;

//			memset(AccessPoint, 0, sizeof(AccessPoint));

			/*---------------------------------------------------------
	 		 * scan_interval이 지났다면, SSID를 스캔한다.
	 		 *
   		 * 한번 스캔 할 때마다, 채널 1 부터 채널을 0.5초 유지하도록 하고, 
   		 * 채널을 증가시킨다.
	 		 * 총 14개 채널을 조회하는데 총 7초가 소요된다.
	 		 */
			if (iw_get_range_info(skfd, ini.dev, &range) < 0)  {
				fprintf(stderr, "%-8.16s no frequency information.\n\n", ini.dev);
				sleep(1);
				continue;
			}
			printf("\n");

			for (int j=0; j<range.num_frequency; j++) {
				freq = iw_freq2float(&(range.freq[j]));
				iw_print_freq_value(buffer, sizeof(buffer), freq);
#ifdef DEBUG_CHANNEL_DETAIL
				printf("[!] Channel Scanning #%.3d : %s\r", range.freq[j].i, buffer);
				fflush(stdout);
#endif

				sprintf(buf, "./%s %s %d %s", ini.sh_chg_channel, ini.dev, range.freq[j].i, ini.logname);
				while (ini.deauth) usleep(1000);	

				system(buf);
				delayScanTime(ini.channel_interval);
			}
		}
		printf("\n");
		ch = 0;
		for (int i=0; i<MAX_SSID_CNT; i++) {

			if (!AccessPoint[i].enable && IS0000(AccessPoint[i].mac)) break;
			if (!AccessPoint[i].enable) continue;

			if (ch == AccessPoint[i].channel) continue;
			ch = AccessPoint[i].channel;

#ifdef DEBUG_CHANNEL_DETAIL
			printf("[!] Channel Scanning #%.3d : %3.1fGhz\r", AccessPoint[i].channel, AccessPoint[i].frequency/1000.0);
			fflush(stdout);
#endif
			sprintf(buf, "./%s %s %d %s", ini.sh_chg_channel, ini.dev, AccessPoint[i].channel, ini.logname);
			while (ini.deauth) usleep(1000);	
			sleep(0);

			system(buf);
			delayScanTime(ini.channel_interval);
		}
		

		/*-------------------------------------------------
		 * 더이상 조회할 SSID정보가 없거나, 배열을 초과할 경우, 
		 * 0 부터 다시 시작한다.
		 * 무한 루프 걸릴 듯 하여, sleep()을 주고, yield()를 호출함.
		 */
		if ( (pos >= MAX_SSID_CNT) ||  
          (!AccessPoint[pos].enable && IS0000(AccessPoint[pos].mac)) ) {
			pos = -1;
			usleep(1000);
			pthread_yield();

			continue;
		}

	} while (1);

	iw_sockets_close(skfd);

  printf("[!] ChannelThread Termination\n");
  return ((void*)0);
}

