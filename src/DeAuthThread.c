/*==============================================================*/
/* 화 일  명: DeAuthThread.c                                    */
/* 제  목:                                                      */
/*--------------------------------------------------------------*/
/* 라이브러리:                                                  */
/* 작 성  자: 강영익                                            */
/* 헤더화일: DeAuthThread.c                                     */
/* 작 성  일: 20.9.01( 최종수정일 :  .  .)                      */
/*--------------------------------------------------------------*/
/* 기  능:                                                      */
/*                                                              */
/*--------------------------------------------------------------*/
/*
 * $Log: DeAuthThread.c,v $
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

int findChannelAP(char *mac)
{

	for (int i=0; i<MAX_SSID_CNT; i++) {
		if (ISMATCH_MAC(mac, AccessPoint[i].mac)) return AccessPoint[i].channel;
	}
	return 0;
}

int getCurChannel()
{
	struct iwreq wrq;
	struct iw_range range;
	double freq;
	int channel;
	int skfd, rt;
	
	skfd = iw_sockets_open();
	if (skfd < 0) {
		perror("socket");
		return 0;
	}
	rt = iw_get_range_info(skfd, ini.dev, &range);
	if (rt < 0) {
		perror("socket");
		iw_sockets_close(skfd);
		return 0;
	}

	rt = iw_get_ext(skfd, ini.dev, SIOCGIWFREQ, &wrq);
	if (rt < 0)  {
		perror("socket");
		iw_sockets_close(skfd);
		return 0;
	}
	freq = iw_freq2float(&(wrq.u.freq));
	channel = iw_freq_to_channel(freq, &range);

	iw_sockets_close(skfd);
	return channel;
}


void *DeAuthThread(void *arg)
{
	char buf[MAX_STRING_LENGTH];
	trandata_t *data;

 
	tfunc_t *func = (tfunc_t *) arg;


	/*------------------------------
	 * 실제 세션을 끊을 때, ChannelThread가 channel을 변경하지
	 * 않도록 하기 위해서, ini.deauth를 사용한다.
	 * ini.deauth = 0; 인 경우에는 ChannelThread가 반복적으로 
	 * 채널을 변경하지만, ini.deauth = 1; 인 경우에는 
	 * ChannelThread가 채널을 변경하지 않도록 하였다.
	 * 즉, deauth를 실제 수행하는 시점에 ini.deauth를 Set했다가
	 * deauth를 완료한 후에는 원복(0)하여야 한다.
	 */
	ini.deauth = 0;

  printf("[!] DeAuthentication Thread Starting....\n");

	do {
		int ch;

  	printf("[!] DeAuthentication Thread Running....\n");
		pthread_yield();

#ifndef _SKIP_DEAUTH_THREAD
		
		/*-------------------------------------------------
		 * 등록되지 않은 Sensor라면 작동 안되도록 함
		 */
		if (!ini.run) {
			printf("[X] This Sensor is not registered!!!\n");
			printf("    Administrator's permission is required for this WIPS sensor to funtion properly\n");
			sleep(5);
			continue;
		}

		/*--------------------------------------------------
		 * 최소한 허용되는 AP가 1개라도 등록되어 있는 경우,
		 * Deauth 호출되도록 하였다.  * 혹시, 운영상의 오류를 방지하고자 이 부분을 추가한다.
		 */
		if (IS0000(AllowedAPDev[0].mac)) {
			if (ini.deauth == 1) changeMode(0);
			ini.deauth = 0;
			printf("[X] This WIPS Sensor is working only with settings that allow at least one AP\n");
			sleep(5);
			continue; 
		}

		/*---------------------------------------------------------
		 * TranData에있는, 즉 단말이 접속시도한 경우의 단말->AP접속
		 * 정보를 가져와서, 해당 디바이스에 대한 허용 또는 차단을 한다.
		 * 허용 정보는 AllowedAPDev[]의 정보를 검색하여 찾는다.
		 *
		 */
	  pthread_mutex_lock(func->lock);
		data = getTranData();
	  pthread_mutex_unlock(func->lock);
		if (data == NULL) {
//			printf("************************************************\n");
//			printf("**     Transaction Data Empty        ***********\n");
//			printf("************************************************\n");
			if (ini.deauth == 1) changeMode(0);
			ini.deauth = 0;
			sleep(1);
			usleep(5000);
			continue;
		}
		if (ini.deauth == 0) changeMode(0);
		ini.deauth = 1;

		
		
		printf("[!] DeAuth: ch = %d mac=%02x:%02x:%02x:%02x:%02x:%02x\n", data->channel, MAC(data->device));
		/*
		 * 허가된 디바이스 정보라면 차단SKIP
		 */
		if (isDeviceRegist(data, AllowedAPDev)) continue;

//		addBlockDeviceList(data, AllowedAPDev);


		ch = findChannelAP(data->ap);
		if (ch > 0) data->channel = ch;

		/*
		 * 채널이 다르다면 변경
		 */
		if (ch != getCurChannel()) {
		  sprintf(buf, "./%s %s %d %s", ini.sh_chg_channel, ini.dev, ch, ini.logname); 	
			system(buf);
		}

		/*-------------------------------------------------
		 * DeAuth 호출 위한 파라미터 설정
		 * Device -> AP 접속을 차단함
		 */
		sprintf(buf, "./%s %d %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x %d %s",
				ini.sh_deauth_device, ini.repeat_cnt, MAC(data->device), MAC(data->ap), data->channel, ini.dev);

		system(buf);

#else
		sleep(5);
#endif  // _SKIP_DEAUTH_THREAD

	} while (1);

  printf("[!] DeAuthentication Thread Termination\n");
  return ((void*)0);
}

