/*==============================================================*/
/* ȭ ��  ��: DeAuthThread.c                                    */
/* ��  ��:                                                      */
/*--------------------------------------------------------------*/
/* ���̺귯��:                                                  */
/* �� ��  ��: ������                                            */
/* ���ȭ��: DeAuthThread.c                                     */
/* �� ��  ��: 20.9.01( ���������� :  .  .)                      */
/*--------------------------------------------------------------*/
/* ��  ��:                                                      */
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
	 * ���� ������ ���� ��, ChannelThread�� channel�� ��������
	 * �ʵ��� �ϱ� ���ؼ�, ini.deauth�� ����Ѵ�.
	 * ini.deauth = 0; �� ��쿡�� ChannelThread�� �ݺ������� 
	 * ä���� ����������, ini.deauth = 1; �� ��쿡�� 
	 * ChannelThread�� ä���� �������� �ʵ��� �Ͽ���.
	 * ��, deauth�� ���� �����ϴ� ������ ini.deauth�� Set�ߴٰ�
	 * deauth�� �Ϸ��� �Ŀ��� ����(0)�Ͽ��� �Ѵ�.
	 */
	ini.deauth = 0;

  printf("[!] DeAuthentication Thread Starting....\n");

	do {
		int ch;

  	printf("[!] DeAuthentication Thread Running....\n");
		pthread_yield();

#ifndef _SKIP_DEAUTH_THREAD
		
		/*-------------------------------------------------
		 * ��ϵ��� ���� Sensor��� �۵� �ȵǵ��� ��
		 */
		if (!ini.run) {
			printf("[X] This Sensor is not registered!!!\n");
			printf("    Administrator's permission is required for this WIPS sensor to funtion properly\n");
			sleep(5);
			continue;
		}

		/*--------------------------------------------------
		 * �ּ��� ���Ǵ� AP�� 1���� ��ϵǾ� �ִ� ���,
		 * Deauth ȣ��ǵ��� �Ͽ���.  * Ȥ��, ����� ������ �����ϰ��� �� �κ��� �߰��Ѵ�.
		 */
		if (IS0000(AllowedAPDev[0].mac)) {
			if (ini.deauth == 1) changeMode(0);
			ini.deauth = 0;
			printf("[X] This WIPS Sensor is working only with settings that allow at least one AP\n");
			sleep(5);
			continue; 
		}

		/*---------------------------------------------------------
		 * TranData���ִ�, �� �ܸ��� ���ӽõ��� ����� �ܸ�->AP����
		 * ������ �����ͼ�, �ش� ����̽��� ���� ��� �Ǵ� ������ �Ѵ�.
		 * ��� ������ AllowedAPDev[]�� ������ �˻��Ͽ� ã�´�.
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
		 * �㰡�� ����̽� ������� ����SKIP
		 */
		if (isDeviceRegist(data, AllowedAPDev)) continue;

//		addBlockDeviceList(data, AllowedAPDev);


		ch = findChannelAP(data->ap);
		if (ch > 0) data->channel = ch;

		/*
		 * ä���� �ٸ��ٸ� ����
		 */
		if (ch != getCurChannel()) {
		  sprintf(buf, "./%s %s %d %s", ini.sh_chg_channel, ini.dev, ch, ini.logname); 	
			system(buf);
		}

		/*-------------------------------------------------
		 * DeAuth ȣ�� ���� �Ķ���� ����
		 * Device -> AP ������ ������
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

