/*==============================================================*/
/* ȭ ��  ��: MonitorThread.c                                   */
/* ��  ��:                                                      */
/*--------------------------------------------------------------*/
/* ���̺귯��:                                                  */
/* �� ��  ��: ������                                            */
/* ���ȭ��: MonitorThread.h                                    */
/* �� ��  ��: 05.1.01( ���������� :  .  .)                      */
/*--------------------------------------------------------------*/
/* ��  ��:                                                      */
/*                                                              */
/*--------------------------------------------------------------*/
/*
 * $Log: MonitorThread.c,v $
 *
 *                                                              */
/*--------------------------------------------------------------*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>

#include "wips.h"
#include "IGIetc.h"
#include "ScanThread.h"


extern ap_t AccessPoint[];
extern ap_t AllowedAPDev[];
extern blocklist_t BlockList[];
extern tran_t TranData;
extern	ini_t ini;

#define _GNU_SOURCE

void *MonitorThread(void *arg)
{
  tfunc_t *func =  (tfunc_t  *)  arg;

	long firstT, lastT;
	long firstT2, lastT2;


  pthread_mutex_lock(func->lock); 
  /*
  * ��ȿ �ð�(��) ����  �ڷḦ ��´�.
  * ��ȿ�Ⱓ�� ����  ��Ŷ�� ���ؼ��� �ڷḦ List���� 
  * �����Ѵ�. ������  ��, Lock�� �ɾ��  �Ѵ�.  
  * �׷���, �о�� ��,  ����ִ°Ϳ��� Lock�� �ɸ��� 
  * �ۿ� ����. 
  * �̰���  �ذ��ϴ�  ����� ������?   ÷ ������ Lock�� 
  * �����ʴ´ٴ� �������� ����������, ���� �������� 
  * Lock�� ���� ������,�ٸ� ���μ������� data������ 
  * �ϴٰ� link��  ��������  ��Ȳ�� �߻���  ������ 
  * ���δ�.
  * ���߿�  «���� ����  �ٲ����  �������  ��������.
  */
  if (getMAC(&ini) < 0) {
    printf("[x] MAC �ּҸ� ��ȸ�� �� �����ϴ�.\n");
    printf("    %s �� ��Ȯ���ϼ���. \n", INI_SH_GET_MAC);
  }
  printf("[!] MAC=%s\n", ini.mac);

  pthread_mutex_unlock(func->lock); 

	sleep(10);

	firstT = firstT2 = 0;
  do {
  	printf("[!] Monitor Thread Running...\n");

#ifndef _SKIP_MONITOR_THREAD
		lastT = lastT2 = time(0);

		if (lastT - firstT > ini.allow_interval) {
			printf("allow-interval: %d\n", ini.allow_interval);
			printf("ini.run       : %d\n", ini.run);

			if (ini.run) GET_ALLOW_INFO(ini.sh_allow_info, ini.mac);
			firstT = time(0);
		}

		if (lastT2 - firstT2 > ini.monitor_interval) {
			if (ini.run) {
				printBlockList(BlockList);
				printAPstatus();
				prnTranData();
			}
			firstT2 = time(0);
		}
#endif
    sleep(ini.monitor_sleep);
  } while (1);
  
  printf("[!] Monitor Thread Termination\n");
  return ((void*)0);
}
