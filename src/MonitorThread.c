/*==============================================================*/
/* 화 일  명: MonitorThread.c                                   */
/* 제  목:                                                      */
/*--------------------------------------------------------------*/
/* 라이브러리:                                                  */
/* 작 성  자: 강영익                                            */
/* 헤더화일: MonitorThread.h                                    */
/* 작 성  일: 05.1.01( 최종수정일 :  .  .)                      */
/*--------------------------------------------------------------*/
/* 기  능:                                                      */
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
  * 유효 시간(초) 정의  자료를 얻는다.
  * 유효기간이 지난  패킷에 대해서는 자료를 List에서 
  * 삭제한다. 삭제할  때, Lock을 걸어야  한다.  
  * 그러면, 읽어가는 것,  집어넣는것에도 Lock이 걸릴수 
  * 밖에 없다. 
  * 이것을  해결하는  방법이 없을까?   첨 시작을 Lock을 
  * 걸지않는다는 관점에서 시작했으나, 삭제 시점에서 
  * Lock을 걸지 않으면,다른 프로세스에서 data추적을 
  * 하다가 link가  끊어지는  상황이 발생할  것으로 
  * 보인다.
  * 나중에  짬나는 데로  바꿔야할  대상으로  여겨진다.
  */
  if (getMAC(&ini) < 0) {
    printf("[x] MAC 주소를 조회할 수 없습니다.\n");
    printf("    %s 를 재확인하세요. \n", INI_SH_GET_MAC);
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
