/*==============================================================*/
/* 화 일  명: wips.h                                            */
/* 제  목:                                                      */
/*--------------------------------------------------------------*/
/* 라이브러리:                                                  */
/* 작 성  자: 강영익                                            */
/* 헤더화일: wips.h                                             */
/* 작 성  일: 05.1.01( 최종수정일 :  .  .)                      */
/*--------------------------------------------------------------*/
/* 기  능:                                                      */
/*                                                              */
/*--------------------------------------------------------------*/
/*
 * $Log: wips.h,v $
 *
 *
 *--------------------------------------------------------------*/

#ifndef _WIPS_H_

#include <pthread.h>

#define _WIPS_H_


#define _GNU_SOURCE


#ifndef MAX_STRING_LENGTH
#define MAX_STRING_LENGTH 1024
#endif

#define MAX_CHANNEL_2G 14

#define MAC(x)  x[0], x[1], x[2], x[3], x[4], x[5]
#define ISMATCH_MAC(x, y) ((x[0] == y[0]) && (x[1] == y[1]) && (x[2] == y[2]) && (x[3] == y[3]) && (x[4] == y[4]) && (x[5] == y[5]))
#define ISFFFF(x) ( (x[0] == 0xff) && (x[1]==0xff) && (x[2]==0xff) && (x[3]==0xff) && (x[4]==0xff) && (x[5]==0xff) )
#define IS0000(x) ( (x[0] == 0x00) && (x[1]==0x00) && (x[2]==0x00) && (x[3]==0x00) && (x[4]==0x00) && (x[5]==0x00) )

/*-------------------------------
 * 초기 설정 정보가 들어있는 파일
 *------------------------------*/
#ifndef INI_FILE
#define INI_FILE  "wips.ini"
#endif


/*-------------------------------
 * INI파일에서의 그룹 정보
 * Makefie 로 이동
 *------------------------------*/
#ifndef INI_AGENT_GROUP
#define INI_AGENT_GROUP   "AGENT"
#endif

#ifndef INI_MONITOR_GROUP__
#define INI_MONITOR_GROUP__   "MONITOR"
#endif


#ifndef INI_SLEEP_VAR
#define INI_SLEEP_VAR   "SLEEP"
#endif

/*----------------------------------------------
 * Agent가 수행될 개수가 정의된 항목
 * 여기에 정의될 값은 최대 (MAX_AGENT_THREAD_CNT - 2)보다
 * 작아야 한다.
 * Makefile로 이동
 *------------------------------------------*/
#ifndef INI_DISPATCHER_CNT_VAR
#define INI_DISPATCHER_CNT_VAR      "AGENT_CNT"
#endif

/*----------------------------------------------
 * wlan을 Managed/Monitor mode 전환 쉘 파일명
 *------------------------------------------*/
#define INI_SH_MANAGED_MODE      "SH_MANAGED_MODE"
#define INI_SH_MONITOR_MODE      "SH_MONITOR_MODE"
/*----------------------------------------------
 * channel 변경
 *------------------------------------------*/
#ifndef INI_SH_CHG_CHANNEL
#define INI_SH_CHG_CHANNEL      "SH_CHG_CHANNEL"
#endif

/*----------------------------------------------
 * Allow MAC정보 수신용
 *------------------------------------------*/
#ifndef INI_SH_ALLOW_INFO
#define INI_SH_ALLOW_INFO      "SH_ALLOW_INFO"
#endif

#ifndef INI_SH_ALLOW_DEVICE_INFO
#define INI_SH_ALLOW_DEVICE_INFO      "SH_ALLOW_DEVICE_INFO"
#endif

/*-------------------------------------------
 * Local wlan0의 MAC조회용
 *-----------------------------------------*/
#define INI_SH_GET_MAC         "SH_GET_MAC"

#define FILE_WLAN_MAC           "wips.mac"

/*----------------------------------------------
 * Log 파일명
 *------------------------------------------*/
#ifndef INI_LOGNAME
#define INI_LOGNAME      "LOGNAME"
#endif

#ifndef INI_REPEAT_CNT
#define INI_REPEAT_CNT      "REPEAT_CNT"
#endif

#ifndef INI_DEAUTH_AP
#define INI_DEAUTH_AP      "SH_DEAUTH_AP"
#endif

#ifndef INI_DEAUTH_DEVICE
#define INI_DEAUTH_DEVICE  "SH_DEAUTH_DEVICE"
#endif

#ifndef INI_USLEEP_VAR
#define INI_USLEEP_VAR      "USLEEP"
#endif

#ifndef INI_DEV
#define INI_DEV      "DEV"
#endif


#ifndef PCAP_TIMEOUT
#define PCAP_TIMEOUT      100
#endif

#ifndef INI_FILTER_RULE
#define INI_FILTER_RULE      "FILTER"
#endif


#ifndef INI_SCAN_INTERVAL
#define INI_SCAN_INTERVAL      "SCAN_INTERVAL"
#endif

#ifndef INI_CHANNEL_INTERVAL
#define INI_CHANNEL_INTERVAL   "CHANNEL_INTERVAL"
#endif

#define INI_ALLOW_INTERVAL     "ALLOW_INFO_INTERVAL"
#define INI_MONITOR_INTERVAL     "MONITOR_INTERVAL"

#define ALLOW_AP_FILE          "allow_ap.json"
#define ALLOW_DEVICE_FILE      "allow_device.json"

#define TEMP_EXT_NAME          "tmp"

#define JSON_ALLOW             "ALLOW"
#define JSON_SSID              "SSID"
#define JSON_MAC               "MAC"
#define JSON_REC_CNT           "CNT"
#define JSON_CHECKSUM          "CHECKSUM"
#define JSON_RUN               "RUN"
#define JSON_DATE              "DATE"
#define JSON_DEVICE            "DEVICE"
#define JSON_EXP_DATE          "EXP_DATE"
#define JSON_AP                "AP"
#define JSON_STATUS            "STATUS"


#define ALLOW_AP_SHA1_PATTERN      "%s-%s-%d-%s-%s-SIG"
#define ALLOW_DEVICE_SHA1_PATTERN  "%s-%s-SIG"

/*------------------------------------------
 * 최대로 수행될 AgentThread의 개수를 정의
 * 실제로 수행되는 Thread의 개수는 INI파일에
 * 정의된 것으로 정의한다.
 * Makefile로 이동
 *---------------------------------------*/
#ifndef MAX_DISPATCHER_CNT
#define MAX_DISPATCHER_CNT 100
#endif


#ifndef MAX_SSID_CNT
#define MAX_SSID_CNT 1024
#endif

#define MAX_DEVICE_CNT 4096

#define GET_ALLOW_DEVICE_INFO_TEMP(device, ap)  getAllowDeviceInfo(device, ap, 1)
#define GET_ALLOW_DEVICE_INFO_LOCAL(device, ap) getAllowDeviceInfo(device, ap, 0)
#define GET_ALLOW_DEVICE_INFO(device,ap)  getAllowDeviceInfo(device, ap, 1); getAllowDeviceInfo(device, ap, 0); printAllowedDevice(AllowedDevice) 

#define GET_ALLOW_INFO_TEMP(x, mac)  getAllowInfo(x, mac, 1)
#define GET_ALLOW_INFO_LOCAL(x, mac) getAllowInfo(x, mac, 0)
#define GET_ALLOW_INFO(x, mac)  getAllowInfo(x, mac, 1); getAllowInfo(x, mac, 0); printAllowedAP(AllowedAPDev) 

/*--------------------------------------------------
 * Block된 AP가 하루에 4096개를 넘지는 않을 것 같다.
 */
#define MAX_BLOCKLIST_CNT 4096

#define MAX_TRANSACTION_CNT 1024

typedef struct ap_t {
	char enable;
  char ssid[64];
  char mac[6];
  char device[6];    // 단말 미등록시 0xff 로 채움
  char exp_date[20];  // 날짜 미등록시 9999-12-31 로 채움
  unsigned int  channel;
  unsigned int frequency;
	char flag;
} ap_t;

typedef struct device_t {
	char enable;
  char device[6];
  char ap[6];
  char exp_date[20];
	char flag;
} device_t;

typedef struct tfunc_t{
  char             type;  /* main(1), monitor(2), agent(3) 구분 */
  pthread_t        thread;
  pthread_mutex_t *lock;
  void            *exec;
  enum cmd_t      *cmd;


  int              id;
  int             *flag;
  int              maxDeAuthNo;

  int              pos;
  int              usleep;
} tfunc_t;


typedef struct ini_t {
	char dev[MAX_STRING_LENGTH];
	char sh_monitor_mode[MAX_STRING_LENGTH];
	char sh_managed_mode[MAX_STRING_LENGTH];
	char sh_chg_channel[MAX_STRING_LENGTH];
	char sh_deauth_ap[MAX_STRING_LENGTH];
	char sh_deauth_device[MAX_STRING_LENGTH];
	char sh_allow_info[MAX_STRING_LENGTH];
	char sh_allow_device_info[MAX_STRING_LENGTH];
	char sh_get_mac[MAX_STRING_LENGTH];

	char logname[MAX_STRING_LENGTH];

	char filter[MAX_STRING_LENGTH];
	int agent_cnt;
	int repeat_cnt;
	int usleep;
	int monitor_sleep;
	int effective_time;

	int allow_interval;
	int channel_interval;
	int scan_interval;
	int monitor_interval;
	char mac[50];
	char run;
	char deauth;
} ini_t;


typedef struct blocklist_t {
	char device[6];
	char ssid[MAX_STRING_LENGTH];
	char ap[6];
	char date1[20];
	char time1[20];
	char date2[20];
	char time2[20];
	char flag;
} blocklist_t;


typedef struct trandata_t {
	char enable;

	char type;
	char subtype;
	unsigned int channel;
	char device[6];
	char ap[6];
} trandata_t;

typedef struct tran_t {
	int front;
	int rear;

	trandata_t *data;
} tran_t;


int getINIData(ini_t *ini);
void changeMode(char mode);

void getAllowInfo(char *s, char *mac, char isTemp);
void printAllowedAP(ap_t ap[]);
void printAllowedDevice(device_t device[]);
void printAPstatus();

void printBlockList(blocklist_t ap[]);
void addBlockList(ap_t ap);
char isRegist(ap_t ap, ap_t allowed[]);
char isDeviceRegist(trandata_t *data, ap_t allowed[]);

char isExistBlockAP();


int getMAC(ini_t *ini);

int getBlockListCnt();

void *ScanThread(void *arg);
void *MonitorThread(void *arg);
void *DeAuthThread(void *arg);
void *ChannelThread(void *arg);

#endif
