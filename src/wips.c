 /*==============================================================*/
/* FileName : wips.c                                            */
/*                                                              */
/*--------------------------------------------------------------*/
/* Author: igi                                                  */
/* include : wips.h                                             */
/* Created  : 20.8.18                                           */
/*--------------------------------------------------------------*/
/* 기  능:                                                      */
/*                                                              */
/*--------------------------------------------------------------*/
/*                                                              
 * $Log: wips.c,v $
 * Initial revision
 *                                       
 *                                                              */
/*--------------------------------------------------------------*/
#include  <stdio.h>
#include  <ctype.h>
#include  <stdlib.h>
#include  <pthread.h>
#include  <sched.h>
#include  <string.h>

#ifndef _WIN32
#include  <unistd.h>
#endif

#include  <signal.h>
#include  "parson.h"

#include  "wips.h"

#include  "IGIetc.h"
#include  "sha1.h"


ap_t AccessPoint[MAX_SSID_CNT];
ap_t AllowedAPDev[MAX_DEVICE_CNT];
//device_t AllowedDevice[MAX_DEVICE_CNT];
blocklist_t BlockList[MAX_BLOCKLIST_CNT];
tran_t TranData;
ini_t ini;


static void *counted_malloc(size_t size);
static void counted_free(void *ptr);

size_t malloc_count;






static void *counted_malloc(size_t size) 
{
    void *res = malloc(size);
    if (res != NULL) {
        malloc_count++;
    }
    return res;
}

static void counted_free(void *ptr) 
{
    if (ptr != NULL) {
        malloc_count--;
    }
    free(ptr);
}


int getINIData(ini_t *ini)
{
  char *t;

  /*------------------------------------------
   * ini 초기 화일에서 정의된 자료 얻기
   * POOL정보 얻기
   *-----------------------------------------*/
  t = IGIgetEnvIni(INI_FILE, INI_AGENT_GROUP, INI_DEV);
  if ( t == NULL ) {
    printf(" %s 파일에서 [%s]그룹 내의 %s 정보를 찾을 수 없습니다.\n",
           INI_FILE, INI_AGENT_GROUP, INI_DEV);
    return -1;
  }
  strcpy(ini->dev, t);


  /*------------------------------------------
   * MANAGER모드 실행정보
   *-----------------------------------------*/
  t = IGIgetEnvIni(INI_FILE, INI_AGENT_GROUP, INI_SH_MANAGED_MODE);
  if ( t == NULL ) {
    printf(" %s 파일에서 [%s]그룹 내의 %s 정보를 찾을 수 없습니다.\n",
           INI_FILE, INI_AGENT_GROUP, INI_SH_MANAGED_MODE);
    return -1;
  }
  strcpy(ini->sh_managed_mode, t);

  /*------------------------------------------
   * MONITOR모드 실행정보
   *-----------------------------------------*/
  t = IGIgetEnvIni(INI_FILE, INI_AGENT_GROUP, INI_SH_MONITOR_MODE);
  if ( t == NULL ) {
    printf(" %s 파일에서 [%s]그룹 내의 %s 정보를 찾을 수 없습니다.\n",
           INI_FILE, INI_AGENT_GROUP, INI_SH_MONITOR_MODE);
    return -1;
  }
  strcpy(ini->sh_monitor_mode, t);

  /*------------------------------------------
   * 채널 변경용 쉘 파일명 조회
   *-----------------------------------------*/
  t = IGIgetEnvIni(INI_FILE, INI_AGENT_GROUP, INI_SH_CHG_CHANNEL);
  if ( t == NULL ) {
    printf(" %s 파일에서 [%s]그룹 내의 %s 정보를 찾을 수 없습니다.\n",
           INI_FILE, INI_AGENT_GROUP, INI_SH_CHG_CHANNEL);
    return -1;
  }
  strcpy(ini->sh_chg_channel, t);

  /*------------------------------------------
   * 웹서버에서 Allow 정보 수신하는 쉘 파일
   *-----------------------------------------*/
  t = IGIgetEnvIni(INI_FILE, INI_AGENT_GROUP, INI_SH_ALLOW_INFO);
  if ( t == NULL ) {
    printf(" %s 파일에서 [%s]그룹 내의 %s 정보를 찾을 수 없습니다.\n",
           INI_FILE, INI_AGENT_GROUP, INI_SH_ALLOW_INFO);
    return -1;
  }
  strcpy(ini->sh_allow_info, t);

  /*------------------------------------------
   * 웹서버에서 AllowDevice 정보 수신하는 쉘 파일
   *-----------------------------------------*/
  t = IGIgetEnvIni(INI_FILE, INI_AGENT_GROUP, INI_SH_ALLOW_DEVICE_INFO);
  if ( t == NULL ) {
    printf(" %s 파일에서 [%s]그룹 내의 %s 정보를 찾을 수 없습니다.\n",
           INI_FILE, INI_AGENT_GROUP, INI_SH_ALLOW_DEVICE_INFO);
    return -1;
  }
  strcpy(ini->sh_allow_device_info, t);

  /*------------------------------------------
   * 무선랜 카드의 MAC주소 조회
   *-----------------------------------------*/
  t = IGIgetEnvIni(INI_FILE, INI_AGENT_GROUP, INI_SH_GET_MAC);
  if ( t == NULL ) {
    printf(" %s 파일에서 [%s]그룹 내의 %s 정보를 찾을 수 없습니다.\n",
           INI_FILE, INI_AGENT_GROUP, INI_SH_GET_MAC);
    return -1;
  }
  strcpy(ini->sh_get_mac, t);

  /*------------------------------------------
   * 웹서버에서 Allow 정보 수신주기 (초)
   *-----------------------------------------*/
  t = IGIgetEnvIni(INI_FILE, INI_AGENT_GROUP, INI_ALLOW_INTERVAL);
  if ( t == NULL ) {
    printf(" %s 파일에서 [%s]그룹 내의 %s 정보를 찾을 수 없습니다.\n",
           INI_FILE, INI_AGENT_GROUP, INI_ALLOW_INTERVAL);
    return -1;
  }
  ini->allow_interval =  atoi(t);
	if (ini->allow_interval < 60) ini->allow_interval = 60;
	if (ini->allow_interval > 3600) ini->allow_interval = 3600;

  /*------------------------------------------
   * MONITOR용으로 화면에 출력될 주기(초)
   *-----------------------------------------*/
  t = IGIgetEnvIni(INI_FILE, INI_AGENT_GROUP, INI_MONITOR_INTERVAL);
  if ( t == NULL ) {
    printf(" %s 파일에서 [%s]그룹 내의 %s 정보를 찾을 수 없습니다.\n",
           INI_FILE, INI_AGENT_GROUP, INI_MONITOR_INTERVAL);
    return -1;
  }
  ini->monitor_interval =  atoi(t);
	if (ini->monitor_interval < 10) ini->monitor_interval = 10;
	if (ini->monitor_interval > 3600) ini->monitor_interval = 3600;

  /*------------------------------------------
   * 로그파일
   *-----------------------------------------*/
  t = IGIgetEnvIni(INI_FILE, INI_AGENT_GROUP, INI_LOGNAME);
  if ( t == NULL ) {
    printf(" %s 파일에서 [%s]그룹 내의 %s 정보를 찾을 수 없습니다.\n",
           INI_FILE, INI_AGENT_GROUP, INI_LOGNAME);
    return -1;
  }
  strcpy(ini->logname, t);


  /*------------------------------------------
   * ini 초기 화일에서 정의된 자료 얻기
   * POOL정보 얻기
   *-----------------------------------------*/
  t = IGIgetEnvIni(INI_FILE, INI_AGENT_GROUP, INI_FILTER_RULE);
  if (t == NULL) {
    printf(" %s 파일에서 [%s]그룹 내의 %s 정보를 찾을 수 없습니다.\n",
           INI_FILE, INI_AGENT_GROUP, INI_FILTER_RULE);
    return -1;
  }
  strcpy(ini->filter, t);

  t = IGIgetEnvIni(INI_FILE, INI_AGENT_GROUP, INI_DEAUTH_AP);
  if ( t == NULL ) {
      printf(" %s파일에서 [%s]그룹 내의 %s 정보를 찾을 수 없습니다.\n",
              INI_FILE, INI_AGENT_GROUP, INI_DEAUTH_AP);
      return -1;
  }
  strcpy(ini->sh_deauth_ap, t);

  t = IGIgetEnvIni(INI_FILE, INI_AGENT_GROUP, INI_DEAUTH_DEVICE);
  if ( t == NULL ) {
      printf(" %s파일에서 [%s]그룹 내의 %s 정보를 찾을 수 없습니다.\n",
              INI_FILE, INI_AGENT_GROUP, INI_DEAUTH_DEVICE);
      return -1;
  }
  strcpy(ini->sh_deauth_device, t);

  t = IGIgetEnvIni(INI_FILE, INI_AGENT_GROUP, INI_REPEAT_CNT);
  if ( t == NULL ) {
      printf(" %s파일에서 [%s]그룹 내의 %s 정보를 찾을 수 없습니다.\n",
              INI_FILE, INI_AGENT_GROUP, INI_REPEAT_CNT);
      return -1;
  }
  ini->repeat_cnt = atoi(t);  if (ini->repeat_cnt <= 0) ini->repeat_cnt = 1;

  t=  IGIgetEnvIni(INI_FILE, INI_AGENT_GROUP, INI_USLEEP_VAR);
  if  (!t) {
    printf(" %s파일에서  [%s]그룹 내의 %s 정보를 찾을 수 없습니다.\n",
        INI_FILE,  INI_AGENT_GROUP, INI_USLEEP_VAR);
    return -1;
  }
  ini->usleep  =  atoi(t);

  if  (ini->usleep  <= 1) {
    printf("%s 값이 너무 작습니다.\n", INI_USLEEP_VAR);
    printf("Program Termination\n");
    return -1;
  }

  t = IGIgetEnvIni(INI_FILE, INI_AGENT_GROUP, INI_SCAN_INTERVAL);
  if ( t == NULL ) {
      printf(" %s파일에서 [%s]그룹 내의 %s 정보를 찾을 수 없습니다.\n",
              INI_FILE, INI_AGENT_GROUP, INI_SCAN_INTERVAL);
      return -1;
  }
  ini->scan_interval = atoi(t);  if (ini->scan_interval <= 0) ini->scan_interval = 60;
 
  t = IGIgetEnvIni(INI_FILE, INI_AGENT_GROUP, INI_CHANNEL_INTERVAL);
  if ( t == NULL ) {
      printf(" %s파일에서 [%s]그룹 내의 %s 정보를 찾을 수 없습니다.\n",
              INI_FILE, INI_AGENT_GROUP, INI_CHANNEL_INTERVAL);
      return -1;
  }
  ini->channel_interval = atoi(t);  if (ini->channel_interval <= 0) ini->channel_interval = 100;



  t=  IGIgetEnvIni(INI_FILE, INI_AGENT_GROUP,  INI_SLEEP_VAR);
  if  (!t) {
    printf(" %s파일에서  [%s]그룹 내의 %s 정보를 찾을 수 없습니다.\n",
        INI_FILE,  INI_AGENT_GROUP, INI_SLEEP_VAR);
    return -1;
  }
  ini->monitor_sleep =  atoi(t);
	if (ini->monitor_sleep < 1) ini->monitor_sleep = 1;
	if (ini->monitor_sleep > 10000) ini->monitor_sleep = 10000;

  return 0;
}


void changeMode(char mode)
{
	char buf[MAX_STRING_LENGTH];

	if(mode == 0)
		sprintf(buf, "./%s %s %s", ini.sh_monitor_mode, ini.dev, ini.logname);
	else
		sprintf(buf, "./%s %s %s", ini.sh_managed_mode, ini.dev, ini.logname);

	system(buf);
}


#define HEX2DEC(x)  (isdigit(x)?((x)-'0'):tolower(x)-'a'+10)

void addAllowDevice(const char *device, const char *ssid, const char *ap, const char *exp_date)
{
	char buf[10];
	unsigned char mac1[6], mac2[6];
	
	if (!device)  memset(mac1, 0, sizeof(mac1));
	else {
		if (strlen(device) != 17) return;

		mac1[0] = HEX2DEC(device[ 0])*16 + HEX2DEC(device[ 1]);
		mac1[1] = HEX2DEC(device[ 3])*16 + HEX2DEC(device[ 4]);
		mac1[2] = HEX2DEC(device[ 6])*16 + HEX2DEC(device[ 7]);
		mac1[3] = HEX2DEC(device[ 9])*16 + HEX2DEC(device[10]);
		mac1[4] = HEX2DEC(device[12])*16 + HEX2DEC(device[13]);
		mac1[5] = HEX2DEC(device[15])*16 + HEX2DEC(device[16]);
	}

	if (strlen(ap)     != 17) return;

	mac2[0] = HEX2DEC(ap[ 0])*16 + HEX2DEC(ap[ 1]);
	mac2[1] = HEX2DEC(ap[ 3])*16 + HEX2DEC(ap[ 4]);
	mac2[2] = HEX2DEC(ap[ 6])*16 + HEX2DEC(ap[ 7]);
	mac2[3] = HEX2DEC(ap[ 9])*16 + HEX2DEC(ap[10]);
	mac2[4] = HEX2DEC(ap[12])*16 + HEX2DEC(ap[13]);
	mac2[5] = HEX2DEC(ap[15])*16 + HEX2DEC(ap[16]);

	if (!exp_date) strcpy(buf, "99991231");
	else {
		memcpy(buf,   exp_date,   4);
		memcpy(buf+4, exp_date+5, 2);
		memcpy(buf+6, exp_date+8, 2);
		buf[8] = 0;
	}

	for (int i=0; i < MAX_DEVICE_CNT; i++) {
		if ( AllowedAPDev[i].enable                   &&
				ISMATCH_MAC(AllowedAPDev[i].device, mac1) &&
				ISMATCH_MAC(AllowedAPDev[i].mac,    mac2    ) ) {
			strcpy(AllowedAPDev[i].exp_date, buf);
			AllowedAPDev[i].flag++;
			break;
		}
		if ( AllowedAPDev[i].enable ) continue;

		if ( IS0000(AllowedAPDev[i].device) && IS0000(AllowedAPDev[i].mac) ) {
			AllowedAPDev[i].enable = 1;
			memcpy(AllowedAPDev[i].device, mac1, 6);
			memcpy(AllowedAPDev[i].mac,    mac2, 6);
			strcpy(AllowedAPDev[i].ssid,   ssid?ssid:"");
			strcpy(AllowedAPDev[i].exp_date, buf);
			AllowedAPDev[i].flag++;
			break;
		}
	}
}

#ifdef TEST
void addAllowAP(const char *macstr, const char *ssid, const char *device, const char *date)
{
	const char temp[6] = { 0, 0, 0, 0, 0, 0};
	char buf[10];
	unsigned char mac[6];

	if (strlen(macstr) != 17) return;

	mac[0] = HEX2DEC(macstr[ 0])*16 + HEX2DEC(macstr[ 1]);
	mac[1] = HEX2DEC(macstr[ 3])*16 + HEX2DEC(macstr[ 4]);
	mac[2] = HEX2DEC(macstr[ 6])*16 + HEX2DEC(macstr[ 7]);
	mac[3] = HEX2DEC(macstr[ 9])*16 + HEX2DEC(macstr[10]);
	mac[4] = HEX2DEC(macstr[12])*16 + HEX2DEC(macstr[13]);
	mac[5] = HEX2DEC(macstr[15])*16 + HEX2DEC(macstr[16]);


	/*
   * 아래의 중첩된 if문은 수정되어야 할 부분이다.
   * 간만에 소스를 추가하면서, 과거 로직을 파악하지 않고 
   * 당장의 기능이 되도록 하려고 추가하다가 보니,
   * 끼워 맞추게 되었다.
   */
	for (int i=0; i < MAX_DEVICE_CNT; i++) {
		if (AllowedAPDev[i].enable &&
				memcmp(AllowedAPDev[i].mac, mac, 6) == 0) {
			if (device) {
				if (memcmp(AllowedAPDev[i].device, device, 6) == 0) {  
					strcpy(AllowedAPDev[i].ssid, ssid?ssid:"");
					strcpy(AllowedAPDev[i].exp_date, date?date:"");
					AllowedAPDev[i].flag++;
					break;
				}
			}
			else {
				strcpy(AllowedAPDev[i].ssid, ssid?ssid:"");
				AllowedAPDev[i].flag++;
				break;
			}
		}

		if (!AllowedAPDev[i].enable &&
				memcmp(AllowedAPDev[i].mac, temp, 6) == 0) {
			AllowedAPDev[i].enable = 1;
			memcpy(AllowedAPDev[i].mac, mac, 6);

			if (device) memcpy(AllowedAPDev[i].device, device, 6);
			else memset(AllowedAPDev[i].device, 0xff, sizeof(AllowedAPDev[i].device));

			strcpy(AllowedAPDev[i].ssid, ssid?ssid:"");
			if (date) strcpy(AllowedAPDev[i].exp_date, date?date:"");
			else strcpy(AllowedAPDev[i].exp_date, "9999-12-31");
			AllowedAPDev[i].flag++;
			break;
		}
	}
}

void getAllowDeviceInfo(char *s, char *mac, char isTemp)
{
	char buf[MAX_STRING_LENGTH];
	JSON_Value *root;
	JSON_Array *aplist;
	JSON_Object *array;
	const char *checksum;
	const char *dt;
	const char *run;
	int status;
	int cnt;
	char flag;
	

	int rec_cnt;

	/*--------------------------------------
	 * 외부 파일 수신
	 */
	if (isTemp) {
		sprintf(buf, "./%s %s %s.%s", s, mac, ALLOW_DEVICE_FILE, TEMP_EXT_NAME);
		system(buf);
	}

	/*--------------------------------------
	 * isTemp==1 이라면, TEMP_EXT_NAME의 정보를 검증한다.
   *
	 * 파일에 대한 검증을 한 후에, ALLOW_DEVICE_FILE로
	 * 바꾸어서 저장한다.
	 * 파일 검증에서 오류가 나면, 기존의 ALLOW_DEVICE_FILE을
	 * 그대로 사용한다.
	 */
	if (isTemp) sprintf(buf, "%s.%s", ALLOW_DEVICE_FILE, TEMP_EXT_NAME);
	else sprintf(buf, "%s", ALLOW_DEVICE_FILE);
	root = json_parse_file(buf);
	if (!root) {
		printf("[X] '%s' File Parsing Error\n", buf);
		return;
	}

	dt  = json_object_get_string(json_object(root), JSON_DATE );
	status  = json_object_get_number(json_object(root), JSON_STATUS );
	if (status != 0) {
		printf("[X] Get AllowedDevice Info Error: %d\n", status);
		json_value_free(root);
		return;
	}
		 
	aplist = json_object_get_array (json_object(root), JSON_ALLOW);
	if (aplist == NULL) { json_value_free(root); return; }

	if (!isTemp) {
		for (int i=0; i<MAX_DEVICE_CNT; i++)
			AllowedDevice[i].flag = 0;
	}

	cnt = 0;
	for (int i=0; i < json_array_get_count(aplist); i++) {
		const char *ap, *device, *checksum, *exp_date;

		array = json_array_get_object(aplist, i);
		if (array == NULL) break;

		ap      = json_object_get_string(array, JSON_AP);
		device  = json_object_get_string(array, JSON_DEVICE);
		checksum= json_object_get_string(array, JSON_CHECKSUM);
		exp_date= json_object_get_string(array, JSON_EXP_DATE);
	
		if (!ap || !checksum || !checksum || !exp_date) break;
		/*-------------------
		 * validation check
		 */
		sprintf(buf, ALLOW_DEVICE_SHA1_PATTERN, (device)?device:"", ap);

		/* thread unsafe */
		flag = strcasecmp(sha1(buf, strlen(buf)), checksum);
		if ( flag == 0) cnt++; 
		else {
			printf("[X] Device=%s, AP=%s, CHECKSUM=%s\n", (device==NULL)?"":device, ap, checksum);
			continue;
		}
		if (!isTemp) addAllowDevice(device, ap, exp_date);
	}
	json_value_free(root);
	
	/*--------------------
	 * TMP파일의 검증 완료되면, 정상인 것만 JSON_DEVICE_FILE로 저장
	 */
	
	if (isTemp) {
		sprintf(buf, "mv %s.%s %s", ALLOW_DEVICE_FILE, TEMP_EXT_NAME, ALLOW_DEVICE_FILE);
		system(buf);
	}
	else {
		for (int i=0; i<MAX_DEVICE_CNT; i++)
			if (AllowedDevice[i].flag == 0) AllowedDevice[i].enable = 0;
	}
	return;
}
#endif

void getAllowInfo(char *s, char *mac, char isTemp)
{
	char buf[MAX_STRING_LENGTH];
	JSON_Value *root;
	JSON_Array *aplist;
	JSON_Object *array;
	const char *checksum;
	const char *dt;
	const char *run;
	int cnt;
	char flag;

	int rec_cnt;

	printf("[!] %s (%d)\n", __FUNCTION__, __LINE__);


	/*--------------------------------------
	 * 외부 파일 수신
	 */
	if (isTemp) {
		sprintf(buf, "./%s %s %s.%s", s, mac, ALLOW_AP_FILE, TEMP_EXT_NAME);
		system(buf);
	}

	/*--------------------------------------
	 * isTemp==1 이라면, TEMP_EXT_NAME의 정보를 검증한다.
   *
	 * 파일에 대한 검증을 한 후에, ALLOW_AP_FILE로
	 * 바꾸어서 저장한다.
	 * 파일 검증에서 오류가 나면, 기존의 ALLOW_AP_FILE을
	 * 그대로 사용한다.
	 */
	if (isTemp) sprintf(buf, "%s.%s", ALLOW_AP_FILE, TEMP_EXT_NAME);
	else sprintf(buf, "%s", ALLOW_AP_FILE);
	root = json_parse_file(buf);
	if (!root) {
		printf("[X] '%s' File Parsing Error\n", buf);
		return;
	}

	checksum  = json_object_get_string(json_object(root), JSON_CHECKSUM );
	run  = json_object_get_string(json_object(root), JSON_RUN );
	dt  = json_object_get_string(json_object(root), JSON_DATE );
	rec_cnt  = json_object_get_number(json_object(root), JSON_REC_CNT );


	sprintf(buf, "%s%d%s-SIG", dt, rec_cnt, run);
	flag = strcasecmp(sha1(buf, strlen(buf)), checksum);
	if (flag != 0) {
		printf("[X] checksum error\n");
		json_value_free(root);
		ini.run = 0;
		return;
	}

	if (!strcasecmp(run, "ON")) {
		ini.run = 1;
//		GET_ALLOW_DEVICE_INFO(ini.sh_allow_device_info, ini.mac);
	}
	else ini.run = 0;
	

	aplist = json_object_get_array (json_object(root), JSON_ALLOW);

	if (aplist == NULL) { json_value_free(root); return; }

	if (!isTemp) {
		for (int i=0; i<MAX_DEVICE_CNT; i++)
			AllowedAPDev[i].flag = 0;
	}

	cnt = 0;
	for (int i=0; i < json_array_get_count(aplist); i++) {
		const char *ssid, *mac, *check, *device, *exp_date;

		array = json_array_get_object(aplist, i);
		if (array == NULL) break;

		ssid     = json_object_get_string(array, JSON_SSID);
		mac      = json_object_get_string(array, JSON_MAC);
		device   = json_object_get_string(array, JSON_DEVICE);
		exp_date = json_object_get_string(array, JSON_EXP_DATE);
		check    = json_object_get_string(array, JSON_CHECKSUM);
	
		if (!mac || !check) break;
		/*-------------------
		 * validation check
		 */
		sprintf(buf, ALLOW_AP_SHA1_PATTERN, mac, 
																				ssid?ssid:"", 
																				(int)strlen(ssid), 
																				(device)?device:"None", 
																				(exp_date)?exp_date:"None");

		/* thread unsafe */
		flag = strcasecmp(sha1(buf, strlen(buf)), check);
		if ( flag == 0) cnt++; 
		else {
			printf("[X] MAC=%s, SSID=%s, CHECKSUM=%s\n", mac, ssid?ssid:"[*]", check);
			continue;
		}
		if (!isTemp) addAllowDevice(device, ssid, mac, exp_date);
//		if (!isTemp) addAllowAP(mac, ssid, device, exp_date);
	}
	json_value_free(root);
	
	/*--------------------
	 * TMP파일의 검증 완료되면, 정상인 것만 JSON_AP_FILE로 저장
	 */
	
	if (isTemp) {
		sprintf(buf, "mv %s.%s %s", ALLOW_AP_FILE, TEMP_EXT_NAME, ALLOW_AP_FILE);
		system(buf);
	}
	else {
		for (int i=0; i<MAX_DEVICE_CNT; i++)
			if (AllowedAPDev[i].flag == 0) AllowedAPDev[i].enable = 0;
	}
	return;
}

void printAllowedDevice(device_t device[])
{
#ifdef DEBUG_MONITOR
	char temp[] = { 0, 0, 0, 0, 0, 0 };

	printf("\n");
  printf("    ------------------- ALLOWED DEVICE -------------------\n");
  printf("      #          DEVICE              AP           EXP_DATE\n");
  printf("    ----   ----------------- -------------------- --------\n");
	for (int i=0; i<MAX_DEVICE_CNT; i++) {
		if (!device[i].enable && !memcmp(device[i].device, temp, 6) && !memcmp(device[i].ap, temp, 6)) break;
		printf("[!]  %2d: %c %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x %s\n", 
						i+1, device[i].enable?' ':'x', MAC(device[i].device), MAC(device[i].ap),
						device[i].exp_date);	
	}
  printf("    ----   ----------------- -------------------- --------\n");
#endif
}

void printAllowedAP(ap_t ap[])
{
#ifdef DEBUG_MONITOR
	char temp[] = { 0, 0, 0, 0, 0, 0 };

	printf("\n");
  printf("    ------------------------------ ALLOWED AP --------------------------------\n");
  printf("      #     END-DATE       DEVICE(MAC)        AP(MAC)               SSID \n");
  printf("    ----   ---------- ----------------- ----------------- --------------------\n");
	for (int i=0; i<MAX_DEVICE_CNT; i++) {
		if (!ap[i].enable && !memcmp(ap[i].mac, temp, 6)) break;
		printf("[!]  %2d: %c %10s %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x %-20s\n", 
						i+1, ap[i].enable?' ':'x', 
                 ap[i].exp_date,MAC(ap[i].device), MAC(ap[i].mac),
						ap[i].ssid[0]?ap[i].ssid:"[*]"
						);
	}
  printf("    ----   ---------- ----------------- ----------------- --------------------\n");
#endif
}


int getBlockListCnt()
{
  char dummy[] = {0, 0, 0, 0, 0, 0};
	int sum=0;

	for (int i=0; i < MAX_BLOCKLIST_CNT; i++) {
    if (memcmp(BlockList[i].ap, dummy, 6) == 0) break;
		sum++; 
	}
	return sum;
}

void addBlockList(ap_t ap)
{ 
  char dummy[] = {0, 0, 0, 0, 0, 0};
  
  for (int i=0; i < MAX_BLOCKLIST_CNT; i++) {
    if ( (memcmp(BlockList[i].ap,     ap.mac,     6) == 0) &&
				 (memcmp(BlockList[i].device, ap.device, 6) == 0)) {
      strcpy(BlockList[i].date2, getdatestrF());
      strcpy(BlockList[i].time2, gettimestrF());
			break;
		}
    
    if (memcmp(BlockList[i].ap, dummy, 6) == 0) {
      memcpy(BlockList[i].ap,     ap.mac,    6);
      memcpy(BlockList[i].device, ap.device, 6);
      strcpy(BlockList[i].ssid,   ap.ssid[0]?ap.ssid:"");
      strcpy(BlockList[i].date1,  getdatestrF());
      strcpy(BlockList[i].time1,  gettimestrF());
      BlockList[i].flag = 0;
      break;
    }
  }

}


void printBlockList(blocklist_t ap[])
{
#ifdef DEBUG_MONITOR
  char dummy[] = {0, 0, 0, 0, 0, 0}; 
	int i;

  printf("\n");
  printf("----------------BLOCK LIST(LOG)--------------------------\n");
  printf("  #     DATE     TIME  ~  TIME       MAC           SSID\n");
  printf("--- ---------- -------- -------- ---------------- -------\n");

  for (i=0; i < MAX_BLOCKLIST_CNT; i++) {
    if (memcmp(ap[i].ap, dummy, 6) == 0) break;
    printf(" %2d  %s %s~%s %02x:%02x:%02x:%02x:%02x:%02x  %s\n", 
        i+1, ap[i].date1, ap[i].time1,  ap[i].time2,
             MAC(ap[i].ap),
						 ap[i].ssid?ap[i].ssid:"[*]");
  }      
  if (i == 0) printf("Empty!!!\n");
  printf("--- ---------- -------- -------- ---------------- -------\n");
#endif

}

/* MAX_SSID_CNT -> MAX_DEVICE_CNT */
char isApRegist(ap_t ap, ap_t allowed[])
{

  char dummy[] = { 0, 0, 0, 0, 0, 0 };

  for (int i=0; i < MAX_DEVICE_CNT; i++) {
    if (!allowed[i].enable && IS0000(allowed[i].mac)) break;
		if (!allowed[i].enable) continue;

    if (ISMATCH_MAC(ap.mac, allowed[i].mac)) return i+1;
/*
    if (!memcmp(ap.mac, allowed[i].mac, 6) &&
        !strcasecmp(ap.ssid, allowed[i].ssid) &&
        (ap.ssid[0] == allowed[i].ssid[0])) return 1;
*/
  }
  return 0;
}

char isExistBlockAP()
{
  char dummy[] = { 0, 0, 0, 0, 0, 0 };
	int rt;

	for (int i=0; i < MAX_SSID_CNT; i++)  {
		if (!AccessPoint[i].enable &&  IS0000(AccessPoint[i].mac)) break;
		if (!AccessPoint[i].enable) continue;

	  rt = isApRegist(AccessPoint[i], AllowedAPDev);
		if (rt) return rt;
	}
	return 0;
}

void printAPstatus()
{
#ifdef DEBUG_MONITOR
  char dummy[] = { 0, 0, 0, 0, 0, 0 };
	int i;

	printf("\n");
	printf(" -------------- Access Point Status --------------\n");
	printf("   #   TYPE         MAC         CH    SSID\n");
	printf(" ---- ------ ----------------- --- ---------------\n");
				
  for (i=0; i < MAX_SSID_CNT; i++) {
    if (!AccessPoint[i].enable && IS0000(AccessPoint[i].mac)) break;
    if (!AccessPoint[i].enable) continue; 

		printf(" %3d:%c %-5s %02x:%02x:%02x:%02x:%02x:%02x %3d %s\n",
					i+1, AccessPoint[i].enable?' ':'x', 
					isApRegist(AccessPoint[i], AllowedAPDev)?"-":"Block",
					MAC(AccessPoint[i].mac),
					AccessPoint[i].channel,
					AccessPoint[i].ssid[0]?AccessPoint[i].ssid:"[*]");	
	}
	if (i== 0) printf(" Empty\n");
	printf(" ---- ------ ----------------- --- ---------------\n");
#endif
}

char isDeviceRegist(trandata_t *data, ap_t allowed[])
{
  char dummy[] = { 0, 0, 0, 0, 0, 0 };

  for (int i=0; i < MAX_DEVICE_CNT; i++) {
		/*
		 * 빈 데이터라면 탐색 중지
		 */
    if (!allowed[i].enable && IS0000(allowed[i].device)) break;
		if (!allowed[i].enable) continue;

		/*
		 * And 조건으로 안풀고 중첩 조건으로 풀었다.
		 */
		if ( ISMATCH_MAC(data->ap,     allowed[i].mac   )) {
			if  (ISFFFF(allowed[i].device) ||  
			  	 ISMATCH_MAC(data->device, allowed[i].device) )  {
				if (strcmp(getdatestr() , allowed[i].exp_date) <= 0) return i+1; 
			}
		} 
  }
  return 0;
}


int getMAC(ini_t *ini)
{
	char buf[MAX_STRING_LENGTH];
	FILE *f;

	sprintf(buf, "./%s %s %s", ini->sh_get_mac, ini->dev, FILE_WLAN_MAC);
	system(buf);

	f = fopen(FILE_WLAN_MAC, "r");
	if (f == NULL) return -1;

	fscanf(f, "%s", ini->mac);
	fclose(f);
	if (ini->mac[0] == 0) return -1;
	return 0;
}


/*==============================================================
 * 함수명: main
 * 인수   : argc, argv <- 안갈케줘
 * 기능   : Monitor/Scan/Channel/Agent Thread를 수행한다.
 *------------------------------------------------------------*/
int main()
{
  pthread_mutex_t  mutex = PTHREAD_MUTEX_INITIALIZER;

  tfunc_t func[MAX_DISPATCHER_CNT+2];

	int flag = 0;

  

	memset(AccessPoint,   0, sizeof(AccessPoint)  );
	memset(AllowedAPDev,  0, sizeof(AllowedAPDev) );
//	memset(AllowedDevice, 0, sizeof(AllowedDevice));

	json_set_allocation_functions(counted_malloc, counted_free);
	TranData.data = (trandata_t *)malloc(sizeof(trandata_t) * MAX_TRANSACTION_CNT);
	if (TranData.data == NULL) {
		printf("[X] 메모리 확보 오류%s(%d)\n", __FUNCTION__, __LINE__);
		return -1;
	}

	if (getINIData(&ini) < 0) {
		printf("[X] INI 파일 정보 얻기 오류\n");
		return -1;
	}

	if (getMAC(&ini) < 0) {
		printf("[X] MAC 주소를 조회할 수 없습니다.\n");
		printf("    %s 를 재확인하세요. \n", INI_SH_GET_MAC);
	}
	printf("[!] MAC=%s\n", ini.mac);

	/*--------------------------------------------
	 * Allow 정보를 수신 (allow_ap.json 로 저장됨)
	 */

	GET_ALLOW_INFO(ini.sh_allow_info, ini.mac);
//	if (ini.run) GET_ALLOW_DEVICE_INFO(ini.sh_allow_device_info, ini.mac);

  pthread_mutex_init(&mutex, NULL); 

  memset(&func, 0, sizeof(func));

  /*----------------------------------------------------------
   * thread  처리를 위해서 각 thread별 특성값을  정의한다.
   *
   * 아래것은 ScanThread가  운영되기  위하여 값을  설정한다.
   */
  func[0].type  = 1;
  func[0].lock  = (pthread_mutex_t *) &mutex;
  func[0].exec  = (void *)ScanThread;
  func[0].id  = -1;
  func[0].flag  = &flag;
  func[0].usleep =  ini.usleep;;

  /*----------------------------------------------------------
   * 채널을 바꾸는 Thread. 
   */
  func[1].type  = 2;
  func[1].lock  = (pthread_mutex_t *) &mutex;
  func[1].exec  = (void *)ChannelThread;
  func[1].id  = -1;
  func[1].flag  = &flag;
  func[1].usleep =  ini.usleep;;

  /*----------------------------------------------------------
   * DeAuth 처리
   */
  func[2].type  = 3;
  func[2].lock  = (pthread_mutex_t *) &mutex;
  func[2].exec  = (void *)DeAuthThread;
  func[2].id  = -1;
  func[2].flag  = &flag;
  func[2].usleep =  ini.usleep;

  /*----------------------------------------------------------
   * MonitorThread가  운영되기  위한 값을 설정한다.
   */
  func[3].type  = 4;
  func[3].lock  = &mutex;
  func[3].exec  = (void *)MonitorThread; 
  func[3].id  = -1;
  func[3].flag  = &flag;
  func[3].usleep =  ini.usleep;

  /*-----------------------------------------------------------
   * create  the main  thread, agent thread  and monitor  thread.
   */
  for  (int i=0;  i < 4; i++)  {
    pthread_create(&func[i].thread,  NULL,  func[i].exec, &(func[i]));
  }
//    pthread_create(&func[0].thread,  NULL,  func[0].exec, &(func[0]));
//    pthread_create(&func[1].thread,  NULL,  func[1].exec, &(func[1]));
//    pthread_create(&func[3].thread,  NULL,  func[3].exec, &(func[3]));

  /*-----------------------------------------------------------
   * wait for all  the agent and monitor thread.
   */
  for  (int i  = 0; i < 4;  i++) {
    pthread_join(func[i].thread,  NULL);
  }
//    pthread_join(func[0].thread,  NULL);
//    pthread_join(func[1].thread,  NULL);
//    pthread_join(func[3].thread,  NULL);

  /*-----------------------------------------------------------
   * exit this  thread
   */

  pthread_exit((void*) 0);
	return 0;
}


