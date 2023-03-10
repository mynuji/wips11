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
blocklist_t BlockList[MAX_BLOCKLIST_CNT];


static void *counted_malloc(size_t size);
static void counted_free(void *ptr);

size_t malloc_count;



#define ALLOW_AP_SHA1_PATTERN "%s-%s-%d-SIG"




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
   * 모니터 모드 실행정보
   *-----------------------------------------*/
  t = IGIgetEnvIni(INI_FILE, INI_AGENT_GROUP, INI_SH_MONITOR_MODE);
  if ( t == NULL ) {
    printf(" %s 파일에서 [%s]그룹 내의 %s 정보를 찾을 수 없습니다.\n",
           INI_FILE, INI_AGENT_GROUP, INI_SH_MONITOR_MODE);
    return -1;
  }
  strcpy(ini->sh_monitor_mode, t);

  /*------------------------------------------
   * Managed 모드 실행정보
   *-----------------------------------------*/
  t = IGIgetEnvIni(INI_FILE, INI_AGENT_GROUP, INI_SH_MANAGED_MODE);
  if ( t == NULL ) {
    printf(" %s 파일에서 [%s]그룹 내의 %s 정보를 찾을 수 없습니다.\n",
           INI_FILE, INI_AGENT_GROUP, INI_SH_MANAGED_MODE);
    return -1;
  }
  strcpy(ini->sh_managed_mode, t);

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

  t = IGIgetEnvIni(INI_FILE, INI_AGENT_GROUP, INI_DEAUTH);
  if ( t == NULL ) {
      printf(" %s파일에서 [%s]그룹 내의 %s 정보를 찾을 수 없습니다.\n",
              INI_FILE, INI_AGENT_GROUP, INI_DEAUTH);
      return -1;
  }
  strcpy(ini->sh_deauth, t);

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



  t=  IGIgetEnvIni(INI_FILE, INI_MONITOR_GROUP,  
                   INI_SLEEP_VAR);
  if  (!t) {
    printf(" %s파일에서  [%s]그룹 내의 %s 정보를 찾을 수 없습니다.\n",
        INI_FILE,  INI_MONITOR_GROUP, INI_SLEEP_VAR);
    return -1;
  }
  ini->monitor_sleep =  atoi(t);
	if (ini->monitor_sleep < 1) ini->monitor_sleep = 1;
	if (ini->monitor_sleep > 10000) ini->monitor_sleep = 10000;

  return 0;
}

#define HEX2DEC(x)  (isdigit(x)?((x)-'0'):tolower(x)-'a'+10)

void addAllowAP(const char *macstr, const char *ssid)
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

	for (int i=0; i < MAX_DEVICE_CNT; i++) {
		if (AllowedAPDev[i].enable &&
				memcmp(AllowedAPDev[i].mac, mac, 6) == 0) {
			strcpy(AllowedAPDev[i].ssid, ssid?ssid:"");
			AllowedAPDev[i].flag++;
			break;
		}
		if (!AllowedAPDev[i].enable &&
				memcmp(AllowedAPDev[i].mac, temp, 6) == 0) {
			AllowedAPDev[i].enable = 1;
			memcpy(AllowedAPDev[i].mac, mac, 6);
			strcpy(AllowedAPDev[i].ssid, ssid?ssid:"");
			AllowedAPDev[i].flag++;
			break;
		}
	}
}

void getAllowInfo(char *s, char isTemp)
{
	char buf[MAX_STRING_LENGTH];
	JSON_Value *root;
	JSON_Array *aplist;
	JSON_Object *array;
	int cnt;
	char flag;

	int rec_cnt;

	/*--------------------------------------
	 * 외부 파일 수신
	 */
	if (isTemp) {
		sprintf(buf, "./%s %s.%s", s, ALLOW_AP_FILE, TEMP_EXT_NAME);
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

	rec_cnt  = json_object_get_number(json_object(root), JSON_REC_CNT );
	aplist = json_object_get_array (json_object(root), JSON_AP_ALLOW);

	if (aplist == NULL) { json_value_free(root); return; }

	if (!isTemp) {
		for (int i=0; i<MAX_DEVICE_CNT; i++)
			AllowedAPDev[i].flag = 0;
	}

	cnt = 0;
	for (int i=0; i < json_array_get_count(aplist); i++) {
		const char *ssid, *mac, *check;

		array = json_array_get_object(aplist, i);
		if (array == NULL) break;

		ssid = json_object_get_string(array, JSON_AP_SSID);
		mac  = json_object_get_string(array, JSON_AP_MAC);
		check= json_object_get_string(array, JSON_AP_CHECK);
	
		if (!mac || !check) break;
		/*-------------------
		 * validation check
		 */
		sprintf(buf, ALLOW_AP_SHA1_PATTERN, mac, ssid?ssid:"", (int)strlen(ssid));

		/* thread unsafe */
		flag = strcasecmp(sha1(buf, strlen(buf)), check);
		if ( flag == 0) cnt++; 
		else {
			printf("[ERR] MAC=%s, SSID=%s, CHECK=%s\n", mac, ssid?ssid:"[*]", check);
			continue;
		}
		if (!isTemp) addAllowAP(mac, ssid);
	}
	json_value_free(root);
	
	/*--------------------
	 * TMP파일의 검증 완료되면, 정상인 것만 JSON_AP_FILE로 저장
	 */
	
	if (isTemp) {
		sprintf(buf, "mv %s.%s %s", ALLOW_AP_FILE, TEMP_EXT_NAME, ALLOW_AP_FILE);
		system(buf);
	}
	if (!isTemp) {
		for (int i=0; i<MAX_DEVICE_CNT; i++)
			if (AllowedAPDev[i].flag == 0) AllowedAPDev[i].enable = 0;
	}
	return;

	sprintf(buf, "%s", ALLOW_AP_FILE);
	root = json_parse_file(buf);
	if (!root) {
		printf("[X] '%s' File Parsing Error\n", buf);
		return;
	}

	rec_cnt  = json_object_get_number(json_object(root), JSON_REC_CNT );
	aplist = json_object_get_array (json_object(root), JSON_AP_ALLOW);

	if (aplist == NULL) { json_value_free(root); return; }

//	if (rec_cnt > 0) memset(AllowedAP, 0, sizeof(AllowedAP));

//	memset(AllowedAP, 0, sizeof(AllowedAP));


	for (int i=0; i<MAX_DEVICE_CNT; i++) 
		AllowedAPDev[i].flag = 0;

	for (int i=0; i <= json_array_get_count(aplist); i++) {
		const char *ssid, *mac, *check;

		array = json_array_get_object(aplist, i);
		if (array == NULL) break;

		ssid = json_object_get_string(array, JSON_AP_SSID);
		mac  = json_object_get_string(array, JSON_AP_MAC);
		check= json_object_get_string(array, JSON_AP_CHECK);
	
		if (!mac || !check) break;
		/*-------------------
		 * validation check
		 */
		sprintf(buf, ALLOW_AP_SHA1_PATTERN, mac, ssid?ssid:"", (int)strlen(ssid));

		/* thread unsafe */
		if (strcasecmp(sha1(buf, strlen(buf)), check)) continue;

		addAllowAP(mac, ssid);
		if (flag) printf("[ERR] MAC=%s, SSID=%s, CHECK=%s\n", 
							mac, ssid?ssid:"[*]", check);
	}
	for (int i=0; i<MAX_DEVICE_CNT; i++) 
		if (AllowedAPDev[i].flag == 0) AllowedAPDev[i].enable = 0;;

	return;
}

void printAllowedAP(ap_t ap[])
{
	char temp[] = { 0, 0, 0, 0, 0, 0 };

	printf("\n");
  printf("    ------------ ALLOWED AP --------------------\n");
  printf("      #        MAC                  SSID        \n");
  printf("    ---- ------------------ --------------------\n");
	for (int i=0; i<MAX_SSID_CNT; i++) {
		if (!ap[i].enable && !memcmp(ap[i].mac, temp, 6)) break;
		printf("[!]  %2d: %c %02x:%02x:%02x:%02x:%02x:%02x %-20s\n", 
						i+1, ap[i].enable?' ':'x', 
								 ap[i].mac[0], ap[i].mac[1], ap[i].mac[2], 
						     ap[i].mac[3], ap[i].mac[4], ap[i].mac[5], 
						ap[i].ssid[0]?ap[i].ssid:"[*]");
	}
  printf("    ---- ------------------ --------------------\n\n");
}


int getBlockListCnt()
{
  char dummy[] = {0, 0, 0, 0, 0, 0};
	int sum=0;

	for (int i=0; i < MAX_BLOCKLIST_CNT; i++) {
    if (memcmp(BlockList[i].mac, dummy, 6) == 0) break;
		sum++; 
	}
	return sum;
}

void addBlockList(ap_t ap)
{ 
  char dummy[] = {0, 0, 0, 0, 0, 0};
  
  for (int i=0; i < MAX_BLOCKLIST_CNT; i++) {
    if (memcmp(BlockList[i].mac, ap.mac, 6) == 0) {
      strcpy(BlockList[i].date2, getdatestrF());
      strcpy(BlockList[i].time2, gettimestrF());
			break;
		}
    
    if (memcmp(BlockList[i].mac, dummy, 6) == 0) {
      memcpy(BlockList[i].mac, ap.mac, 6);
      strcpy(BlockList[i].ssid, ap.ssid[0]?ap.ssid:"");
      strcpy(BlockList[i].date1, getdatestrF());
      strcpy(BlockList[i].time1, gettimestrF());
      BlockList[i].flag = 0;
      break;
    }
  }

}


void printBlockList(blocklist_t ap[])
{
  char dummy[] = {0, 0, 0, 0, 0, 0}; 
	int i;

  printf("\n\n");
  printf("----------------BLOCK LIST-------------------------------\n");
  printf("  #     DATE     TIME  ~  TIME       MAC           SSID\n");
  printf("--- ---------- -------- -------- ---------------- -------\n");

  for (i=0; i < MAX_BLOCKLIST_CNT; i++) {
    if (memcmp(ap[i].mac, dummy, 6) == 0) break;
    printf(" %2d  %s %s~%s %02x:%02x:%02x:%02x:%02x:%02x  %s\n", 
        i+1, ap[i].date1, ap[i].time1,  ap[i].time2,
             ap[i].mac[0], ap[i].mac[1], ap[i].mac[2],
             ap[i].mac[3], ap[i].mac[4], ap[i].mac[5], 
						 ap[i].ssid?ap[i].ssid:"[*]");
  }      
  if (i == 0) printf("Empty!!!\n");
  printf("--- ---------- -------- -------- ---------------- -------\n");

}


char isRegist(ap_t ap, ap_t allowed[])
{

  char dummy[] = { 0, 0, 0, 0, 0, 0 };

  for (int i=0; i < MAX_SSID_CNT; i++) {
    if (!allowed[i].enable &&
				!memcmp(allowed[i].mac, dummy, 6)) break;

    if (allowed[i].enable &&
			  !memcmp(ap.mac, allowed[i].mac, 6) &&
        !strcasecmp(ap.ssid, allowed[i].ssid) &&
        (ap.ssid[0] == allowed[i].ssid[0])) return 1;
  }
  return 0;
}

char isExistBlockAP()
{
  char dummy[] = { 0, 0, 0, 0, 0, 0 };

	for (int i=0; i < MAX_SSID_CNT; i++)  {
		if (!AccessPoint[i].enable &&  
				!memcmp(AccessPoint[i].mac, dummy, 6)) break;
	  if (!isRegist(AccessPoint[i], AllowedAP)) return 1;
	}
	return 0;
}

void printAPstatus()
{
  char dummy[] = { 0, 0, 0, 0, 0, 0 };

	printf("\n\n");
	printf(" ------------ Access Point Status -------------\n");
	printf("   #   TYPE         MAC            SSID\n");
	printf(" ---- ------- ----------------- ---------------\n");
				
  for (int i=0; i < MAX_SSID_CNT; i++) {
    if (!AccessPoint[i].enable &&
				!memcmp(AccessPoint[i].mac, dummy, 6)) break;

		printf(" %3d:%c %-5s %02x:%02x:%02x:%02x:%02x:%02x %s\n",
					i+1, AccessPoint[i].enable?' ':'x', 
					isRegist(AccessPoint[i], AllowedAP)?"-":"Block",
					AccessPoint[i].mac[0], AccessPoint[i].mac[1],
					AccessPoint[i].mac[2], AccessPoint[i].mac[3],
					AccessPoint[i].mac[4], AccessPoint[i].mac[5],
					AccessPoint[i].ssid[0]?AccessPoint[i].ssid:"[*]");	
	}
	printf(" ---- ------- ----------------- ---------------\n");
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

	ini_t ini;
  

	memset(AccessPoint, 0, sizeof(AccessPoint));
	memset(AllowedAP, 0, sizeof(AllowedAP));
	json_set_allocation_functions(counted_malloc, counted_free);


	if (getINIData(&ini) < 0) {
		printf("[X] INI 파일 정보 얻기 오류\n");
		return -1;
	}

	if (getMAC(&ini) < 0) {
		printf("[x] MAC 주소를 조회할 수 없습니다.\n");
		printf("    %s 를 재확인하세요. \n", INI_SH_GET_MAC);
	}
	printf("[!] MAC=%s\n", ini.mac);

	/*--------------------------------------------
	 * Allow 정보를 수신 (allow_ap.json 로 저장됨)
	 */
	getAllowInfo(ini.sh_allow_info);
	printAllowedAP(AllowedAP);


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
   * 채널을 바꾸는 Thread. 이 thread가 거의 Main의 역할을
   * 한다.
   *
   */
  func[1].type  = 2;
  func[1].lock  = (pthread_mutex_t *) &mutex;
  func[1].exec  = (void *)DeAuthThread;
  func[1].id  = -1;
  func[1].flag  = &flag;
  func[1].usleep =  ini.usleep;

  /*----------------------------------------------------------
   * MonitorThread가  운영되기  위한 값을 설정한다.
   */
  func[2].type  = 3;
  func[2].lock  = &mutex;
  func[2].exec  = (void *)MonitorThread; 
  func[2].id  = -1;
  func[2].flag  = &flag;
  func[2].usleep =  ini.usleep;

  /*-----------------------------------------------------------
   * create  the main  thread, agent thread  and monitor  thread.
   */
  for  (int i=0;  i < 3; i++)  {
    pthread_create(&func[i].thread,  NULL,  func[i].exec, &(func[i]));
  }

  /*-----------------------------------------------------------
   * wait for all  the agent and monitor thread.
   */
  for  (int i  = 0; i < 3;  i++) {
    pthread_join(func[i].thread,  NULL);
  }

  /*-----------------------------------------------------------
   * exit this  thread
   */

  pthread_exit((void*) 0);
	return 0;
}


