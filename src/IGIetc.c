/*==================================================================*/
/*a 화  일  명  : IGIetc.c                                           */
/* 제      목  :                                                    */
/*------------------------------------------------------------------*/
/* 라이브러리  :                                                    */
/* 작  성  자  : 강영익                                             */
/* 헤더  화일  : IGIetc.h                                           */
/* 작  성  일  : 99. 7. 19 ( 최종수정일 :   .  .   )                */
/*------------------------------------------------------------------*/
/* 기      능  :                                                    */
/*                                                                  */
/*------------------------------------------------------------------*/
/*
 *  $Log: IGIetc.c,v $
 *  Revision 1.7  2005/01/28 07:36:27  root
 *  lock관련 함수 등록
 *
 *  Revision 1.6  2005/01/25 11:50:28  root
 *  GetFileSize 함수 추가
 *
 *  Revision 1.5  2005/01/25 10:12:32  root
 *  fd_lock, fd_unlock 함수 추가
 *
 *  Revision 1.4  2005/01/20 05:29:58  root
 *  isExistFile의 mode 관련 오류 사항 수정
 *
 *  Revision 1.3  2005/01/20 05:16:05  root
 *  isExistFile 함수 추가
 *
 *  Revision 1.2  2005/01/19 06:55:20  root
 *    삭제
 *
 *  Revision 1.1  2005/01/19 02:29:15  root
 *  Initial revision
 *
 *  Revision 1.5  2003/07/16 02:08:06  igi
 *  그냥 등록하는 겁니다.
 *  뭘수정 했는지 모릅니다.
 *
 *  Revision 1.4  2003/05/23 01:15:41  igi
 *  작은 수정만 있었음.
 *
 *  Revision 1.3  2003/04/14 04:53:39  igi
 *  IGIsleep() 구현...sleep()함수와 동일함
 *
 *  Revision 1.2  2003/04/10 10:51:11  igi
 *  RCS log 생성 라인 변경
 *
 *  Revision 1.1  2003/04/10 10:36:41  igi
 *  Initial revision
 *                            
 *                                                                  */
/*------------------------------------------------------------------*/


#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#include <time.h>
#include <stdarg.h>
#include <sys/stat.h>

#include "IGIetc.h"




#ifdef TEST_MODULE

/*-----------------------------------------------------------
 * 함수명 : main
 * 기능   : 함수 테스트용  메인 프로그램
 *     TEST_MODULE가 정의되어있을 경우, 메인 프로그램으로 처리됨
 *-----------------------------------------------------------*/
main()
{
  char *s;

  s= IGIgetEnvIni("robot.ini", "AGENT", "POOL");
  printf("robot.ini 파일의 AGENT 그룹에서 POOL의 값을 찾습니다.\n");
  printf("%s\n", (s==NULL)?"NULL":s);
  IGIsleep(5000000);


}

#endif


/*==============================================================
 * 함수명 : void IGIeraseLBlank(char *s)
 * 기능   : 문자열 s의 왼쪽 공백을 지워주는 부분.
 * 반환   : 없음
 * 사용예 : char *s = "   abcd efg ";
 * 
 *          IGIeraseLBlank(s);
 *          s  ->   "abcd efg "
 *--------------------------------------------------------------*/
void IGIeraseLBlank(char *s)
{
  char *t;

  if (!s) return;
  t = s;
  while (*t == ' ' || *t == '\t')
    t++;
	while (*t != 0) {
		*s = *t;
		s++; t++;
	}
	*s = *t;
}

/*============================================================
 * 함수명 : void IGIeraseRBlank(char *s)
 * 기능   : 문자열 s의 오른쪽 공백을 지워주는 부분
 * 반환   : 없음
 * 사용예 : char *s = "   abcd efg ";
 *          IGIeraseRBlank(s);
 *          s  ->    "    abcd efg"
-------------------------------------------------------------*/
void IGIeraseRBlank(char *s)
{
   int len;

   if (!s) return;
   len = strlen(s);
   while ( len != 1 && (s[len - 1] == ' ' || s[len - 1] == '\t') ) len--;
   s[len] = '\0';
}

/*========================================================
 * 함수명 : void IGIeraseBlank(char *s)
 * 기능   : 문자열 s의 좌우 공백을 지워주는 부분
 * 반환   : 없음
 * 사용예 : char *s = "   abcd efg ";
 *          IGIeraseBlank(s);
 *          s  ->    "abcd efg"
*--------------------------------------------------------*/
void IGIeraseBlank(char *s)
{
  IGIeraseLBlank(s);
  IGIeraseRBlank(s);
}

/*========================================================
 * 함수명: IGIgetEnvIni(char *ininame, char *group, char *var)
 *
 * 인  수: ininame : 조회할 INI파일 명
 *         group   : 조회할 GROUP 이름
 *         var     : 조회할 변수명
 *
 * 기능  : ininame의 파일에서 group에 정의된 변수의 등록 
 *         정보를 얻는다.
 *         ini파일의 내용은 # 은 주석으로 처리되며,
 *         그룹은 [GROUP_NAME] 의 형식으로 그룹 이름이 '[]' 
 *         안에 기술된다.
 *         각 그룹의 구분은 새로운 그룹이름이 나오기 전까지 
 *         등록된 값을
 *         그룹내의 정의된 변수/값으로 간주한다.
 *         변수와 값은  var=value 형식으로 기술된다.
 *         value값은 좌우측에는 SPACE가 있으면 무시가 되며, 
 *         문자열 사이에
 *         SPACE가 있을 경우는 SPACE자체를 value로 인정한다.
 *
 * 반환  : 조회 성공했을 때, 조회한 var의 값을 반환하며,
 *         오류가 발생했을 때, NULL을 반환한다.
 *
 * 참고사항: 내부에서 static 변수를 사용한다.
 *           value의 최대 길이는 200으로 제한된다.
 *
 * 사용예: robot.ini 파일의  "AGENT" 그룹의 "POOL"에 정의된 
 *         값을 얻고자 할경우
 *         s = IGIgetEnvIni(s, "robot.ini", "AGENT", "POOL");
 *         if (s == NULL) printf("error");
 *       
 *-----------------------------------------------------------*/
char *IGIgetEnvIni(char *ininame, char *group, char *var)
{
  char *t;
  FILE *f;
  char temp1[MAX_STRING_LENGTH], 
       temp2[MAX_STRING_LENGTH];
  char flag;
  static char buf[MAX_STRING_LENGTH];


  flag = 0;
  memset(buf, 0, sizeof(buf));

  /*
   *-----------------------
   * 그룹을 [GROUP] 형식으로 정의
   *----------------------
   */
  sprintf(temp2, "[%s]", group);

  /*
   *-----------------------
   * 화일을 열고 
   *----------------------
   */
  if ( (f=fopen(ininame, "r")) == NULL ) return NULL;

   /*
    *-----------------------
    * 문자열을 한줄씩 읽는다 
    *-----------------------
    */
  while (fgets(temp1, sizeof(temp1), f) != NULL) {

    /* 
     *----------------------------------
     * '#' 을 찾아서 그 뒤는 무시한다. 
     *----------------------------------
     */
    t = strchr(temp1, '#');
    if (t) *t = 0;    

    /* 
     *---------------------------------
     * 문자열의 앞뒤의 공백을 삭제한다. 
     *----------------------------------
     */
    IGIeraseBlank(temp1);
    t = strchr(temp1, '\n'); if (t) *t=0;
    t = strchr(temp1, '\r'); if (t) *t=0;

    if (temp1[0] == 0) continue;


    /*
     *---------------------------------------
     * 얻은 문자열(temp1)이 '['로 시작하면,
     * 그룹 정보로 간주해서, 그룹 명칭이 동일한지
     * 확인한다. 
     * 이미 확인된 그룹에서 작업 중에(flag=1) 새로운
     * 그룹 시작 정보를 만나게 되면, 조회를 종료한다.
     *---------------------------------------
     */
    if (temp1[0] == '[') {
      if (flag) break;
      sprintf(temp2, "[%s]", group);
      if (strcmp(temp1, temp2)==0) flag = 1;
      continue;
    }
    if (flag==0) continue; 

    /*
     *----------------------------------------------
     * 문자열에서 변수와 값을 분리한다.
     *--------------------------------------------
     */
    t = strchr(temp1, '=');
    if (!t) {
      printf("(IGIgetEnvIni)환경화일 포맷 에러: %s\n", temp1);
      continue;
    }

    /*
     *--------------------------------------
     * '=' 다음 문자를 t가 가리키도록 이동 
     *--------------------------------------
     */
    *t++ = 0;
    strcpy(temp2, t);
    IGIeraseBlank(temp1);

    /*
     *----------------------------------------
     * 인덱스와 읽은 자료의 인덱스가 다르다면 
     * 다시 한라인 더 읽기위해 위로 
     *----------------------------------------
     */
    if (!IGIisMatch(var, temp1)) continue;
    IGIeraseBlank(temp2);
    strcpy(buf, temp2);
    break;
  }
  fclose(f);

  if (buf[0] == 0x00) return NULL;
  return buf;
}

/*-------------------------------------------------------
 * 함수명 : get_curdate
 * 기능   : 현재의 날짜/시간 을 얻는다.
 * 반환   : 시간값
 *
 *------------------------------------------------------*/
struct tm *get_curdate()
{
  time_t t;

  t = time(NULL);

  return (localtime(&t));
}


/*=====================================================
 * 함수명 : IGIisMatch(char s[], char key[])
 * 인수   : s 는  검색하게될 대상이 되는 문자열
 *          key는 검색의 키로 사용될 문자열로 '*', 
 *          '?'등의 문자로 표현될수있다.
 * 기능   : key로 사용된 문자열에 s가 포함되는지를 찾는 함수
 * 반환   : 문자열(s)가 key에 포함된다면 1을, 아니면 0을 반환
 * 
 * 사용예 :  IGIisMatch("abcdefg", "abcdefg")  =>  1
 *           IGIisMatch("abcdefg", "abcdeff")  =>  0
 *           IGIisMatch("abcdefg", "abc*")     =>  1
 *           IGIisMatch("abcdefg", "abc??fg")  =>  1
 *           IGIisMatch("abcdefg", "a*c??fg")  =>  1
 *           IGIisMatch("abcdefg", "*c??fg")   =>  1
 *
 * 주의사항: 아직 완전한 검증을 받지 못함.. 테스트는 했는데.... 
 *      오랜 테스트 시간없이 경우의 수만을 만들어서 만든 
 *      테스트라서 완전한 검증이되지 못했다.
 * 라이브러리 중에 pattern match 하는 함수가 있는 듯.. 쩝... 
 * 만들어 둔 후에 안거라서.... 쩝... 
 *----------------------------------------------------------*/
int IGIisMatch(char s[], char key[])
{
  int i, j, wild;

  int temp_j=-1;

  i = j = wild = 0;

  /*
   *-------------------------------
   *  문자열을 다 소비할때까지 
   *-------------------------------
   */
  while (i < strlen(s) ) {
    /*
     *-----------------------------
     * ?키일때 그냥 지나감  
     *-----------------------------
     */
    if (key[j] == '?')  j++;
    else {
    /* 
     *-------------------------------
     * 주석 생략(말로 표현하기 어려운 관계로) 
     *--------------------------------
     */
      if (key[j] == '*') { wild = 1; temp_j = ++j; }
      if (wild) {
        if (s[i] == key[j])  j++;
        else if (j != temp_j) {j = temp_j; continue;}
      }
      else if (s[i] == key[j])  j++;
      else return 0;
    }
    i++;
  }
  /*----------------------------------------
   * 루틴을 마치고 나오면 i와 j는 각 문자열의 
   * 마지막 NULL을 가리키고 있어야지만, 정상적인 
   * 것이므로, 만일 이 자료가 서로 같지 않다면 
   * 오류로 반환 아래줄을 같지 않다가 아닌, 둘 중 
   * 하나라도 NULL이 아니라면 0을 반환하도록 고쳐야 
   * 맞지 않을까 싶다.  짬나면 다시 한번 생각해봐야
   * 될 곳이다.                                                   
   *----------------------------------------*/
  if (s[i] != key[j]) return 0;
  return 1;
}

/*=============================================
 * 함수명 : power
 * 기능   : 거듭 제곱에 대한 값을 구한다.
 * 반환   : 정상일 때, 거듭제곱한 값 (1 이상의 값)
 *          오류일 때, -1
 *
 * 사용예)     rt = power( 5, 2 );
 *               rt -> 5 X 5  = 25
 *--------------------------------------------*/
int IGIgetPower(int base, int times)
{
  int i;
  int result = 1;

  if (times < 0) return -1;

  for (i = 0; i < times; i++)
    result = result * base;

  return result;
}

/*===================================================
 * 함수명 : IGIsleep
 * 인수   : sleep할 시간 값(microsec)
 * 기능   : usleep 함수와 비슷한 함수로, 
 *          select를 이용하여 구현
 * 반환   : 없음
 * 사용예 :  IGIsleep(500);  <- 0.5초 sleep
 *--------------------------------------------------*/
void IGIsleep(long usec)
{
   struct timeval  sleep_time;
   fd_set set;
   int nset;
   int rt;

 
   sleep_time.tv_sec  = (long)usec/1000000;
   sleep_time.tv_usec = (long)usec%1000000;


   nset = 1;
   FD_ZERO(&set);
   FD_SET(0, &set);

   rt = select(nset, 0, &set, 0, &sleep_time);
}





/*-------------------------------------------
함수명 : gotoxy(int x, int y)
기능   : 커서를 x, y 좌표로 이동
반환   : 없음.
사용예 : gotoxy(x, y)
--------------------------------------------*/
void gotoxy(x, y)
int x, y;
{
  printf("%c[%d;%dH", 27, y, x);
  fflush(stdout);
}


int isMatch(char *code, int cnt, ...)
{

  va_list ap;
  int i;
  char *value;

  va_start(ap, cnt);
  for (i = 0; i < cnt; i++) {
    value = va_arg(ap, char *);

    if (!strcasecmp(code, value)) return 1;
  }
  va_end(ap);

  return 0;
}

int isExistFile(char *fname, int mode)
{
  struct stat st;
  int rt;

  rt = stat(fname, &st);
  if (rt < 0) return 0;

  if (!(st.st_mode & mode)) return 0;

  return 1;
}


/*-------------------------------------------
 * 파일이 잠겨있는지 확인하고 잠겨 있지 않으면
 * 잠금을 얻고 
 * 잠겨 있을경우 잠김이 풀릴때까지 기다린다(F_SETLKW) 
 *-------------------------------------------*/
int fd_lock(int fd)
{
    struct flock lock;

    lock.l_type = F_WRLCK; 
    lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;

    return fcntl(fd, F_SETLKW, &lock);
}

/*-----------------------------
 * 파일 잠금을 얻은후 모든 작업이 끝난다면 
 * 파일 잠금을 돌려준다. 
 *------------------------------------*/
int fd_unlock(int fd)
{
    struct flock lock;

    lock.l_type = F_UNLCK; 
    lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;

    return fcntl(fd, F_SETLK, &lock);
}

#ifndef _WIN32
long GetFileSize(char *fname)
{

  FILE *f;
  long size;

  f = fopen(fname, "r+");
  if (f = NULL) return -1;

  fseek(f, 0, SEEK_END);
  size = ftell(f);

  fclose(f);

  return size;
}
#endif

/**----------------------------------------------------------------------
 * 함수명: getdatestr
 * 인수 : 없음
 * 반환 : 현재 일자를 문자열을 반환 (YYYYMMDD형태)
 * 기능 : 상동
 *------------------------------------------------------------------------*/
char *getdatestr()
{
  struct tm *t;
  static char buf[30];

  t = get_curdate();

  sprintf(buf, "%04d%02d%02d", t->tm_year+1900, t->tm_mon+1, t->tm_mday);
  return buf;
}

/**----------------------------------------------------------------------
 * 함수명: getdatestrF2
 * 인수 : 없음
 * 반환 : 현재 일자를 문자열을 반환 (YYYY-MM-DD형태)
 * 기능 : 상동
 *------------------------------------------------------------------------*/
char *getdatestrF2()
{
  struct tm *t;
  static char buf[30];

  t = get_curdate();

  sprintf(buf, "%04d-%02d-%02d", t->tm_year+1900, t->tm_mon+1, t->tm_mday);
  return buf;
}

/**----------------------------------------------------------------------
 * 함수명: getdatestrF
 * 인수 : 없음
 * 반환 : 현재 일자를 문자열을 반환 (YYYY/MM/DD형태)
 * 기능 : 상동
 *------------------------------------------------------------------------*/
char *getdatestrF()
{
  struct tm *t;
  static char buf[30];

  t = get_curdate();

  sprintf(buf, "%04d/%02d/%02d", t->tm_year+1900, t->tm_mon+1, t->tm_mday);
  return buf;
}

/**----------------------------------------------------------------------
 * 함수명: gettimestr
 * 인수 : 없음
 * 반환 : 현재 시간을 문자열을 반환 (HHMMSS형태)
 * 기능 : 상동
 *------------------------------------------------------------------------*/
char *gettimestr()
{
  struct tm *t;
  static char buf[30];

  t = get_curdate();

  sprintf(buf, "%02d%02d%02d", t->tm_hour, t->tm_min, t->tm_sec);
  return buf;
}


/**----------------------------------------------------------------------
 * 함수명: gettimestrF
 * 인수 : 없음
 * 반환 : 현재 시간을 문자열을 반환 (HH:MM:SS형태)
 * 기능 : 상동
 *------------------------------------------------------------------------*/
char *gettimestrF()
{
  struct tm *t;
  static char buf[30];

  t = get_curdate();

  sprintf(buf, "%02d:%02d:%02d", t->tm_hour, t->tm_min, t->tm_sec);
  return buf;
}

