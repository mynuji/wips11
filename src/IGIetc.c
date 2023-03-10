/*==================================================================*/
/*a ȭ  ��  ��  : IGIetc.c                                           */
/* ��      ��  :                                                    */
/*------------------------------------------------------------------*/
/* ���̺귯��  :                                                    */
/* ��  ��  ��  : ������                                             */
/* ���  ȭ��  : IGIetc.h                                           */
/* ��  ��  ��  : 99. 7. 19 ( ���������� :   .  .   )                */
/*------------------------------------------------------------------*/
/* ��      ��  :                                                    */
/*                                                                  */
/*------------------------------------------------------------------*/
/*
 *  $Log: IGIetc.c,v $
 *  Revision 1.7  2005/01/28 07:36:27  root
 *  lock���� �Լ� ���
 *
 *  Revision 1.6  2005/01/25 11:50:28  root
 *  GetFileSize �Լ� �߰�
 *
 *  Revision 1.5  2005/01/25 10:12:32  root
 *  fd_lock, fd_unlock �Լ� �߰�
 *
 *  Revision 1.4  2005/01/20 05:29:58  root
 *  isExistFile�� mode ���� ���� ���� ����
 *
 *  Revision 1.3  2005/01/20 05:16:05  root
 *  isExistFile �Լ� �߰�
 *
 *  Revision 1.2  2005/01/19 06:55:20  root
 *    ����
 *
 *  Revision 1.1  2005/01/19 02:29:15  root
 *  Initial revision
 *
 *  Revision 1.5  2003/07/16 02:08:06  igi
 *  �׳� ����ϴ� �̴ϴ�.
 *  ������ �ߴ��� �𸨴ϴ�.
 *
 *  Revision 1.4  2003/05/23 01:15:41  igi
 *  ���� ������ �־���.
 *
 *  Revision 1.3  2003/04/14 04:53:39  igi
 *  IGIsleep() ����...sleep()�Լ��� ������
 *
 *  Revision 1.2  2003/04/10 10:51:11  igi
 *  RCS log ���� ���� ����
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
 * �Լ��� : main
 * ���   : �Լ� �׽�Ʈ��  ���� ���α׷�
 *     TEST_MODULE�� ���ǵǾ����� ���, ���� ���α׷����� ó����
 *-----------------------------------------------------------*/
main()
{
  char *s;

  s= IGIgetEnvIni("robot.ini", "AGENT", "POOL");
  printf("robot.ini ������ AGENT �׷쿡�� POOL�� ���� ã���ϴ�.\n");
  printf("%s\n", (s==NULL)?"NULL":s);
  IGIsleep(5000000);


}

#endif


/*==============================================================
 * �Լ��� : void IGIeraseLBlank(char *s)
 * ���   : ���ڿ� s�� ���� ������ �����ִ� �κ�.
 * ��ȯ   : ����
 * ��뿹 : char *s = "   abcd efg ";
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
 * �Լ��� : void IGIeraseRBlank(char *s)
 * ���   : ���ڿ� s�� ������ ������ �����ִ� �κ�
 * ��ȯ   : ����
 * ��뿹 : char *s = "   abcd efg ";
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
 * �Լ��� : void IGIeraseBlank(char *s)
 * ���   : ���ڿ� s�� �¿� ������ �����ִ� �κ�
 * ��ȯ   : ����
 * ��뿹 : char *s = "   abcd efg ";
 *          IGIeraseBlank(s);
 *          s  ->    "abcd efg"
*--------------------------------------------------------*/
void IGIeraseBlank(char *s)
{
  IGIeraseLBlank(s);
  IGIeraseRBlank(s);
}

/*========================================================
 * �Լ���: IGIgetEnvIni(char *ininame, char *group, char *var)
 *
 * ��  ��: ininame : ��ȸ�� INI���� ��
 *         group   : ��ȸ�� GROUP �̸�
 *         var     : ��ȸ�� ������
 *
 * ���  : ininame�� ���Ͽ��� group�� ���ǵ� ������ ��� 
 *         ������ ��´�.
 *         ini������ ������ # �� �ּ����� ó���Ǹ�,
 *         �׷��� [GROUP_NAME] �� �������� �׷� �̸��� '[]' 
 *         �ȿ� ����ȴ�.
 *         �� �׷��� ������ ���ο� �׷��̸��� ������ ������ 
 *         ��ϵ� ����
 *         �׷쳻�� ���ǵ� ����/������ �����Ѵ�.
 *         ������ ����  var=value �������� ����ȴ�.
 *         value���� �¿������� SPACE�� ������ ���ð� �Ǹ�, 
 *         ���ڿ� ���̿�
 *         SPACE�� ���� ���� SPACE��ü�� value�� �����Ѵ�.
 *
 * ��ȯ  : ��ȸ �������� ��, ��ȸ�� var�� ���� ��ȯ�ϸ�,
 *         ������ �߻����� ��, NULL�� ��ȯ�Ѵ�.
 *
 * �������: ���ο��� static ������ ����Ѵ�.
 *           value�� �ִ� ���̴� 200���� ���ѵȴ�.
 *
 * ��뿹: robot.ini ������  "AGENT" �׷��� "POOL"�� ���ǵ� 
 *         ���� ����� �Ұ��
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
   * �׷��� [GROUP] �������� ����
   *----------------------
   */
  sprintf(temp2, "[%s]", group);

  /*
   *-----------------------
   * ȭ���� ���� 
   *----------------------
   */
  if ( (f=fopen(ininame, "r")) == NULL ) return NULL;

   /*
    *-----------------------
    * ���ڿ��� ���پ� �д´� 
    *-----------------------
    */
  while (fgets(temp1, sizeof(temp1), f) != NULL) {

    /* 
     *----------------------------------
     * '#' �� ã�Ƽ� �� �ڴ� �����Ѵ�. 
     *----------------------------------
     */
    t = strchr(temp1, '#');
    if (t) *t = 0;    

    /* 
     *---------------------------------
     * ���ڿ��� �յ��� ������ �����Ѵ�. 
     *----------------------------------
     */
    IGIeraseBlank(temp1);
    t = strchr(temp1, '\n'); if (t) *t=0;
    t = strchr(temp1, '\r'); if (t) *t=0;

    if (temp1[0] == 0) continue;


    /*
     *---------------------------------------
     * ���� ���ڿ�(temp1)�� '['�� �����ϸ�,
     * �׷� ������ �����ؼ�, �׷� ��Ī�� ��������
     * Ȯ���Ѵ�. 
     * �̹� Ȯ�ε� �׷쿡�� �۾� �߿�(flag=1) ���ο�
     * �׷� ���� ������ ������ �Ǹ�, ��ȸ�� �����Ѵ�.
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
     * ���ڿ����� ������ ���� �и��Ѵ�.
     *--------------------------------------------
     */
    t = strchr(temp1, '=');
    if (!t) {
      printf("(IGIgetEnvIni)ȯ��ȭ�� ���� ����: %s\n", temp1);
      continue;
    }

    /*
     *--------------------------------------
     * '=' ���� ���ڸ� t�� ����Ű���� �̵� 
     *--------------------------------------
     */
    *t++ = 0;
    strcpy(temp2, t);
    IGIeraseBlank(temp1);

    /*
     *----------------------------------------
     * �ε����� ���� �ڷ��� �ε����� �ٸ��ٸ� 
     * �ٽ� �Ѷ��� �� �б����� ���� 
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
 * �Լ��� : get_curdate
 * ���   : ������ ��¥/�ð� �� ��´�.
 * ��ȯ   : �ð���
 *
 *------------------------------------------------------*/
struct tm *get_curdate()
{
  time_t t;

  t = time(NULL);

  return (localtime(&t));
}


/*=====================================================
 * �Լ��� : IGIisMatch(char s[], char key[])
 * �μ�   : s ��  �˻��ϰԵ� ����� �Ǵ� ���ڿ�
 *          key�� �˻��� Ű�� ���� ���ڿ��� '*', 
 *          '?'���� ���ڷ� ǥ���ɼ��ִ�.
 * ���   : key�� ���� ���ڿ��� s�� ���ԵǴ����� ã�� �Լ�
 * ��ȯ   : ���ڿ�(s)�� key�� ���Եȴٸ� 1��, �ƴϸ� 0�� ��ȯ
 * 
 * ��뿹 :  IGIisMatch("abcdefg", "abcdefg")  =>  1
 *           IGIisMatch("abcdefg", "abcdeff")  =>  0
 *           IGIisMatch("abcdefg", "abc*")     =>  1
 *           IGIisMatch("abcdefg", "abc??fg")  =>  1
 *           IGIisMatch("abcdefg", "a*c??fg")  =>  1
 *           IGIisMatch("abcdefg", "*c??fg")   =>  1
 *
 * ���ǻ���: ���� ������ ������ ���� ����.. �׽�Ʈ�� �ߴµ�.... 
 *      ���� �׽�Ʈ �ð����� ����� ������ ���� ���� 
 *      �׽�Ʈ�� ������ �����̵��� ���ߴ�.
 * ���̺귯�� �߿� pattern match �ϴ� �Լ��� �ִ� ��.. ��... 
 * ����� �� �Ŀ� �ȰŶ�.... ��... 
 *----------------------------------------------------------*/
int IGIisMatch(char s[], char key[])
{
  int i, j, wild;

  int temp_j=-1;

  i = j = wild = 0;

  /*
   *-------------------------------
   *  ���ڿ��� �� �Һ��Ҷ����� 
   *-------------------------------
   */
  while (i < strlen(s) ) {
    /*
     *-----------------------------
     * ?Ű�϶� �׳� ������  
     *-----------------------------
     */
    if (key[j] == '?')  j++;
    else {
    /* 
     *-------------------------------
     * �ּ� ����(���� ǥ���ϱ� ����� �����) 
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
   * ��ƾ�� ��ġ�� ������ i�� j�� �� ���ڿ��� 
   * ������ NULL�� ����Ű�� �־������, �������� 
   * ���̹Ƿ�, ���� �� �ڷᰡ ���� ���� �ʴٸ� 
   * ������ ��ȯ �Ʒ����� ���� �ʴٰ� �ƴ�, �� �� 
   * �ϳ��� NULL�� �ƴ϶�� 0�� ��ȯ�ϵ��� ���ľ� 
   * ���� ������ �ʹ�.  «���� �ٽ� �ѹ� �����غ���
   * �� ���̴�.                                                   
   *----------------------------------------*/
  if (s[i] != key[j]) return 0;
  return 1;
}

/*=============================================
 * �Լ��� : power
 * ���   : �ŵ� ������ ���� ���� ���Ѵ�.
 * ��ȯ   : ������ ��, �ŵ������� �� (1 �̻��� ��)
 *          ������ ��, -1
 *
 * ��뿹)     rt = power( 5, 2 );
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
 * �Լ��� : IGIsleep
 * �μ�   : sleep�� �ð� ��(microsec)
 * ���   : usleep �Լ��� ����� �Լ���, 
 *          select�� �̿��Ͽ� ����
 * ��ȯ   : ����
 * ��뿹 :  IGIsleep(500);  <- 0.5�� sleep
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
�Լ��� : gotoxy(int x, int y)
���   : Ŀ���� x, y ��ǥ�� �̵�
��ȯ   : ����.
��뿹 : gotoxy(x, y)
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
 * ������ ����ִ��� Ȯ���ϰ� ��� ���� ������
 * ����� ��� 
 * ��� ������� ����� Ǯ�������� ��ٸ���(F_SETLKW) 
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
 * ���� ����� ������ ��� �۾��� �����ٸ� 
 * ���� ����� �����ش�. 
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
 * �Լ���: getdatestr
 * �μ� : ����
 * ��ȯ : ���� ���ڸ� ���ڿ��� ��ȯ (YYYYMMDD����)
 * ��� : ��
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
 * �Լ���: getdatestrF2
 * �μ� : ����
 * ��ȯ : ���� ���ڸ� ���ڿ��� ��ȯ (YYYY-MM-DD����)
 * ��� : ��
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
 * �Լ���: getdatestrF
 * �μ� : ����
 * ��ȯ : ���� ���ڸ� ���ڿ��� ��ȯ (YYYY/MM/DD����)
 * ��� : ��
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
 * �Լ���: gettimestr
 * �μ� : ����
 * ��ȯ : ���� �ð��� ���ڿ��� ��ȯ (HHMMSS����)
 * ��� : ��
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
 * �Լ���: gettimestrF
 * �μ� : ����
 * ��ȯ : ���� �ð��� ���ڿ��� ��ȯ (HH:MM:SS����)
 * ��� : ��
 *------------------------------------------------------------------------*/
char *gettimestrF()
{
  struct tm *t;
  static char buf[30];

  t = get_curdate();

  sprintf(buf, "%02d:%02d:%02d", t->tm_hour, t->tm_min, t->tm_sec);
  return buf;
}

