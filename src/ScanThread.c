/*==============================================================*/
/* ȭ  ��  ��  : ScanThread.c                                   */
/* ��      ��  :                                                */
/*--------------------------------------------------------------*/
/* ���̺귯��  :                                                */
/* ��  ��  ��  : ������                                         */
/* ���  ȭ��  : ScanThread.h                                   */
/* ��  ��  ��  : 03. 4. 14 ( ���������� :   .  .   )            */
/*--------------------------------------------------------------*/
/* ��      ��  :                                                */
/*                                                              */
/*--------------------------------------------------------------*/
/*
 *  $Log: ScanThread.c,v $
 *
 *                                                              */
/*--------------------------------------------------------------*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <pthread.h>
#include <sched.h>
#include <unistd.h>

#include <pcap.h>
#include <sys/socket.h>

#include "ScanThread.h"
#include "IGIetc.h"
#include "wips.h"


extern ap_t AccessPoint[];
extern tran_t TranData;
extern ini_t ini;


int getCalcChannel(unsigned int frequency)
{
	int channel;

	if (frequency > 5000) {
    if (frequency <= 5160) return 32;
		channel = ((frequency - 5035) / 5) + 7;

		if (channel < 32) return 32;
		if (channel > 196) return 196;

		return channel;
	}
	if (frequency > 2400) {
    if (frequency <= 2412) return 1;
		channel = ((frequency - 2412) / 5) + 1;

		if (channel < 1) return 1;
		if (channel > 14) return 14;

		return channel;
	}
	return 0;
}

void printSSID()
{
#ifdef DEBUG_MONITOR

	for (int i=0; i<MAX_SSID_CNT; i++) {
		if (!AccessPoint[i].enable && IS0000(AccessPoint[i].mac)) break;

  	printf("[!] %02d  #%d(%d): %c [%s], %02x:%02x:%02x:%02x:%02x:%02x\n", i+1, 
			             AccessPoint[i].channel, AccessPoint[i].enable?' ':'x',
									 AccessPoint[i].frequency, AccessPoint[i].ssid, 
									 MAC(AccessPoint[i].mac));
	}
#endif
}

void addSSID(ap_t ap)
{
	const char temp[6] = { 0, 0, 0, 0, 0, 0 };

	if (IS0000(ap.mac) || ISFFFF(ap.mac)) return;

	ap.ssid[sizeof(ap.ssid)-1] = 0;

	for (int i=0; i<MAX_SSID_CNT; i++) {
		if (AccessPoint[i].enable && ISMATCH_MAC(AccessPoint[i].mac, ap.mac)) {
			if (AccessPoint[i].channel != ap.channel) AccessPoint[i].channel = ap.channel;
			break;
		}

		if (!AccessPoint[i].enable && IS0000(AccessPoint[i].mac)) {
			AccessPoint[i].enable = 1;
			memcpy(AccessPoint[i].mac, ap.mac, 6);
			AccessPoint[i].frequency = ap.frequency;

			AccessPoint[i].channel = (ap.channel)?ap.channel:getCalcChannel(ap.frequency);

			if (ap.ssid[0]) strcpy(AccessPoint[i].ssid, ap.ssid);
			else AccessPoint[i].ssid[0] = 0;
#ifdef DEBUG_MONITOR_DETAIL
  		printf("[!] #%d: [%s], %02x:%02x:%02x:%02x:%02x:%02x\n", 
			             ap.channel, ap.ssid, MAC(ap.mac));
//			printSSID();
//			printf("\n");
#endif

			break;
		}
	}
}



/*-------------------------------------------------------
 * Queue Full �� front, rear ��ġ ���η� �˻����� �ʰ�,
 * �����Ͱ� �ִ��� ����(enable)�� Ȯ���Ͽ���.
 *
 * full�� ������ ���� ���� ���, -1�� ��ȯ
 * �������� ���� 0�� ��ȯ��.
 *-----------------------------------------------------*/
int addTranData(frame_t frame)
{
  int front, rear;
	char device[6], ap[6];

  front = TranData.front;
  rear = TranData.rear;


	if (!frame.fromDS && !frame.toDS) {
		memcpy(device, (!ISMATCH_MAC(frame.address1, frame.address3)?frame.address1:frame.address2), 6);
		memcpy(ap,     ( ISMATCH_MAC(frame.address1, frame.address3)?frame.address1:frame.address2), 6);
	}

	if (frame.fromDS && !frame.toDS) {
		memcpy(device, frame.address1, 6);
		memcpy(ap    , frame.address2, 6);
	}
	if (!frame.fromDS && frame.toDS) {
		memcpy(device, frame.address2, 6);
		memcpy(ap    , frame.address1, 6);
	}
	if (frame.fromDS && frame.toDS) {
		printf("[?] *************************\n");
		memcpy(device, (!ISMATCH_MAC(frame.address1, frame.address3)?frame.address1:frame.address2), 6);
		memcpy(ap,     ( ISMATCH_MAC(frame.address1, frame.address3)?frame.address1:frame.address2), 6);
	}

	if (IS0000(device) || ISFFFF(device) || IS0000(ap) || ISFFFF(ap) ) {
		return 0;
	}
	

	/* ������ ������ ������ �������� �ʴ´�.
   */
	for (int i=0; i<MAX_TRANSACTION_CNT; i++) {
		int pos;

		pos = (rear+i) % MAX_TRANSACTION_CNT;
		if (!TranData.data[pos].enable) break;

		if (ISMATCH_MAC(TranData.data[pos].device, device) &&
		    ISMATCH_MAC(TranData.data[pos].ap, ap)       ) {
			return 0;
		}
	}

	/*
	 * ť�� �߰�
	 */
  if (TranData.data[front].enable) {
		return -1; 
	}

  TranData.data[front].type = frame.type;
  TranData.data[front].subtype = frame.subtype;
  TranData.data[front].channel = (frame.channel==0)?getCalcChannel(frame.frequency):frame.channel;
//	printf("[!] Scan Thread: channel = %d\n", TranData.data[front].channel);
             
	memcpy(TranData.data[front].device, device, 6);
	memcpy(TranData.data[front].ap,     ap,     6);
  TranData.data[front].enable = 1;
  TranData.front++;

  if (TranData.front >= MAX_TRANSACTION_CNT) TranData.front = 0;

  return 0;
}

trandata_t *getTranData()
{
  static trandata_t node;
  int front, rear;

  front = TranData.front;
  rear  = TranData.rear;

  if (!TranData.data[rear].enable) return NULL;
  
  node.type    = TranData.data[rear].type;
  node.subtype = TranData.data[rear].subtype;
  node.channel = TranData.data[rear].channel;
//  printf("[!] %s(%d) ch=%d\n", __FUNCTION__, __LINE__, node.channel);
        
  memcpy(node.device, TranData.data[rear].device, sizeof(node.device) );
  memcpy(node.ap,     TranData.data[rear].ap,     sizeof(node.ap)     );  

  TranData.data[rear].enable = 0;
  TranData.rear++;
  if (TranData.rear >= MAX_TRANSACTION_CNT) TranData.rear = 0;

  return &node;
}




void prnHeaderInfo(frame_t frame)
{
#ifdef DEBUG_CAPTURE
  char *conv[]= {"BEACON", "AUTH", "PROB_REQ", "PROB_RES", "ASSOC_REQ", "ASSOC_RES", "RE_ASSO", "ACTION", "NULLDATA", "QOSDATA", "DATA", "UNKNOWN"};


  switch (frame.subtype) {
//    case BEACON:
//        printf("[!] %13s   %1d    %1d  %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x %3d %-20.20s %3d %5.3f\n",
//                conv[frame.subtype], frame.fromDS, frame.toDS,
//                MAC(frame.address1), MAC(frame.address2), MAC(frame.address3), frame.ssid_len, frame.ssid, frame.channel, (float)frame.frequency /1000 );
//        break;
//    case PROB_REQ:
    case NULLDATA:
//    case QOSDATA:
    case DATA:
    case PROB_RES:
    case ASSOC_REQ:
          printf("[!] %13s   %1d    %1d  %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x %3d %-20.20s\n",
                conv[frame.subtype], frame.fromDS, frame.toDS,
                MAC(frame.address1), MAC(frame.address2), MAC(frame.address3), frame.ssid_len, frame.ssid );
/*
        if (ISMATCH_MAC(frame.address1, frame.address3))
          printf("[!] %13s   %1d    %1d  %02x:%02x:%02x:%02x:%02x:%02x %-17s %02x:%02x:%02x:%02x:%02x:%02x %3d %-20.20s\n",
                conv[frame.subtype], frame.fromDS, frame.toDS,
                MAC(frame.address2), ISFFFF(frame.address1)?"-->ANY":"-->AP", MAC(frame.address3), frame.ssid_len, frame.ssid );
        else if (ISMATCH_MAC(frame.address2, frame.address3))
          printf("[!] %13s   %1d    %1d  %-17s %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x %3d %-20.20s\n",
                conv[frame.subtype], frame.fromDS, frame.toDS,
                ISFFFF(frame.address2)?"ANY<--":"AP<--", MAC(frame.address1), MAC(frame.address3), frame.ssid_len, frame.ssid );
        else
          printf("[!] %13s   %1d    %1d  %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x %3d %-20.20s\n",
                conv[frame.subtype], frame.fromDS, frame.toDS,
                MAC(frame.address1), MAC(frame.address2), MAC(frame.address3), frame.ssid_len, frame.ssid );
*/
        break;
    case ACTION:
    case AUTH:
    case ASSOC_RES:
          printf("[!] %13s   %1d    %1d  %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x seq=%3d status=%3d\n",
                conv[frame.subtype], frame.fromDS, frame.toDS,
                MAC(frame.address1), MAC(frame.address2), MAC(frame.address3), frame.seq, frame.status );
/*
        if (ISMATCH_MAC(frame.address1, frame.address3))
          printf("[!] %13s   %1d    %1d  %02x:%02x:%02x:%02x:%02x:%02x %-17s %02x:%02x:%02x:%02x:%02x:%02x seq=%3d status=%3d\n",
                conv[frame.subtype], frame.fromDS, frame.toDS,
                MAC(frame.address2), "-->AP", MAC(frame.address3), frame.seq, frame.status );
        else if (ISMATCH_MAC(frame.address2, frame.address3))
          printf("[!] %13s   %1d    %1d  %-17s %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x seq=%3d status=%3d\n",
                conv[frame.subtype], frame.fromDS, frame.toDS,
                "AP<--", MAC(frame.address1), MAC(frame.address3), frame.seq, frame.status );
        else
          printf("[!] %13s   %1d    %1d  %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x seq=%3d status=%3d\n",
                conv[frame.subtype], frame.fromDS, frame.toDS,
                MAC(frame.address1), MAC(frame.address2), MAC(frame.address3), frame.seq, frame.status );
*/

        break;
  }

#endif
}

#ifdef ____DELETE
void prnHeaderInfo(frame_t frame)
{
#ifdef DEBUG_CAPTURE
	char *conv[]= {"BEACON", "AUTH", "PROB_REQ", "PROB_RES", "ASSOC_REQ", "ASSOC_RES", "RE_ASSO", "ACTION", "UNKNOWN"};

	switch (frame.subtype) {
/*
		case BEACON:
				printf("[!] %13s   %1d    %1d  %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x %3d %-20.20s %3d %5.3f\n", 
								conv[frame.subtype], frame.fromDS, frame.toDS,
								MAC(frame.address1), MAC(frame.address2), MAC(frame.address3), frame.ssid_len, frame.ssid, frame.channel, (float)frame.frequency /1000 );
				break;
		case PROB_REQ:
*/
		case PROB_RES:
		case ASSOC_REQ:
				if (ISMATCH_MAC(frame.address1, frame.address3))
					printf("[!] %13s   %1d    %1d  %-17s %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x %3d %-20.20s\n", 
								conv[frame.subtype], frame.fromDS, frame.toDS,
								ISFFFF(frame.address1)?"ANY<--":"AP<--", MAC(frame.address2), MAC(frame.address3), frame.ssid_len, frame.ssid );
				else if (ISMATCH_MAC(frame.address2, frame.address3))
					printf("[!] %13s   %1d    %1d  %02x:%02x:%02x:%02x:%02x:%02x %-17s %02x:%02x:%02x:%02x:%02x:%02x %3d %-20.20s\n", 
								conv[frame.subtype], frame.fromDS, frame.toDS,
								MAC(frame.address1), ISFFFF(frame.address2)?"-->ANY":"-->AP", MAC(frame.address3), frame.ssid_len, frame.ssid );
				else
					printf("[!] %13s   %1d    %1d  %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x %3d %-20.20s\n", 
								conv[frame.subtype], frame.fromDS, frame.toDS,
								MAC(frame.address1), MAC(frame.address2), MAC(frame.address3), frame.ssid_len, frame.ssid );
				break;
		case ACTION:	
		case AUTH:
		case ASSOC_RES:
				if (ISMATCH_MAC(frame.address1, frame.address3))
					printf("[!] %13s   %1d    %1d  %-17s %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x seq=%3d status=%3d\n", 
								conv[frame.subtype], frame.fromDS, frame.toDS,
								"AP<--", MAC(frame.address2), MAC(frame.address3), frame.seq, frame.status );
				else if (ISMATCH_MAC(frame.address2, frame.address3))
					printf("[!] %13s   %1d    %1d  %02x:%02x:%02x:%02x:%02x:%02x %-17s %02x:%02x:%02x:%02x:%02x:%02x seq=%3d status=%3d\n", 
								conv[frame.subtype], frame.fromDS, frame.toDS,
								MAC(frame.address1), "-->AP", MAC(frame.address3), frame.seq, frame.status );
				else
					printf("[!] %13s   %1d    %1d  %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x seq=%3d status=%3d\n", 
								conv[frame.subtype], frame.fromDS, frame.toDS,
								MAC(frame.address1), MAC(frame.address2), MAC(frame.address3), frame.seq, frame.status );
				

				break;
	}

#endif
}

#endif


void prnTranData()
{
	int front, rear;
  char *conv[]= {"BEACON", "AUTH", "PROB_REQ", "PROB_RES", "ASSOC_REQ", 
								 "ASSOC_RES", "RE_ASSO", "ACTION", "NULLDATA", "QOSDATA", "DATA", "UNKNOWN"};
	int i;

	printf("\n");
	front = TranData.front;
	rear = TranData.rear;
	printf(" ------------------ Transaction Data ---------------------\n");
	for (i=0; i<MAX_TRANSACTION_CNT; i++) {
		int pos;

		pos = (rear+i) % MAX_TRANSACTION_CNT;
		if (!TranData.data[pos].enable) break;
		printf("    %3d %-15s %02x:%02x:%02x:%02x:%02x:%02x      %02x:%02x:%02x:%02x:%02x:%02x\n",
								pos, conv[TranData.data[pos].subtype], 
								MAC(TranData.data[pos].device), MAC(TranData.data[pos].ap));
	}
	if (i==0) printf(" Empty.. \n");
	printf(" ---------------------------------------------------------\n");

}

int getHeaderInfo(frame_t *frame, const unsigned char *p)
{
  int pos;
	int dummy;

  memset(frame, 0, sizeof(frame_t));

  frame->it_len    = *(p+2)  + *(p+ 3)*0xff;
  frame->frequency = *(p+10) + *(p+11)*0xff;

  pos = frame->it_len;

  /*---------------------------------------------------
   * beacon frame
   */
//  if (*(p+pos) == 0x80) {
	switch (*(p+pos)) {
	case 0x80:

    frame->type = T_MGMT;
    frame->subtype = BEACON;

    if (*(p+pos+1) & 0x01) frame->toDS   = 1;
    if (*(p+pos+1) & 0x02) frame->fromDS = 1;

    /*
     * frame control: 2
     * duration     : 2
     * DA           : 6
     * SA           : 6
     * BSSID        : 6
     */
    memcpy(frame->address1, (p+pos+2+2), 6);;
    memcpy(frame->address2, (p+pos+2+2+6), 6);
    memcpy(frame->address3, (p+pos+2+2+6+6), 6);

    /*
     * frag/seq     : 2
     * timestamp    : 8
     * interval     : 2
     * capability   : 2
     * ???          : 1
     */
    pos += (2+2+6+6+6+2+8+2+2+1);
    frame->ssid_len = *(p+pos);

    /*
     * ssid_len     : 1
     */
    memcpy(frame->ssid, (p+pos+1), frame->ssid_len);
    frame->ssid[frame->ssid_len] = 0;

    pos += frame->ssid_len+1;

    /*----------------
     * ä�� ������ ���´�.
     */
    do {
      if ( *(p+pos) > 0x3d ) break;
      if ( (*(p+pos) == 0x03) || (*(p+pos) == 0x3d) ) {
//      if ( (*(p+pos) == 0x3d) && (frame->frequency > 5000))  {
        pos++;
        frame->channel = *(p+pos+1);
        pos += *(p+pos);               /* Tag Length */
        break;
//      }
      }
      pos++;
      pos += *(p+pos);
      pos++;
    } while(1);
    return 0;
//  }

  /*---------------------------------------------------
   * probe request
   */

//  if ( *(p+pos) == 0x40 ) {
	case 0x40:

    frame->type = T_MGMT;
    frame->subtype = PROB_REQ;

    if (*(p+pos+1) & 0x01) frame->toDS   = 1;
    if (*(p+pos+1) & 0x02) frame->fromDS = 1;

    /*
     * frame control   : 2
     * duration        : 2
     *
     * DA              : 6  FF:FF:FF:FF:FF:FF (broadcast)
     * SA              : 6
     * BSSID           : 6  FF:FF:FF:FF:FF:FF (any ap)
     */
    memcpy(frame->address1, (p+pos+2+2), 6);
    memcpy(frame->address2, (p+pos+2+2+6), 6);
    memcpy(frame->address3, (p+pos+2+2+6+6), 6);

    /*
     * frag/seq     : 2
     */
    pos += (2+2+6+6+6+2);

    if (*(p+pos) == 0) {
      frame->ssid_len = *(p+pos+1);
      memcpy(frame->ssid, (p+pos+2), frame->ssid_len);
      frame->ssid[frame->ssid_len] = 0;
    }
    return 0;
//  }

  /*----------------------------
   * ���� ������
   */
//  if ( *(p+pos) == 0xb0) {
	case 0xb0:
    frame->type = T_MGMT;
    frame->subtype = AUTH;

    if (*(p+pos+1) & 0x01) frame->toDS = 1;
    if (*(p+pos+1) & 0x02) frame->fromDS = 1;

    /*
     * frame control : 2
     * duration      : 2
     * DA            : 6  (destination)
     * SA            : 6  (source)
     * BSSID         : 6  (bssid; AP�� MAC)
     */
    memcpy(frame->address1, (p+pos+2+2), 6);
    memcpy(frame->address2, (p+pos+2+2+6), 6);
    memcpy(frame->address3, (p+pos+2+2+6+6), 6);

    /*
     * frag/seq     : 2
     * algorithm    : 2
     * auth seq     : 2
     */
    pos += (2+2+6+6+6+2+2);
    frame->seq    = *(p+pos) + *(p+pos+1)*0xff;
    pos += 2;
    frame->status = *(p+pos) + *(p+pos+1)*0xff;

    frame->ssid[0] = 0;
    return 0;
//  }


  /*----------------------------
   * ���� ��û ������
   */
//  if ( *(p+pos) == 0x00) {
	case 0x00:
    frame->type = T_MGMT;
    frame->subtype = ASSOC_REQ;

    if (*(p+pos+1) & 0x01) frame->toDS = 1;
    if (*(p+pos+1) & 0x02) frame->fromDS = 1;

    /*
     * frame control : 2
     * duration      : 2
     * DA            : 6 (destination)
     * SA            : 6 (source)
     * BSSID         : 6 (AP)
     */
    memcpy(frame->address2, (p+pos+2+2), 6);
    memcpy(frame->address1, (p+pos+2+2+6), 6);
    memcpy(frame->address3, (p+pos+2+2+6+6), 6);

    /*
     * frag/seq     : 2
     * capability   : 2
     * interval     : 2
     * tag #0       : 1
     * SSID IE      : N
     */
    pos += (2+2+6+6+6+2+2+2);
    if (*(p+pos) == 0) {
      frame->ssid_len = *(p+pos+1);

      memcpy(frame->ssid, (p+pos+2), frame->ssid_len);
      frame->ssid[frame->ssid_len] = 0;
    }
    else {
      frame->ssid_len = 0;
      frame->ssid[0] = 0;
    }
    return 0;
//  }

  /*----------------------------
   * ���� ���� ������
   */
//  if ( *(p+pos) == 0x10) {
	case 0x10:
    frame->type = T_MGMT;
    frame->subtype = ASSOC_RES;

    if (*(p+pos+1) & 0x01) frame->toDS = 1;
    if (*(p+pos+1) & 0x02) frame->fromDS = 1;

    /*
     * frame control : 2
     * duration      : 2
     * DA            : 6 (destination)
     * SA            : 6 (source)
     * BSSID         : 6 (AP)
     */
    memcpy(frame->address2, (p+pos+2+2), 6);
    memcpy(frame->address1, (p+pos+2+2+6), 6);
    memcpy(frame->address3, (p+pos+2+2+6+6), 6);

    /*
     * frag/seq     : 2
     * capability   : 2
     * status       : 2
     */
    pos += (2+2+6+6+6+2+2);
    frame->ssid_len = 0; frame->ssid[0] = 0;

    frame->status = *(p+pos) + *(p+pos+1)*0xff;
    return 0;

//  }

  /*----------------------------
   * ����տ�û/����
   */
//  if ( *(p+pos) == 0x20) {
	case 0x20:
    frame->type = T_MGMT;
    frame->subtype = RE_ASSO;

    if (*(p+pos+1) & 0x01) frame->toDS = 1;
    if (*(p+pos+1) & 0x02) frame->fromDS = 1;

    /*
     * frame control : 2
     * duration      : 6
     * DA            : 6
     * SA            : 6
     * BSSID         : 6
     */
    memcpy(frame->address2, (p+pos+2+6), 6);
    memcpy(frame->address1, (p+pos+2+6+6), 6);
    memcpy(frame->address3, (p+pos+2+6+6+6), 6);

    /*
     * frag/seq     : 2
     * capability   : 2
     * listen interval       : 2
     */
    pos += (2+6+6+6+6+2+2+2);
    if (*(p+pos) == 0) {
      memcpy(frame->cur_ap, (p+pos), 6);

      pos += 6;
      frame->ssid_len = *(p+pos+1);

      memcpy(frame->ssid, (p+pos+2), frame->ssid_len);
      frame->ssid[frame->ssid_len] = 0;
    }
    return 0;
//  }

  /*----------------------------
   * action
   */
//  if ( *(p+pos) == 0xd0) {
	case 0xd0:
    frame->type = T_MGMT;
    frame->subtype = ACTION;

    if (*(p+pos+1) & 0x01) frame->toDS = 1;
    if (*(p+pos+1) & 0x02) frame->fromDS = 1;

    /*
     * duration      : 2
     * DA            : 6  (destination)
     * SA            : 6  (source)
     * BSSID         : 6  (bssid; AP�� MAC)
     * seq           : 2
     */
    memcpy(frame->address2, (p+pos+2+2), 6);
    memcpy(frame->address1, (p+pos+2+2+6), 6);
    memcpy(frame->address3, (p+pos+2+2+6+6), 6);

    frame->seq = 0;
    frame->status=0;
    frame->ssid[0] = 0;
    return 0;
//  }
	case 0x50:
    frame->type = T_MGMT;
    frame->subtype = PROB_RES;

    if (*(p+pos+1) & 0x01) frame->toDS   = 1;
    if (*(p+pos+1) & 0x02) frame->fromDS = 1;

    /*
     * frame control   : 2
     * duration        : 2
     *
     * DA              : 6  FF:FF:FF:FF:FF:FF (broadcast)
     * SA              : 6
     * BSSID           : 6  FF:FF:FF:FF:FF:FF (any ap)
     */
    memcpy(frame->address1, (p+pos+2+2), 6);
    memcpy(frame->address2, (p+pos+2+2+6), 6);
    memcpy(frame->address3, (p+pos+2+2+6+6), 6);

    /*
     * frag/seq     : 2
     */
    pos += (2+2+6+6+6+2);

    if (*(p+pos) == 0) {
      frame->ssid_len = *(p+pos+1);
      memcpy(frame->ssid, (p+pos+2), frame->ssid_len);
      frame->ssid[frame->ssid_len] = 0;
    }
		return 0;
	case 0x08:
	case 0x18:
	case 0x28:
	case 0x38:
	case 0x48:
	case 0x58:
case 0x68:
	case 0x78:
	case 0x88:
	case 0xa9:
	case 0xb9:
	case 0xc9:
	case 0xd9:
	case 0xe9:
	case 0xf8:
    frame->type = T_DATA;
		if ( *(p+pos) == 0x48 ) frame->subtype = NULLDATA;
		if ( *(p+pos) <= 0x78 ) frame->subtype = DATA;
		if ( *(p+pos) >= 0x88 ) frame->subtype = QOSDATA;
		dummy = 4;

    if (*(p+pos+1) & 0x01) frame->toDS   = 1;
    if (*(p+pos+1) & 0x02) frame->fromDS = 1;

    /*
     * QoS : addr1 -> device, addr2 ->ap 
     * STA(SA)         : 6  FF:FF:FF:FF:FF:FF (broadcast)
     * Dest(BSSID)     : 6
     */
    memcpy(frame->address1, (p+pos+dummy), 6);
    memcpy(frame->address2, (p+pos+dummy+6), 6);
    memcpy(frame->address3, (p+pos+dummy+6+6), 6);

		return 0;
	default: 
//		printf("   ******************************\n");
//		printf("[?] type = %02x\n", *(p+pos));
		break;
	}


  return 0;
}

#ifdef _______DELTE_
int getHeaderInfo(frame_t *frame, const unsigned char *p)
{
	int pos;

	memset(frame, 0, sizeof(frame_t));

	frame->it_len    = *(p+2)  + *(p+ 3)*0xff;
	frame->frequency = *(p+10) + *(p+11)*0xff;

	pos = frame->it_len;

	/*---------------------------------------------------
   * beacon frame
	 */
	if (*(p+pos) == 0x80) {

		frame->type = T_MGMT;
		frame->subtype = BEACON;

		if (*(p+pos+1) & 0x01) frame->toDS   = 1;
		if (*(p+pos+1) & 0x02) frame->fromDS = 1;

		/*
     * frame control: 2
     * duration     : 2
		 * DA           : 6
		 * SA           : 6
		 * BSSID        : 6
     */
		memcpy(frame->address1, (p+pos+2+2), 6);;
		memcpy(frame->address2, (p+pos+2+2+6), 6);
		memcpy(frame->address3, (p+pos+2+2+6+6), 6);

		/*
     * frag/seq     : 2
		 * timestamp    : 8 
		 * interval     : 2
		 * capability   : 2
		 * ???          : 1
		 */
		pos += (2+2+6+6+6+2+8+2+2+1);
		frame->ssid_len = *(p+pos);
		
		/*
		 * ssid_len     : 1
		 */
		memcpy(frame->ssid, (p+pos+1), frame->ssid_len);
		frame->ssid[frame->ssid_len] = 0;

		pos += frame->ssid_len+1;

		/*----------------
		 * ä�� ������ ���´�.
		 */
		do {
			if ( *(p+pos) > 0x3d ) break;
			if ( (*(p+pos) == 0x03) || (*(p+pos) == 0x3d) ) {
//			if ( (*(p+pos) == 0x3d) && (frame->frequency > 5000))  {
				pos++;
				frame->channel = *(p+pos+1);
				pos += *(p+pos);               /* Tag Length */
				break;
//			}
			}
			pos++;
			pos += *(p+pos);
			pos++;
		} while(1);	
		return 0;
	}			

	/*---------------------------------------------------
   * probe request
	 */

	if ( *(p+pos) == 0x40 ) {

		frame->type = T_MGMT;
		frame->subtype = PROB_REQ;

		if (*(p+pos+1) & 0x01) frame->toDS   = 1;
		if (*(p+pos+1) & 0x02) frame->fromDS = 1;

		/*
		 * frame control   : 2
		 * duration        : 2
		 *
		 * DA              : 6  FF:FF:FF:FF:FF:FF (broadcast)
		 * SA              : 6
		 * BSSID           : 6  FF:FF:FF:FF:FF:FF (any ap)
		 */
		memcpy(frame->address1, (p+pos+2+2), 6);
		memcpy(frame->address2, (p+pos+2+2+6), 6);
		memcpy(frame->address3, (p+pos+2+2+6+6), 6);

		/*
     * frag/seq     : 2
		 */
		pos += (2+2+6+6+6+2);
		
		if (*(p+pos) == 0) {
			frame->ssid_len = *(p+pos+1);
			memcpy(frame->ssid, (p+pos+2), frame->ssid_len);
			frame->ssid[frame->ssid_len] = 0;
		}
		return 0;
	}

	/*----------------------------
	 * ���� ������
	 */
	if ( *(p+pos) == 0xb0) {
		frame->type = T_MGMT;
		frame->subtype = AUTH;

		if (*(p+pos+1) & 0x01) frame->toDS = 1;
		if (*(p+pos+1) & 0x02) frame->fromDS = 1;

		/*
		 * frame control : 2
		 * duration			 : 2
		 * DA						 : 6  (destination)
		 * SA            : 6  (source)
		 * BSSID         : 6  (bssid; AP�� MAC)
		 */
		memcpy(frame->address1, (p+pos+2+2), 6);
		memcpy(frame->address2, (p+pos+2+2+6), 6);
		memcpy(frame->address3, (p+pos+2+2+6+6), 6);

		/*
     * frag/seq     : 2
     * algorithm    : 2
		 * auth seq     : 2
		 */
		pos += (2+2+6+6+6+2+2);
		frame->seq    = *(p+pos) + *(p+pos+1)*0xff;
		pos += 2;
		frame->status = *(p+pos) + *(p+pos+1)*0xff;
		
		frame->ssid[0] = 0;
		return 0;
	}


	/*----------------------------
	 * ���� ��û ������
	 */
	if ( *(p+pos) == 0x00) {
		frame->type = T_MGMT;
		frame->subtype = ASSOC_REQ;

		if (*(p+pos+1) & 0x01) frame->toDS = 1;
		if (*(p+pos+1) & 0x02) frame->fromDS = 1;

		/*
		 * frame control : 2
		 * duration			 : 2
		 * DA						 : 6 
		 * SA            : 6
		 * BSSID         : 6
		 */
		memcpy(frame->address1, (p+pos+2+2), 6);
		memcpy(frame->address2, (p+pos+2+2+6), 6);
		memcpy(frame->address3, (p+pos+2+2+6+6), 6);

		/*
     * frag/seq     : 2
		 * capability   : 2
		 * interval     : 2
		 * tag #0       : 1
		 * SSID IE      : N
		 */
		pos += (2+2+6+6+6+2+2+2);
		if (*(p+pos) == 0) {
			frame->ssid_len = *(p+pos+1);

			memcpy(frame->ssid, (p+pos+2), frame->ssid_len);
			frame->ssid[frame->ssid_len] = 0;
		}
		else {
			frame->ssid_len = 0;
			frame->ssid[0] = 0;
		}		
		return 0;

	}

	/*----------------------------
	 * ���� ���� ������
	 */
	if ( *(p+pos) == 0x10) {
		frame->type = T_MGMT;
		frame->subtype = ASSOC_RES;

		if (*(p+pos+1) & 0x01) frame->toDS = 1;
		if (*(p+pos+1) & 0x02) frame->fromDS = 1;

		/*
		 * frame control : 2
		 * duration			 : 2
		 * DA						 : 6 
		 * SA            : 6
		 * BSSID         : 6
		 */
		memcpy(frame->address1, (p+pos+2+2), 6);
		memcpy(frame->address2, (p+pos+2+2+6), 6);
		memcpy(frame->address3, (p+pos+2+2+6+6), 6);

		/*
     * frag/seq     : 2
		 * capability   : 2
		 * status       : 2
		 */
		pos += (2+2+6+6+6+2+2);
		frame->ssid_len = 0; frame->ssid[0] = 0;
		
		frame->status = *(p+pos) + *(p+pos+1)*0xff;
		return 0;

	}

	/*----------------------------
	 * ����տ�û/����
	 */
	if ( *(p+pos) == 0x20) {
		frame->type = T_MGMT;
		frame->subtype = RE_ASSO;

		if (*(p+pos+1) & 0x01) frame->toDS = 1;
		if (*(p+pos+1) & 0x02) frame->fromDS = 1;

		/*
		 * frame control : 2
		 * duration			 : 6
		 * DA						 : 6 
		 * SA            : 6
		 * BSSID         : 6
		 */
		memcpy(frame->address1, (p+pos+2+6), 6);
		memcpy(frame->address2, (p+pos+2+6+6), 6);
		memcpy(frame->address3, (p+pos+2+6+6+6), 6);

		/*
     * frag/seq     : 2
		 * capability   : 2
		 * listen interval       : 2
		 */
		pos += (2+6+6+6+6+2+2+2);
		if (*(p+pos) == 0) {
			memcpy(frame->cur_ap, (p+pos), 6);

			pos += 6;
			frame->ssid_len = *(p+pos+1); 
		
			memcpy(frame->ssid, (p+pos+2), frame->ssid_len);
			frame->ssid[frame->ssid_len] = 0;
		}
		return 0;
	}
	/*----------------------------
	 * action
	 */
	if ( *(p+pos) == 0xd0) {
		frame->type = T_MGMT;
		frame->subtype = ACTION;

		if (*(p+pos+1) & 0x01) frame->toDS = 1;
		if (*(p+pos+1) & 0x02) frame->fromDS = 1;

		/*
		 * duration			 : 2
		 * DA						 : 6  (destination)
		 * SA            : 6  (source)
		 * BSSID         : 6  (bssid; AP�� MAC)
		 * seq           : 2
		 */
		memcpy(frame->address1, (p+pos+2+2), 6);
		memcpy(frame->address2, (p+pos+2+2+6), 6);
		memcpy(frame->address3, (p+pos+2+2+6+6), 6);

		frame->seq = 0;
		frame->status=0;
		frame->ssid[0] = 0;
		return 0;
	}


	return 0;
}
#endif


/*===========================================================
 * function: pCapture
 * parameter:
 *
 *
 * return value: none
 *
 * example:
 *  if (pcap_loop(pd, -1, pCapture,  0) < 0)  {
 *    perror(pcap_geterr(pd));
 *  }
 *=========================================================*/
void pCapture(void *arg, const struct pcap_pkthdr *h, const unsigned char *p)
{
  tfunc_t *func;
	radiotap_t *rtap;
	struct ap_t ap;;
	frame_t frame;
	int rt;
	char dummy[6] = { 0x64, 0x7b, 0xce, 0x11, 0xab, 0x68 };
  
	printf("."); fflush(stdout);

//#ifndef _SKIP_SCAN_THREAD
	func = (tfunc_t *) arg;

	rtap = (radiotap_t *)p;

	getHeaderInfo(&frame, p);

//	printf("."); fflush(stdout);

//	if (ISMATCH_MAC(frame.address1, dummy) || 
//			ISMATCH_MAC(frame.address2, dummy)) 
		prnHeaderInfo(frame);

	/*-------------------------------------------
	 * ���� �������� �ƴ϶�� SKIP
	 * DATA �����ӵ� ���Ź޴� ������ ����
	 */
//	if (frame.type != T_MGMT) return;



  /*--------------------------------------------
   * ���������� ���ŵǴ� ��Ŷ���� AP�� SSID���� ��ȸ�Ѵ�. 
   * ��ȸ�� SSID, MAC, ����ä��#�� �����Ѵ�. 
   * �̹� ��ȸ�� SSID��� �߰����� �ʴ´�. �ٸ�, ä�������� ������Ʈ �Ѵ�. 
   *   
   */  
	if (frame.subtype == BEACON) {
		strcpy(ap.ssid, frame.ssid);
		memcpy(ap.mac,  frame.address3, 6);

		ap.channel = frame.channel;
		ap.frequency = frame.frequency;

		addSSID(ap);
		return;
	}

//	printf("[!] pCapture...\n");
	if ( ISFFFF(frame.address1) || ISFFFF(frame.address2) || 
		   IS0000(frame.address1) || IS0000(frame.address2) ) return; 

	if ((frame.subtype == AUTH     ) || (frame.subtype == ASSOC_RES) ||
	    (frame.subtype == ASSOC_REQ) || (frame.subtype == RE_ASSO  ) ||
	    (frame.subtype == ACTION   ) || (frame.subtype == DATA     ) ||
	    (frame.subtype == QOSDATA  ) || (frame.subtype == NULLDATA ) ) {

		if (!ini.run) {
			printf("[!] ini.run = %d\n", ini.run);
			return;
		}


		// �ǽð����� ��Ŷ�� �����Ѵ�.
 	  // DeAuther�� ���⼭ ������ �ܸ��� ���� ������ �̿��Ͽ�,
 	  // �㰡�� �ܸ����� �㰡�� AP���� ���������� �˻��� ��, Block�ʿ��� ���,
		// Block��Ű���� �Ѵ�.
// 		pthread_mutex_lock(func->lock);
//      printf("[!] %s(%d)  channel=%d frequency=%d\n", __FUNCTION__, __LINE__, frame.channel, frame.frequency);
		rt = addTranData(frame);
//  	pthread_mutex_unlock(func->lock);
		if (rt < 0) {
			printf("[x] TranData Queue Full!!!  %s(%d)\n", __FUNCTION__, __LINE__);
		}
	}

//#endif
	sleep(0);

	return;
}


/*============================================================
 * �Լ��� : ScanThread
 * �μ�   :
 * ���   :
 * ��ȯ   :
 * 
 *----------------------------------------------------------*/
void *ScanThread(void *arg)
{
  char buf[MAX_STRING_LENGTH]; 

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pd;
  struct bpf_program fcode;
  char  *t;
	int rt;

  tfunc_t *func = (tfunc_t *) arg;

  printf("[!] Scan Thread(ID:%d) Start \n", func->id);

  printf("[!] Device : %s\n", ini.dev);
  printf("[!] Filter Rule: %s\n", ini.filter);


#ifdef DEBUG_CAPTURE
	printf("\n");
	
	printf("       subtype    frDS toDS         DA                 SA             BSSID       LEN         SSID         CH   FREQ\n");
	printf("   -------------- ---- ---- ----------------- ----------------- ----------------- --- -------------------- --- ----------\n");
#endif

  /*--------------------------------------------------------
   * ���� ����� ��, ������ �������̽��� Monitor���� �����Ѵ�. 
   * ����� ���� �����ϴ� ��ɾ��  
   *   
   * $ sudo iwconfig wlan0 mode monitor
   *   
   * �� ����� ���Ե� �ܺ� ���� �����ϵ��� �ߴ�. 
   * Simple is best!!!!
   * ����, �� ���� �����ϸ� �ٸ� �ۿ��� �ǰԵ� �� �� �ֱ⿡, 
   * ���������δ� ������ �� �� �ִ�. 
   *   
   * �̹� monitor���� �����ߴ���, �ݺ������� ����ȴ�. 
   * Ư���� ������ ���� ����. 
   */  
   
  printf("[!] Change to Monitor mode... (%s)\n", ini.dev);
	if (strlen(ini.sh_monitor_mode) + strlen(ini.dev) + strlen(ini.logname)+4 >sizeof(buf)) {
		printf("[X] �ʹ� �� �̸��� �Է��Ͽ����ϴ�. (DEV, LOGNAME, SH_MONITOR_MODE)\n");
		return ((void*) 0);
	}
	changeMode(0);


  pd = pcap_open_live(ini.dev, BUFSIZ, 1, PCAP_TIMEOUT, errbuf);
//  pd = pcap_open_live(ini.dev, PCAP_SNAPSHOT, 1, PCAP_TIMEOUT, errbuf);

  if ( pd == NULL) {
    perror(errbuf);
    return ((void*)0);
  }

  if (pcap_compile(pd, &fcode, ini.filter, 0, PCAP_NETMASK_UNKNOWN) < 0) {
    perror(pcap_geterr(pd));
    return ((void*)0);
  }

  if (pcap_setfilter(pd, &fcode) < 0) {
    perror(pcap_geterr(pd));
    return ((void*)0);
  }

  if (pcap_loop(pd, -1, (pcap_handler)pCapture, (char *)func) < 0) {
    perror(pcap_geterr(pd));
    return ((void*)0);
  }

  pcap_close(pd);
  
  printf("[!] Scan Thread(ID:%d) Termination \n", func->id);
  return ((void*)0);
}


