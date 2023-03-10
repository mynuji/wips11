/*==============================================================*/
/* 화  일  명  : ScanThread.c                                   */
/* 제      목  :                                                */
/*--------------------------------------------------------------*/
/* 라이브러리  :                                                */
/* 작  성  자  : 강영익                                         */
/* 헤더  화일  : ScanThread.h                                   */
/* 작  성  일  : 03. 4. 14 ( 최종수정일 :   .  .   )            */
/*--------------------------------------------------------------*/
/* 기      능  :                                                */
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
 * Queue Full 을 front, rear 일치 여부로 검사하지 않고,
 * 데이터가 있는지 여부(enable)로 확인하였다.
 *
 * full로 데이터 저장 못할 경우, -1을 반환
 * 저장했을 때는 0을 반환함.
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
	

	/* 동일한 정보가 있으면 저장하지 않는다.
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
	 * 큐에 추가
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
     * 채널 정보를 얻어온다.
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
   * 인증 프레임
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
     * BSSID         : 6  (bssid; AP의 MAC)
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
   * 결합 요청 프레임
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
   * 결합 응답 프레임
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
   * 재결합요청/응답
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
     * BSSID         : 6  (bssid; AP의 MAC)
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
		 * 채널 정보를 얻어온다.
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
	 * 인증 프레임
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
		 * BSSID         : 6  (bssid; AP의 MAC)
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
	 * 결합 요청 프레임
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
	 * 결합 응답 프레임
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
	 * 재결합요청/응답
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
		 * BSSID         : 6  (bssid; AP의 MAC)
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
	 * 관리 프레임이 아니라면 SKIP
	 * DATA 프레임도 수신받는 것으로 변경
	 */
//	if (frame.type != T_MGMT) return;



  /*--------------------------------------------
   * 무선랜으로 수신되는 패킷에서 AP의 SSID값을 조회한다. 
   * 조회된 SSID, MAC, 무선채널#을 저장한다. 
   * 이미 조회된 SSID라면 추가하지 않는다. 다만, 채널정보만 업데이트 한다. 
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


		// 실시간으로 패킷을 저장한다.
 	  // DeAuther가 여기서 수집된 단말의 접속 정보를 이용하여,
 	  // 허가된 단말에서 허가된 AP로의 접속인지를 검사한 후, Block필요한 경우,
		// Block시키도록 한다.
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
 * 함수명 : ScanThread
 * 인수   :
 * 기능   :
 * 반환   :
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
   * 최초 실행될 때, 무선랜 인터페이스를 Monitor모드로 변경한다. 
   * 모니터 모드로 변경하는 명령어는  
   *   
   * $ sudo iwconfig wlan0 mode monitor
   *   
   * 위 명령이 포함된 외부 쉘을 실행하도록 했다. 
   * Simple is best!!!!
   * 물론, 이 쉘을 변경하면 다른 작용이 되게도 할 수 있기에, 
   * 보안적으로는 문제가 될 수 있다. 
   *   
   * 이미 monitor모드로 변경했더라도, 반복적으로 수행된다. 
   * 특별히 문제될 것이 없다. 
   */  
   
  printf("[!] Change to Monitor mode... (%s)\n", ini.dev);
	if (strlen(ini.sh_monitor_mode) + strlen(ini.dev) + strlen(ini.logname)+4 >sizeof(buf)) {
		printf("[X] 너무 긴 이름을 입력하였습니다. (DEV, LOGNAME, SH_MONITOR_MODE)\n");
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


