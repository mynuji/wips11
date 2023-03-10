

#ifndef _SCAN_THREAD_H

#define _SCAN_THREAD_H

#ifndef _WIPS_H
#include "wips.h"
#endif

enum frame_type_t { T_MGMT, T_CONTROL, T_DATA };
	
enum frame_subtype_t {
	BEACON, AUTH, PROB_REQ, PROB_RES, ASSOC_REQ, ASSOC_RES,RE_ASSO, ACTION, 
	NULLDATA, QOSDATA, DATA
};


typedef struct frame_t {
  unsigned int  it_len;
	
  enum frame_type_t    type;
  enum frame_subtype_t subtype;

  unsigned char toDS;
  unsigned char fromDS;

  unsigned char address1[6];
  unsigned char address2[6];
  unsigned char address3[6];

  unsigned char cur_ap[6];

	unsigned int  seq;
	unsigned int  status;
  unsigned char ssid_len; 
  unsigned char ssid[128];

	unsigned int  frequency;
	unsigned int channel;
} frame_t;



typedef struct radiotap_t {
  unsigned char it_rev;
  unsigned char it_pad;
  unsigned int  it_len;
} radiotap_t;


int getHeaderInfo(frame_t *frame, const unsigned char *p);
void prnTranData();
trandata_t *getTranData();
int addTranData(frame_t frame);

#endif

