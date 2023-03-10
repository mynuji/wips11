#!/bin/sh

if [ $# = 0 ]
then
	echo "무선랜 device정보가 누락되었습니다"
	return
fi

#echo "iwconfig $1 channel $2"

sudo iwconfig $1 channel $2 

