#!/bin/sh

if [ $# = 0 ]
then
	echo "무선랜 device정보가 누락되었습니다"
	return
fi


#sudo ifconfig $1 down
sudo iwconfig $1 mode managed
#sudo ifconfig $1 up


