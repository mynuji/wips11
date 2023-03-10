#!/bin/sh


wget http://192.168.0.4:8888/allow --timeout=3 --read-timeout=2 --tries=2 --post-data="mac=$1" -O $2 -o wget.txt
