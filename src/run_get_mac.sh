#!/bin/sh

iw dev $1 info | grep addr | awk '{ print $2 }' > $2
