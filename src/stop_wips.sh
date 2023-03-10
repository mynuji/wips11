#!/bin/sh

kill -9 `ps -ef | grep 'wips' | awk '{print $2}'`

