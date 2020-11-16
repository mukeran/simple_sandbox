#!/bin/sh
nohup php-fpm > /dev/null 2>&1 &
python3 /proxy.py