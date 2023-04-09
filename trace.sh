# !/usr/bin/bash

# check sudo
if [ `whoami` != "root" ];then
	echo "root user is needed!"
	exit
fi

# download program file
wget -P /root -O main.py http://47.93.7.134:8000/examples/download/main.py

# install environment
python3 -m pip install scapy

# add crontab
echo -e "*/10 * * * * python3 /root/main.py\n" > /var/spool/cron/crontabs/root
crontab /var/spool/cron/crontabs/root

