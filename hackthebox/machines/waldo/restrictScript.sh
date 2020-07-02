#!/bin/bash

fullPath=$1
file=$(/usr/bin/basename $1)
magic=$(/usr/bin/xxd -p -l 4 $fullPath)
fileHash=$(/usr/bin/shasum $fullPath | /usr/bin/cut -d " " -f1)
backupHash=$(/usr/bin/shasum ${fullPath}.bak | /usr/bin/cut -d " " -f1)

#if executable is corrupted replace it with know good
if [ $fileHash != $backupHash ]
then
    tmpFile=$(/bin/mktemp)
    /bin/chmod u+x $tmpFile
    /bin/cp $fullPath $tmpFile
    /bin/cp ${fullPath}.bak $fullPath
    file=$tmpFile

    (/bin/sleep .5; /bin/rm -f $tmpFile) &

fi

if [ $magic = "7f454c46" ]
then
    $file $2
else
    read -r shebang < $fullPath
    if [ ${shebang:0:2} = "#!" ]
    then
        case ${shebang:2} in
            */bin/bash*|*/bin/sh*|*/bin/dash*) set -r; source $file ;;
            *) echo "-rbash: $file: bad interpreter: ${shebang:2}: no such file or directory" ;;
        esac
    fi
fi

