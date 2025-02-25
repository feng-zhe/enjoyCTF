#!/usr/bin/python3

import requests
import re
import hashlib

def fast_hash():
    url = 'http://docker.hackthebox.eu:32520/'
    s = requests.Session()
    r = s.get(url)
    for line in r.text.splitlines():
        m = re.match(".*<h3 align='center'>(.*)</h3>.*", line)
        if m:
            raw_val = m.group(1)
            break
    hash_val = hashlib.md5(raw_val.encode()).hexdigest()

    r = s.post(url, data={'hash':hash_val})
    if 'Too slow!' in r.text:
        return False
    print(r.text)
    return True

def main():
    for i in range(100):
        print("{}th attempt...".format(i))
        if fast_hash():
            break

if __name__ == '__main__':
    main()
