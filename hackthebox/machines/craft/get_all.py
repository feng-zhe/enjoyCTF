#!/usr/bin/env python

import pymysql

# test connection to mysql database

connection = pymysql.connect(host="db",
                             user="craft",
                             password="qLGockJ6G2J75O",
                             db="craft",
                             cursorclass=pymysql.cursors.DictCursor)

try: 
    with connection.cursor() as cursor:
        sql = "SELECT `username`, `password` FROM `user`"
        cursor.execute(sql)
        result = cursor.fetchall()
        print(result)

finally:
    connection.close()
