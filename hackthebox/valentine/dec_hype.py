#!/usr/bin/python3

f = open('hype_key', 'r')

result = ''
for val in f.read().split():
    result += chr(int(val,16))

f.close()

f = open('dec_key', 'w')
f.write(result)
f.close()
