#!/usr/bin/env python3
arr = ['principalController',
        '$http',
        '$scope',
        '$cookies',
        'OAuth2',
        'get',
        'UserName',
        'Name',
        'data',
        'remove',
        'href',
        'location',
        'login.html',
        'then',
        '/api/Account/',
        'controller',
        'loginController',
        'credentials',
        '',
        'error',
        'index.html',
        'login',
        'message',
        'Invalid Credentials.',
        'show',
        'log',
        '/api/token',
        'post',
        'json',
        'ngCookies',
        'module'
  ];

with open('app.min.js', 'r') as f:
    content = f.read()

for i, val in enumerate(arr):
    content = content.replace('_0xd18f[{}]'.format(i), "'{}'".format(val))

with open('unuglified.app.min.js', 'w') as f:
    f.write(content)
