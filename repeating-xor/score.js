'use strict';
const fs = require('fs');
const lib = require('./lib');

const CIPHERTEXT = fs.readFileSync('./ciphertext').toString();
const ORIG = lib.hex2arr(CIPHERTEXT);
const ENGLISH = ' .c_\nabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const KLEN = 11;

// screen each byte of each group
let result = [];
for (let offset = 0; offset < KLEN; offset++) {
    let bests = 0,
        bestk = [0];
    // try the key from 0 ~ 255
    for (let key = 0; key < 256; key++) {
        let score = 0;
        for (let j = offset; j < ORIG.length; j += KLEN) {
            const xored = key ^ ORIG[j];
            if (ENGLISH.indexOf(String.fromCharCode(xored)) !== -1) {
                score++;
            }
        }
        if (score > bests) {
            bests = score;
            bestk = [key];
        } else if (score === bests) {
            bestk.push(key);
        }
    }
    // record the best
    result.push(bestk);
}

// try to decrypt the ciphertext with each key
const keys = lib.listAll(result);
for (const key of keys) {
    console.log('with key: ' + lib.arr2char(key));
    console.log(lib.decrypt(ORIG, key));
}
