'use strict';
const fs = require('fs');
const lib = require('../libs/general');

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
/*
 * cipherArr: the array of integer value of each character in ciphertext
 * key:  the array of value of each character in key
 */
function decrypt(cipherArr, key) {
    let longkey = [];
    while (longkey.length < cipherArr.length) {
        longkey = longkey.concat(key);
    }
    const xored = [];
    for (let i = 0; i < cipherArr.length; i++) {
        xored.push(longkey[i] ^ cipherArr[i]);
    }
    return lib.arr2char(xored);
}

const keys = lib.listAll(result);
for (const key of keys) {
    console.log('with key: ' + lib.arr2char(key));
    console.log(decrypt(ORIG, key));
}
