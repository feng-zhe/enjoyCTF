'use strict';
const fs = require('fs');
const table = require('text-table');
const lib = require('../libs/general');

const ciphertext = fs.readFileSync('./ciphertext').toString();

function arrHamming(arr1, arr2) {
    const length = arr1.length < arr2.length ? arr1.length : arr2.length;
    const xored = [];
    for(let i = 0; i< length; i++){
        xored.push(arr1[i] ^ arr2[i]);
    }
    return lib.hammingOfArr(xored);
}

// Get the key length. Try from 1 to 12 bytes
const orig = lib.hex2arr(ciphertext);
const header = [
    ['key length', 'hamming weight']
];
const data = []
for (let klen = 1; klen <= 12; klen++) {
    const shifted = orig.slice(klen).concat(orig.slice(0, klen));
    const hamming = arrHamming(orig, shifted);
    data.push([klen, hamming]);
}

// outpu ascending in key length
console.log(table(header.concat(data)));

// output the best three
console.log('**************************************************');
const sorted = data.sort(function(a, b) {
    return a[1] - b[1];
});
console.log('the best are:');
const len = sorted.length < 3 ? sorted.length : 3;
console.log(table(header.concat(sorted.slice(0, len))));
