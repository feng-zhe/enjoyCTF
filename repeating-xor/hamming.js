'use strict';
const fs = require('fs');
const table = require('text-table');
const hex2arr = require('./lib').hex2arr;

const ciphertext = fs.readFileSync('./ciphertext').toString();

function arrHamming(arr1, arr2) {
    function hammingWeight(val) {
        let ones = 0;
        for (const c of val.toString(2)) {
            if (c === '1') ones++;
        }
        return ones;
    }
    const length = arr1.length < arr2.length ? arr1.length : arr2.length;
    let hamming = 0;
    for (let i = 0; i < length; i++) {
        hamming += hammingWeight(arr1[i] ^ arr2[i]);
    }
    return hamming;
}

// Get the key length. Try from 1 to 12 bytes
const orig = hex2arr(ciphertext);
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
