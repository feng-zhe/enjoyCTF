'use strict';

function hex2arr(hexstr) {
    const arr = [];
    for (let i = 0; i + 1 < hexstr.length; i += 2) {
        arr.push(parseInt(hexstr[i] + hexstr[i + 1], 16));
    }
    return arr;
}

function arr2char(arr) {
    let result = '';
    for (const val of arr) {
        result += String.fromCharCode(val);
    }
    return result;
}

function listAll(arrOfArr) {
    const current = [];
    const result = [];

    function traverse(index) {
        if (index < arrOfArr.length) {
            const arr = arrOfArr[index];
            for (const val of arr) {
                current.push(val);
                traverse(index + 1);
                current.pop();
            }
        } else { // index===result.length
            result.push(current.slice());
        }
    }
    traverse(0);
    return result;
}

/*
 * ciphertext: the array of integer value of each character in ciphertext
 * key:  the array of value of each character in key
 */
function decrypt(ciphertext, key) {
    let longkey = [];
    while (longkey.length < ciphertext.length) {
        longkey = longkey.concat(key);
    }
    const xored = [];
    for (let i = 0; i < ciphertext.length; i++) {
        xored.push(longkey[i] ^ ciphertext[i]);
    }
    return arr2char(xored);
}

module.exports.hex2arr = hex2arr;
module.exports.arr2char = arr2char;
module.exports.listAll = listAll;
module.exports.decrypt = decrypt;
