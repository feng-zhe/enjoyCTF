'use strict';

function hex2arr(hexstr) {
    const arr = [];
    for (let i = 0; i + 1 < hexstr.length; i += 2) {
        arr.push(parseInt(hexstr[i] + hexstr[i + 1], 16));
    }
    return arr;
}

function arr2hex(arr) {
    let hexstr = '';
    for (const val of arr) {
        hexstr += val.toString(16);
    }
    return hexstr;
}

function char2arr(str) {
    const arr = [];
    for (let i = 0; i < str.length; i++) {
        arr.push(str.charCodeAt(i));
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

function xor(arr1, arr2) {
    const arr = [];
    const len = arr1.length > arr2.length ? arr2.length : arr1.length;
    for (let i = 0; i < len; i++) {
        arr.push(arr1[i] ^ arr2[i]);
    }
    return arr;
}

module.exports.hex2arr = hex2arr;
module.exports.arr2hex = arr2hex;
module.exports.arr2char = arr2char;
module.exports.char2arr = char2arr;
module.exports.listAll = listAll;
module.exports.decrypt = decrypt;
module.exports.xor = xor;
