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

/*
 * list all possibility result arr by picking one element from one array
 */
function listAll(arrOfArr) {
    const current = [];
    const result = [];

    function traverse(index) {
        if (index < arrOfArr.length) {
            const arr = arrOfArr[index];
            if (arr.length === 0) {
                // when empty, set to 0
                current.push(0);
                traverse(index + 1);
                current.pop();
            } else {
                for (const val of arr) {
                    current.push(val);
                    traverse(index + 1);
                    current.pop();
                }
            }
        } else { // index===result.length
            result.push(current.slice());
        }
    }
    traverse(0);
    return result;
}

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
    return arr2char(xored);
}

/*
 * xor the two arr of values
 */
function xor(arr1, arr2) {
    const arr = [];
    const len = arr1.length > arr2.length ? arr2.length : arr1.length;
    for (let i = 0; i < len; i++) {
        arr.push(arr1[i] ^ arr2[i]);
    }
    return arr;
}

/*
 * xor then to string
 */
function xor2char(arr1, arr2, CHARSET) {
    const xored = xor(arr1, arr2);
    let str = '';
    for (const val of xored) {
        const c = String.fromCharCode(val);
        if (CHARSET !== undefined) {
            if (CHARSET.indexOf(c) !== -1) str += c;
            else str += '?';
        } else {
            str += c;
        }
    }
    return str;
}

function hammingOfArr(arr) {
    function hammingOfByte(val) {
        let ones = 0;
        for (const c of val.toString(2)) {
            if (c === '1') ones++;
        }
        return ones;
    }
    let hamming = 0;
    for (const val of arr) {
        hamming += hammingOfByte(val);
    }
    return hamming;
}

module.exports.hex2arr = hex2arr;
module.exports.arr2hex = arr2hex;
module.exports.arr2char = arr2char;
module.exports.char2arr = char2arr;
module.exports.listAll = listAll;
module.exports.decrypt = decrypt;
module.exports.xor = xor;
module.exports.xor2char = xor2char;
module.exports.hammingOfArr = hammingOfArr;
