'use strict';

const fs = require('fs');

const encrypted = fs.readFileSync('./encrypted.txt', 'utf8');
//const alphabet = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'];
const mapping = ['g', 'c', 'q', 'z', 'k', 'f', 'v', 'a', 'p', 'i', 'd', 'u', 'w', 't', 'h', 'j', 'x', 'y', 'n', 'm', 's', 'o', 'b', 'r', 'e', 'l'];
const statistics = [{
    'name': 'a',
    'value': 0
}, {
    'name': 'b',
    'value': 0
}, {
    'name': 'c',
    'value': 0
}, {
    'name': 'd',
    'value': 0
}, {
    'name': 'e',
    'value': 0
}, {
    'name': 'f',
    'value': 0
}, {
    'name': 'g',
    'value': 0
}, {
    'name': 'h',
    'value': 0
}, {
    'name': 'i',
    'value': 0
}, {
    'name': 'j',
    'value': 0
}, {
    'name': 'k',
    'value': 0
}, {
    'name': 'l',
    'value': 0
}, {
    'name': 'm',
    'value': 0
}, {
    'name': 'n',
    'value': 0
}, {
    'name': 'o',
    'value': 0
}, {
    'name': 'p',
    'value': 0
}, {
    'name': 'q',
    'value': 0
}, {
    'name': 'r',
    'value': 0
}, {
    'name': 's',
    'value': 0
}, {
    'name': 't',
    'value': 0
}, {
    'name': 'u',
    'value': 0
}, {
    'name': 'v',
    'value': 0
}, {
    'name': 'w',
    'value': 0
}, {
    'name': 'x',
    'value': 0
}, {
    'name': 'y',
    'value': 0
}, {
    'name': 'z',
    'value': 0
}];

var result = '';
for (let c of encrypted) {
    if (c === ' ' || c === '\n' || c === '\n\r') {
        result += c;
    } else {
        let pos = c.charCodeAt(0) - 97;
        statistics[pos].value++;
        result += mapping[pos];
    }
}
var total = 0;
for (let i of statistics) {
    total += i.value;
}
for (let i = 0; i < 26; i++) {
    statistics[i].value = statistics[i].value / total;
}

console.log(statistics.sort(function(a, b) {
    return a.value - b.value;
}));

console.log(result);
