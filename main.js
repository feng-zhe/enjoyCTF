'use strict';
const subst = require('./substitution.js');

const map = new Map();

const encrypted = require('fs').readFileSync('./encrypted.txt', 'utf8').toLowerCase();
let text = '';
for (let c of encrypted) {
    if (map.get(c)) {
        text += map.get(c);
    } else {
        text += c;
    }
}

subst.letter(text);
subst.n_gram(text, 2);
subst.word(text, 3);
