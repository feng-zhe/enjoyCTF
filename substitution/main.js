'use strict';
const subst = require('./substitution.js');

const map = new Map();
// the substitution rules
map.set('y','e');
map.set('u','a');
map.set('k','i');

const encrypted = require('fs').readFileSync('./encrypted.txt', 'utf8').toLowerCase();
let text = encrypted;

subst.n_gram(text, 2);
subst.n_gram(text, 3);
subst.n_gram(text, 4);
subst.word(text, 1);
subst.word(text, 2);
subst.word(text, 3);
subst.word(text, 4);

text = '';
for (let c of encrypted) {
    if (map.get(c)) {
        text += map.get(c);
    } else {
        text += c;
    }
}

console.log(text.slice(0, text.indexOf('\n')));
