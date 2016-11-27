'use strict';

const table = require('text-table');

// gather the statistics of n_gram
module.exports.n_gram = (text, length, lines = 5) => {
    const std = [];
    std[2] = ['th', 'he', 'in', 'er', 'an', 're', 'nd', 'on', 'en', 'at', 'ou', 'ed', 'ha', 'to', 'or', 'it', 'is', 'hi', 'es', 'ng'];
    std[3] = ['the', 'and', 'ing', 'her', 'hat', 'his', 'tha', 'ere', 'for', 'ent', 'ion', 'ter', 'was', 'you', 'ith', 'ver', 'all', 'wit', 'thi', 'tio'];
    std[4] = ['that', 'ther', 'with', 'tion', 'here', 'ould', 'ight', 'have', 'hich', 'whic', 'this', 'thin', 'they', 'atio', 'ever', 'from', 'ough', 'were', 'hing', 'ment'];
    const counter = new Map();
    // record all grams with length
    for (let i = 0; i <= text.length - length; i++) {
        const gram = text.slice(i, i + length);
        if (gram.indexOf(' ') === -1 && gram.indexOf('\n') === -1) {
            const count = counter.get(gram);
            if (count) {
                counter.set(gram, count + 1);
            } else {
                counter.set(gram, 1);
            }
        }
    }
    const sorted = map2sorted(counter);
    // output
    const output = [
        ['n_gram', 'Frequency', 'Std_gram']
    ];
    for (let i = 0; i < lines && i < sorted.length; i++) {
        output.push([sorted[i].name, sorted[i].value, std[length] ? std[length][i] : '']);
    }
    console.log('**********' + length + '-grams' + '**********');
    console.log(table(output));
}

// gather the statistics of words
module.exports.word = (text, length, lines = 5) => {
    const std = [];
    std[1] = ['a', 'i'];
    std[2] = ['of', 'to', 'in', 'it', 'is', 'be', 'as', 'at', 'so', 'we', 'he', 'by', 'or', 'on', 'do', 'if', 'me', 'my', 'up', 'an', 'go', 'no', 'us', 'am'];
    std[3] = ['the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'any', 'can', 'had', 'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his', 'how', 'man', 'new', 'now', 'old', 'see', 'two', 'way', 'who', 'boy', 'did', 'its', 'let', 'put', 'say', 'she', 'too', 'use'];
    std[4] = ['that', 'with', 'have', 'this', 'will', 'your', 'from', 'they', 'know', 'want', 'been', 'good', 'much', 'some', 'time'];
    const counter = new Map();
    const words = text.split(/\s/);
    for (const word of words) {
        if (word && word.length === length) {
            if (counter.get(word)) {
                counter.set(word, counter.get(word) + 1);
            } else {
                counter.set(word, 1);
            }
        }
    }
    const sorted = map2sorted(counter);
    // output
    const output = [
        ['Word', 'Frequency', 'StdWord']
    ];
    for (let i = 0; i < lines && i < sorted.length; i++) {
        output.push([sorted[i].name, sorted[i].value, std[length] ? std[length][i] : '']);
    }
    console.log('**********words**********');
    console.log(table(output));
}

// convert a map to a sorted array from most to least
function map2sorted(map) {
    const tempArr = [];
    let total = 0;
    for (const [key, value] of map.entries()) {
        total += value;
    }
    for (const [key, value] of map.entries()) {
        tempArr.push({
            name: key,
            value: Math.round(value / total * 1000) / 10
        });
    }
    const sorted = tempArr.sort((a, b) => {
        return b.value - a.value;
    });
    return sorted;
}

// gather statistics of letters
module.exports.letter = (text, lines = 5) => {
    const standards = [{
        name: 'e',
        value: 12.702
    }, {
        name: 't',
        value: 9.056
    }, {
        name: 'a',
        value: 8.167
    }, {
        name: 'o',
        value: 7.507
    }, {
        name: 'i',
        value: 6.966
    }, {
        name: 'n',
        value: 6.749
    }, {
        name: 's',
        value: 6.327
    }, {
        name: 'h',
        value: 6.094
    }, {
        name: 'r',
        value: 5.987
    }, {
        name: 'd',
        value: 4.253
    }, {
        name: 'l',
        value: 4.025
    }, {
        name: 'c',
        value: 2.782
    }, {
        name: 'u',
        value: 2.758
    }, {
        name: 'm',
        value: 2.406
    }, {
        name: 'w',
        value: 2.360
    }, {
        name: 'f',
        value: 2.228
    }, {
        name: 'g',
        value: 2.015
    }, {
        name: 'y',
        value: 1.974
    }, {
        name: 'p',
        value: 1.929
    }, {
        name: 'b',
        value: 1.492
    }, {
        name: 'v',
        value: 0.978
    }, {
        name: 'k',
        value: 0.772
    }, {
        name: 'j',
        value: 0.153
    }, {
        name: 'x',
        value: 0.150
    }, {
        name: 'q',
        value: 0.095
    }, {
        name: 'z',
        value: 0.074
    }, ];
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

    // do some statistics for letters
    let total = 0;
    for (let c of text) {
        let pos = c.charCodeAt(0) - 97;
        if (0 <= pos && pos <= 25) {
            statistics[pos].value++;
            total++;
        }
    }

    for (let obj of statistics) {
        obj.value = Math.round(obj.value / total * 1000) / 10;
    }

    // sort the relative frequences from most to least
    let sorted = statistics.sort(function(a, b) {
        return b.value - a.value;
    });

    // output
    const output = [
        ['Letter', 'Frequency', 'StdLetter', 'StdFrequency']
    ];
    for (let i = 0; i < lines; i++) {
        output.push([sorted[i].name, sorted[i].value, standards[i].name, standards[i].value]);
    }
    console.log('**********letter**********');
    console.log(table(output));
}
