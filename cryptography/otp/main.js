'use strict';
const table = require('text-table');
const lib = require('../libs/general');

// TODO: change those when needed
// permitted charset during brute force
const BRUTE_FORCE_CHARSET = ' ,.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
// permitted charset when translating from hex to char
const HEX2CHAR_CHARSET = BRUTE_FORCE_CHARSET + '\'\":;';
// the max number of outputed keys
const MAXOUTPUT = 1;
// filter set
const FILTERS = ['never', 'The', 'on', 'mes', 'cipher'];
// check index and its idea value in plaintext
const CHECK_CP_INDEX = 3;
const CHECK_CHAR_INDEX = 40;
const IDEAL_CHAR = 't';
const IDEAL_VALUE = IDEAL_CHAR.charCodeAt(0);
// fixed values in key, normally it will be empty in the start
const FIXED_KEY = [];
FIXED_KEY[0] = [102];
FIXED_KEY[1] = [57];
FIXED_KEY[2] = [110];
FIXED_KEY[5] = [219];
FIXED_KEY[7] = [204];
FIXED_KEY[8] = [152];
FIXED_KEY[10] = [53];
FIXED_KEY[14] = [149];
FIXED_KEY[19] = [120];
FIXED_KEY[21] = [127];
FIXED_KEY[25] = [127];
FIXED_KEY[26] = [107];
FIXED_KEY[30] = [197];
FIXED_KEY[31] = [11];
FIXED_KEY[32] = [105];
FIXED_KEY[33] = [176];
FIXED_KEY[34] = [51];
FIXED_KEY[35] = [154];
FIXED_KEY[36] = [25];
FIXED_KEY[39] = [64];
FIXED_KEY[40] = [26];

// constants
// the final one is the target ciphertext
const cps = ['315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e',
    '234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f',
    '32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb',
    '32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa',
    '3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070',
    '32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4',
    '32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce',
    '315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3',
    '271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027',
    '466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83',
    '32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904' // this is the ciphertext to decrypt
];

// prepare the values
const cps_arr = [];
for (const hex of cps) {
    cps_arr.push(lib.hex2arr(hex));
}
const target_cp = cps_arr[cps_arr.length - 1];

// brute force
function bf() {
    const results = [];

    function bf_imp(index) {
        if (index < target_cp.length) { // the length will constrained to the target
            if (FIXED_KEY[index] !== undefined) { // if fixed, not need to bf
                results[index] = FIXED_KEY[index];
            } else {
                results[index] = [];
                // try 0-255
                for (let key = 0; key < 256; key++) {
                    // try all the cps in this index
                    let allOk = true;
                    for (let i = 0; i < cps_arr.length; i++) {
                        const c = String.fromCharCode(key ^ cps_arr[i][index]);
                        if (BRUTE_FORCE_CHARSET.indexOf(c) === -1) {
                            allOk = false;
                            break;
                        }
                    }
                    if (allOk) {
                        results[index].push(key);
                    }
                }
            }
            bf_imp(index + 1);
            return;
        } else {
            return;
        }
    }
    bf_imp(0);
    return results;
}

// check key value on index
console.log('ciphertext[' + CHECK_CP_INDEX + ']' + '[' + CHECK_CHAR_INDEX + ']' + ' is: ' + cps_arr[CHECK_CP_INDEX][CHECK_CHAR_INDEX]);

// get the result by brute force and fixed the indicated value
const results = bf();
for (let i = 0; i < results.length; i++) {
    if (FIXED_KEY[i] !== undefined) {
        results[i] = FIXED_KEY[i];
    }
}

// get all possible keys from brute force
const keys = lib.listAll(results);

// try every key and output the allowed ones
let outputed = 0;
for (const key of keys) {
    // xor and get the string for target
    const pt = lib.xor2char(key, target_cp, HEX2CHAR_CHARSET);
    // filter
    let allOk = true;
    for (const str of FILTERS) {
        if (pt.indexOf(str) === -1) {
            allOk = false;
            break;
        }
    }
    if (allOk) {
        // output
        outputed++;
        console.log('key[' + CHECK_CHAR_INDEX + ']' + ' is: ' + key[CHECK_CHAR_INDEX]);
        console.log(`to be '${IDEAL_CHAR}', set key[${CHECK_CHAR_INDEX}] to ${(IDEAL_VALUE ^ cps_arr[CHECK_CP_INDEX][CHECK_CHAR_INDEX])}`);
        console.log('plaintext are:');
        // header
        const output_table = [];
        const header = ['n'];
        for (let i = 0; i < target_cp.length; i++) {
            header.push(i);
        }
        output_table.push(header);
        // row
        for (let i = 0; i < cps_arr.length; i++) {
            const row = [i];
            const str = lib.xor2char(key, cps_arr[i]);
            for (const c of str) {
                row.push(c);
            }
            output_table.push(row);
        }
        console.log(table(output_table, {
            hsep: '|'
        }));
        console.log('**********************************************************************');
        if (outputed === MAXOUTPUT) break;
    }
}
