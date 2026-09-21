/**
 * Módulo de Criptografia: Cifra de César Generalizada
 * Disciplina: Segurança de Sistemas - JCRSEGS
 * Prof. Tardelli Stekel
 * 
 * Critérios atendidos:
 * a) Mensagem como palavra ou frase e chave como um número qualquer K (deslocamento no alfabeto).
 * b) Algoritmo de decriptação da mensagem.
 */

(function (root, factory) {
    if (typeof define === 'function' && define.amd) {
        define([], factory);
    } else if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.CaesarModule = factory();
    }
}(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    /**
     * Normaliza o deslocamento K para o intervalo [0, 25].
     * Trata deslocamentos negativos e maiores que 26.
     * @param {number} k
     * @returns {number}
     */
    function normalizeShift(k) {
        const intK = parseInt(k, 10);
        if (isNaN(intK)) {
            throw new Error('A chave K da Cifra de César deve ser um número inteiro.');
        }
        return ((intK % 26) + 26) % 26;
    }

    /**
     * Criptografa uma mensagem de texto usando a Cifra de César com chave K.
     * C = (P + K) mod 26
     * @param {string} message - Palavra ou frase em texto claro
     * @param {number} k - Chave de deslocamento
     * @returns {{ ciphertext: string, k: number, normalizedK: number, steps: Array<any> }}
     */
    function encrypt(message, k) {
        if (typeof message !== 'string') {
            throw new Error('A mensagem deve ser uma string de texto.');
        }

        const normK = normalizeShift(k);
        const rawK = parseInt(k, 10);
        let ciphertext = '';
        const steps = [];

        for (let i = 0; i < message.length; i++) {
            const char = message[i];
            const code = char.charCodeAt(0);

            let isUpper = code >= 65 && code <= 90;
            let isLower = code >= 97 && code <= 122;

            if (isUpper) {
                const p = code - 65;
                const c = (p + normK) % 26;
                const newChar = String.fromCharCode(c + 65);
                ciphertext += newChar;

                steps.push({
                    index: i,
                    originalChar: char,
                    type: 'letra (maiúscula)',
                    p: p,
                    k: rawK,
                    normK: normK,
                    c: c,
                    cipherChar: newChar,
                    formula: `(${p} + ${normK}) mod 26 = ${c} ('${newChar}')`
                });
            } else if (isLower) {
                const p = code - 97;
                const c = (p + normK) % 26;
                const newChar = String.fromCharCode(c + 97);
                ciphertext += newChar;

                steps.push({
                    index: i,
                    originalChar: char,
                    type: 'letra (minúscula)',
                    p: p,
                    k: rawK,
                    normK: normK,
                    c: c,
                    cipherChar: newChar,
                    formula: `(${p} + ${normK}) mod 26 = ${c} ('${newChar}')`
                });
            } else {
                // Espaços, pontuação, acentuação permanecem intactos
                ciphertext += char;
                steps.push({
                    index: i,
                    originalChar: char,
                    type: 'não-alfabético (mantido)',
                    p: null,
                    k: rawK,
                    normK: normK,
                    c: null,
                    cipherChar: char,
                    formula: `Caractere mantido sem deslocamento`
                });
            }
        }

        return {
            ciphertext: ciphertext,
            k: rawK,
            normalizedK: normK,
            steps: steps
        };
    }

    /**
     * Decriptografa uma mensagem cifrada usando a Cifra de César com chave K.
     * P = (C - K) mod 26
     * @param {string} ciphertext - Mensagem cifrada
     * @param {number} k - Chave de deslocamento
     * @returns {{ plaintext: string, k: number, normalizedK: number, steps: Array<any> }}
     */
    function decrypt(ciphertext, k) {
        if (typeof ciphertext !== 'string') {
            throw new Error('O texto cifrado deve ser uma string de texto.');
        }

        const normK = normalizeShift(k);
        const rawK = parseInt(k, 10);
        let plaintext = '';
        const steps = [];

        for (let i = 0; i < ciphertext.length; i++) {
            const char = ciphertext[i];
            const code = char.charCodeAt(0);

            let isUpper = code >= 65 && code <= 90;
            let isLower = code >= 97 && code <= 122;

            if (isUpper) {
                const c = code - 65;
                const p = ((c - normK) % 26 + 26) % 26;
                const newChar = String.fromCharCode(p + 65);
                plaintext += newChar;

                steps.push({
                    index: i,
                    cipherChar: char,
                    type: 'letra (maiúscula)',
                    c: c,
                    k: rawK,
                    normK: normK,
                    p: p,
                    plainChar: newChar,
                    formula: `(${c} - ${normK} + 26) mod 26 = ${p} ('${newChar}')`
                });
            } else if (isLower) {
                const c = code - 97;
                const p = ((c - normK) % 26 + 26) % 26;
                const newChar = String.fromCharCode(p + 97);
                plaintext += newChar;

                steps.push({
                    index: i,
                    cipherChar: char,
                    type: 'letra (minúscula)',
                    c: c,
                    k: rawK,
                    normK: normK,
                    p: p,
                    plainChar: newChar,
                    formula: `(${c} - ${normK} + 26) mod 26 = ${p} ('${newChar}')`
                });
            } else {
                plaintext += char;
                steps.push({
                    index: i,
                    cipherChar: char,
                    type: 'não-alfabético (mantido)',
                    c: null,
                    k: rawK,
                    normK: normK,
                    p: null,
                    plainChar: char,
                    formula: `Caractere mantido sem deslocamento`
                });
            }
        }

        return {
            plaintext: plaintext,
            k: rawK,
            normalizedK: normK,
            steps: steps
        };
    }

    return {
        normalizeShift,
        encrypt,
        decrypt
    };
}));
