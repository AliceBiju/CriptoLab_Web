/**
 * Módulo de Criptografia: Cifra de Vigenère
 * Disciplina: Segurança de Sistemas - JCRSEGS
 * Prof. Tardelli Stekel
 * 
 * Critérios atendidos:
 * a) Mensagem com no mínimo quatro palavras e chave como palavra ou frase.
 * b) Repetição automática da chave caso tenha tamanho inferior à mensagem até atingir o tamanho necessário.
 * c) Algoritmo de decriptação da mensagem.
 */

(function (root, factory) {
    if (typeof define === 'function' && define.amd) {
        define([], factory);
    } else if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.VigenereModule = factory();
    }
}(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    /**
     * Conta a quantidade de palavras em uma frase.
     * Considera palavras delimitadas por espaços em branco.
     * @param {string} text
     * @returns {number}
     */
    function countWords(text) {
        if (!text || typeof text !== 'string') return 0;
        const trimmed = text.trim();
        if (trimmed.length === 0) return 0;
        return trimmed.split(/\s+/).length;
    }

    /**
     * Extrai apenas os caracteres alfabéticos da chave e converte para maiúsculas.
     * @param {string} key
     * @returns {string}
     */
    function cleanKey(key) {
        if (!key || typeof key !== 'string') return '';
        // Normaliza removendo acentos e pegando apenas A-Z
        const normalized = key.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
        return normalized.toUpperCase().replace(/[^A-Z]/g, '');
    }

    /**
     * Valida a mensagem segundo o critério obrigatório: mínimo de quatro palavras.
     * @param {string} message
     */
    function validateMessage(message) {
        const wordCount = countWords(message);
        if (wordCount < 4) {
            throw new Error(`Critério obrigatório não satisfeito: A mensagem deve conter no mínimo 4 palavras. Contagem atual: ${wordCount} palavra(s).`);
        }
        return true;
    }

    /**
     * Criptografa uma mensagem usando a Cifra de Vigenère.
     * Ci = (Pi + Ki) mod 26
     * @param {string} message - Frase com no mínimo 4 palavras
     * @param {string} rawKey - Palavra ou frase como chave
     * @returns {{ ciphertext: string, expandedKey: string, steps: Array<any>, wordCount: number }}
     */
    function encrypt(message, rawKey) {
        validateMessage(message);

        const validKey = cleanKey(rawKey);
        if (validKey.length === 0) {
            throw new Error('A chave deve conter pelo menos uma letra válida (A-Z).');
        }

        let ciphertext = '';
        let expandedKey = '';
        const steps = [];
        let keyIndex = 0;

        for (let i = 0; i < message.length; i++) {
            const char = message[i];
            const code = char.charCodeAt(0);

            const isUpper = code >= 65 && code <= 90;
            const isLower = code >= 97 && code <= 122;

            if (isUpper || isLower) {
                const kChar = validKey[keyIndex % validKey.length];
                expandedKey += kChar;
                const kShift = kChar.charCodeAt(0) - 65;

                const base = isUpper ? 65 : 97;
                const p = code - base;
                const c = (p + kShift) % 26;
                const newChar = String.fromCharCode(c + base);
                ciphertext += newChar;

                steps.push({
                    index: i,
                    plainChar: char,
                    p: p,
                    keyChar: kChar,
                    kShift: kShift,
                    c: c,
                    cipherChar: newChar,
                    formula: `(${p} [${char}] + ${kShift} [${kChar}]) mod 26 = ${c} [${newChar}]`
                });

                keyIndex++;
            } else {
                ciphertext += char;
                expandedKey += char;
                steps.push({
                    index: i,
                    plainChar: char,
                    p: null,
                    keyChar: '-',
                    kShift: null,
                    c: null,
                    cipherChar: char,
                    formula: 'Caractere não-alfabético mantido'
                });
            }
        }

        return {
            ciphertext: ciphertext,
            expandedKey: expandedKey,
            steps: steps,
            wordCount: countWords(message)
        };
    }

    /**
     * Decriptografa uma mensagem cifrada usando a Cifra de Vigenère.
     * Pi = (Ci - Ki + 26) mod 26
     * @param {string} ciphertext - Texto cifrado
     * @param {string} rawKey - Palavra ou frase como chave
     * @returns {{ plaintext: string, expandedKey: string, steps: Array<any> }}
     */
    function decrypt(ciphertext, rawKey) {
        if (typeof ciphertext !== 'string') {
            throw new Error('O texto cifrado deve ser uma string de texto.');
        }

        const validKey = cleanKey(rawKey);
        if (validKey.length === 0) {
            throw new Error('A chave deve conter pelo menos uma letra válida (A-Z).');
        }

        let plaintext = '';
        let expandedKey = '';
        const steps = [];
        let keyIndex = 0;

        for (let i = 0; i < ciphertext.length; i++) {
            const char = ciphertext[i];
            const code = char.charCodeAt(0);

            const isUpper = code >= 65 && code <= 90;
            const isLower = code >= 97 && code <= 122;

            if (isUpper || isLower) {
                const kChar = validKey[keyIndex % validKey.length];
                expandedKey += kChar;
                const kShift = kChar.charCodeAt(0) - 65;

                const base = isUpper ? 65 : 97;
                const c = code - base;
                const p = (c - kShift + 26) % 26;
                const newChar = String.fromCharCode(p + base);
                plaintext += newChar;

                steps.push({
                    index: i,
                    cipherChar: char,
                    c: c,
                    keyChar: kChar,
                    kShift: kShift,
                    p: p,
                    plainChar: newChar,
                    formula: `(${c} [${char}] - ${kShift} [${kChar}] + 26) mod 26 = ${p} [${newChar}]`
                });

                keyIndex++;
            } else {
                plaintext += char;
                expandedKey += char;
                steps.push({
                    index: i,
                    cipherChar: char,
                    c: null,
                    keyChar: '-',
                    kShift: null,
                    p: null,
                    plainChar: char,
                    formula: 'Caractere não-alfabético mantido'
                });
            }
        }

        return {
            plaintext: plaintext,
            expandedKey: expandedKey,
            steps: steps
        };
    }

    return {
        countWords,
        cleanKey,
        validateMessage,
        encrypt,
        decrypt
    };
}));
