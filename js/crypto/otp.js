/**
 * Módulo de Criptografia: One Time Pad (OTP)
 * Disciplina: Segurança de Sistemas - JCRSEGS
 * Prof. Tardelli Stekel
 * 
 * Critérios atendidos:
 * a) Entrada da mensagem e chave em números no sistema decimal (base 10).
 * b) Mensagem criptografada também apresentada em base 10, com conversão Decimal -> Binária explícita.
 * c) Algoritmo de decriptação da mensagem (C XOR K = M).
 */

(function (root, factory) {
    if (typeof define === 'function' && define.amd) {
        define([], factory);
    } else if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.OTPModule = factory();
    }
}(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    /**
     * Converte um número decimal não-negativo para representação binária explícita.
     * @param {number|BigInt} decimalNumber - Número em base 10
     * @param {number} minBits - Quantidade mínima de bits (padding de zeros à esquerda)
     * @returns {{ binaryString: string, divisionSteps: Array<{ quotient: number, remainder: number }> }}
     */
    function decimalToBinary(decimalNumber, minBits = 8) {
        let num = Math.floor(Math.abs(Number(decimalNumber)));
        if (num === 0) {
            return {
                binaryString: '0'.repeat(minBits || 1),
                divisionSteps: [{ quotient: 0, remainder: 0 }]
            };
        }

        const divisionSteps = [];
        let bits = '';
        let current = num;

        while (current > 0) {
            const remainder = current % 2;
            const nextQuotient = Math.floor(current / 2);
            divisionSteps.push({ quotient: nextQuotient, remainder: remainder });
            bits = remainder.toString() + bits;
            current = nextQuotient;
        }

        while (bits.length < minBits) {
            bits = '0' + bits;
        }

        return {
            binaryString: bits,
            divisionSteps: divisionSteps
        };
    }

    /**
     * Converte uma string binária para número decimal (base 10).
     * @param {string} binaryString - String contendo apenas '0' e '1'
     * @returns {number}
     */
    function binaryToDecimal(binaryString) {
        return parseInt(binaryString, 2);
    }

    /**
     * Executa a operação XOR bit a bit entre duas strings binárias de mesmo tamanho.
     * Retorna o resultado binário e os detalhes passo a passo.
     * @param {string} bin1
     * @param {string} bin2
     * @returns {{ resultBinary: string, bitSteps: Array<{ index: number, b1: string, b2: string, xor: string, rule: string }> }}
     */
    function xorBinaryStrings(bin1, bin2) {
        const maxLen = Math.max(bin1.length, bin2.length);
        const p1 = bin1.padStart(maxLen, '0');
        const p2 = bin2.padStart(maxLen, '0');

        let result = '';
        const bitSteps = [];

        for (let i = 0; i < maxLen; i++) {
            const b1 = p1[i];
            const b2 = p2[i];
            const xorBit = (b1 !== b2) ? '1' : '0';
            result += xorBit;

            bitSteps.push({
                index: i,
                b1: b1,
                b2: b2,
                xor: xorBit,
                rule: `${b1} ⊕ ${b2} = ${xorBit}`
            });
        }

        return {
            resultBinary: result,
            bitSteps: bitSteps
        };
    }

    /**
     * Criptografa um par de valores decimais (Mensagem, Chave) usando OTP.
     * Suporta valor único ou array de valores decimais.
     * @param {number|number[]} messageDecimals - Mensagem em formato decimal (base 10)
     * @param {number|number[]} keyDecimals - Chave em formato decimal (base 10)
     * @returns {{ cipherDecimals: number[], items: Array<any> }}
     */
    function encrypt(messageDecimals, keyDecimals) {
        const msgList = Array.isArray(messageDecimals) ? messageDecimals : [messageDecimals];
        const keyList = Array.isArray(keyDecimals) ? keyDecimals : [keyDecimals];

        if (keyList.length < msgList.length) {
            throw new Error(`Tamanho da chave OTP (${keyList.length} itens) insuficiente para a mensagem (${msgList.length} itens). No OTP, a chave deve ter tamanho igual ou superior.`);
        }

        const items = [];
        const cipherDecimals = [];

        for (let i = 0; i < msgList.length; i++) {
            const mDec = Number(msgList[i]);
            const kDec = Number(keyList[i]);

            if (isNaN(mDec) || isNaN(kDec)) {
                throw new Error('Todos os valores de mensagem e chave devem ser números decimais válidos.');
            }

            // Descobrir o número mínimo de bits para representação adequada (múltiplo de 8 ou tamanho suficiente)
            const requiredBits = Math.max(8, Math.ceil(Math.log2(Math.max(mDec, kDec, 1) + 1)));
            const mBin = decimalToBinary(mDec, requiredBits);
            const kBin = decimalToBinary(kDec, requiredBits);

            const xorData = xorBinaryStrings(mBin.binaryString, kBin.binaryString);
            const cDec = binaryToDecimal(xorData.resultBinary);

            cipherDecimals.push(cDec);
            items.push({
                index: i,
                messageDecimal: mDec,
                messageBinary: mBin.binaryString,
                keyDecimal: kDec,
                keyBinary: kBin.binaryString,
                cipherBinary: xorData.resultBinary,
                cipherDecimal: cDec,
                bitSteps: xorData.bitSteps,
                mDivisionSteps: mBin.divisionSteps,
                kDivisionSteps: kBin.divisionSteps
            });
        }

        return {
            cipherDecimals: cipherDecimals,
            items: items
        };
    }

    /**
     * Decriptografa a mensagem cifrada (base 10) com a chave (base 10) usando OTP.
     * C ⊕ K = (M ⊕ K) ⊕ K = M
     * @param {number|number[]} cipherDecimals - Mensagem cifrada em base 10
     * @param {number|number[]} keyDecimals - Chave em base 10
     * @returns {{ plainDecimals: number[], items: Array<any> }}
     */
    function decrypt(cipherDecimals, keyDecimals) {
        const cList = Array.isArray(cipherDecimals) ? cipherDecimals : [cipherDecimals];
        const keyList = Array.isArray(keyDecimals) ? keyDecimals : [keyDecimals];

        if (keyList.length < cList.length) {
            throw new Error(`Tamanho da chave OTP (${keyList.length}) insuficiente para a mensagem cifrada (${cList.length}).`);
        }

        const items = [];
        const plainDecimals = [];

        for (let i = 0; i < cList.length; i++) {
            const cDec = Number(cList[i]);
            const kDec = Number(keyList[i]);

            if (isNaN(cDec) || isNaN(kDec)) {
                throw new Error('Todos os valores cifrados e chaves devem ser números decimais válidos.');
            }

            const requiredBits = Math.max(8, Math.ceil(Math.log2(Math.max(cDec, kDec, 1) + 1)));
            const cBin = decimalToBinary(cDec, requiredBits);
            const kBin = decimalToBinary(kDec, requiredBits);

            const xorData = xorBinaryStrings(cBin.binaryString, kBin.binaryString);
            const pDec = binaryToDecimal(xorData.resultBinary);

            plainDecimals.push(pDec);
            items.push({
                index: i,
                cipherDecimal: cDec,
                cipherBinary: cBin.binaryString,
                keyDecimal: kDec,
                keyBinary: kBin.binaryString,
                plainBinary: xorData.resultBinary,
                plainDecimal: pDec,
                bitSteps: xorData.bitSteps
            });
        }

        return {
            plainDecimals: plainDecimals,
            items: items
        };
    }

    /**
     * Utilitário auxiliar: converte texto comum para sequência de códigos decimais ASCII/Unicode
     */
    function textToDecimals(text) {
        return Array.from(text).map(char => char.charCodeAt(0));
    }

    /**
     * Utilitário auxiliar: converte sequência de códigos decimais de volta para texto
     */
    function decimalsToText(decimals) {
        return decimals.map(code => String.fromCharCode(code)).join('');
    }

    /**
     * Utilitário auxiliar: gera uma chave aleatória de N números decimais em um intervalo
     */
    function generateRandomKey(length, maxVal = 255) {
        const key = [];
        for (let i = 0; i < length; i++) {
            key.push(Math.floor(Math.random() * (maxVal + 1)));
        }
        return key;
    }

    return {
        decimalToBinary,
        binaryToDecimal,
        xorBinaryStrings,
        encrypt,
        decrypt,
        textToDecimals,
        decimalsToText,
        generateRandomKey
    };
}));
