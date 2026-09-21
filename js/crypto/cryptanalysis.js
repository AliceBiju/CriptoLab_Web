/**
 * Módulo de Criptoanálise e Expansão Criptográfica (Módulo Livre)
 * Disciplina: Segurança de Sistemas - JCRSEGS
 * Prof. Tardelli Stekel
 * 
 * Contempla:
 * 1. Opção A: Ataque de Força Bruta na Cifra de César com 25 possibilidades
 *    + BÔNUS COMPLETO: Análise de Frequência da Língua Portuguesa para sugerir a chave mais provável.
 * 2. Opção B: Demonstração da Vulnerabilidade de Reutilização de Chave no OTP (Two-Time Pad),
 *    provando matematicamente que C1 ⊕ C2 = M1 ⊕ M2 (chave cancelada).
 */

(function (root, factory) {
    if (typeof define === 'function' && define.amd) {
        define([], factory);
    } else if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.CryptanalysisModule = factory();
    }
}(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // Frequências percentuais padrão das letras no idioma Português (pt-BR)
    const PT_FREQUENCIES = {
        'A': 14.63, 'E': 12.57, 'O': 10.73, 'S': 7.81, 'R': 6.53,
        'I': 6.18,  'N': 5.05,  'D': 4.99,  'M': 4.74, 'U': 4.63,
        'T': 4.34,  'C': 3.88,  'L': 2.78,  'P': 2.52, 'V': 1.67,
        'G': 1.30,  'H': 1.28,  'Q': 1.20,  'B': 1.04, 'F': 1.02,
        'Z': 0.47,  'J': 0.40,  'X': 0.21,  'K': 0.02, 'Y': 0.01,
        'W': 0.01
    };

    /**
     * Decifra texto na Cifra de César com deslocamento K fixo.
     */
    function decryptCaesarQuick(ciphertext, k) {
        const normK = ((k % 26) + 26) % 26;
        let result = '';
        for (let i = 0; i < ciphertext.length; i++) {
            const char = ciphertext[i];
            const code = char.charCodeAt(0);

            if (code >= 65 && code <= 90) {
                result += String.fromCharCode(((code - 65 - normK + 26) % 26) + 65);
            } else if (code >= 97 && code <= 122) {
                result += String.fromCharCode(((code - 97 - normK + 26) % 26) + 97);
            } else {
                result += char;
            }
        }
        return result;
    }

    /**
     * Calcula o score de similaridade com a língua portuguesa baseado na estatística Qui-Quadrado (χ²).
     * Quanto menor o χ², mais próximo o texto está da distribuição natural do português.
     * Retorna também uma pontuação normalizada de 0% a 100%.
     */
    function calculatePortugueseFitness(text) {
        const clean = text.toUpperCase().replace(/[^A-Z]/g, '');
        const N = clean.length;
        if (N === 0) return { chiSquare: 9999, scorePercentage: 0, letterCounts: {} };

        const counts = {};
        for (const letter in PT_FREQUENCIES) {
            counts[letter] = 0;
        }

        for (let i = 0; i < N; i++) {
            const ch = clean[i];
            if (counts[ch] !== undefined) {
                counts[ch]++;
            }
        }

        let chiSquare = 0;
        let dotProduct = 0;
        let textMagSq = 0;
        let ptMagSq = 0;

        for (const letter in PT_FREQUENCIES) {
            const expected = (PT_FREQUENCIES[letter] / 100) * N;
            const observed = counts[letter];
            chiSquare += Math.pow(observed - expected, 2) / (expected || 0.0001);

            // Similaridade de Cosseno para dar uma pontuação intuitiva de 0 a 100%
            const obsFreq = (observed / N) * 100;
            const expFreq = PT_FREQUENCIES[letter];
            dotProduct += obsFreq * expFreq;
            textMagSq += obsFreq * obsFreq;
            ptMagSq += expFreq * expFreq;
        }

        const cosineSimilarity = dotProduct / (Math.sqrt(textMagSq) * Math.sqrt(ptMagSq) || 1);
        const scorePercentage = Math.max(0, Math.min(100, Math.round(cosineSimilarity * 100)));

        return {
            totalLetters: N,
            chiSquare: Number(chiSquare.toFixed(2)),
            scorePercentage: scorePercentage,
            letterCounts: counts
        };
    }

    /**
     * Opção A: Executa ataque de força bruta na Cifra de César, gerando todas as 25 possibilidades
     * e ranqueando a mais provável usando análise de frequência em português.
     * @param {string} ciphertext - Texto cifrado sem chave
     * @returns {{ candidates: Array<any>, bestCandidate: any, ptFrequencies: object }}
     */
    function bruteForceCaesar(ciphertext) {
        if (!ciphertext || typeof ciphertext !== 'string' || ciphertext.trim().length === 0) {
            throw new Error('Informe um texto cifrado para executar o ataque de força bruta.');
        }

        const candidates = [];

        for (let k = 1; k <= 25; k++) {
            const candidateText = decryptCaesarQuick(ciphertext, k);
            const fitness = calculatePortugueseFitness(candidateText);

            candidates.push({
                shift: k,
                decryptedText: candidateText,
                chiSquare: fitness.chiSquare,
                confidenceScore: fitness.scorePercentage,
                totalLetters: fitness.totalLetters
            });
        }

        // Ordena pelo menor Chi-Quadrado (mais provável primeiro)
        const sortedByLikelihood = [...candidates].sort((a, b) => a.chiSquare - b.chiSquare);
        const bestCandidate = sortedByLikelihood[0];

        // Marca o mais provável no array original
        candidates.forEach(c => {
            c.isBestMatch = (c.shift === bestCandidate.shift);
        });

        return {
            ciphertext: ciphertext,
            candidates: candidates,
            bestCandidate: bestCandidate,
            ptFrequencies: PT_FREQUENCIES
        };
    }

    /**
     * Opção B: Demonstração da quebra de OTP por reutilização de chave (Two-Time Pad).
     * Dados C1 = M1 ⊕ K e C2 = M2 ⊕ K,
     * calcula C1 ⊕ C2 = (M1 ⊕ K) ⊕ (M2 ⊕ K) = M1 ⊕ M2.
     * @param {number[]|string} cipher1 - Texto ou decimais do texto cifrado 1
     * @param {number[]|string} cipher2 - Texto ou decimais do texto cifrado 2
     */
    function demonstrateTwoTimePad(cipher1, cipher2) {
        let c1Decimals = [];
        let c2Decimals = [];

        if (Array.isArray(cipher1)) {
            c1Decimals = cipher1.map(Number);
        } else if (typeof cipher1 === 'string') {
            // Se for lista de números separados por vírgula ou espaço
            if (/^[\d\s,;]+$/.test(cipher1.trim())) {
                c1Decimals = cipher1.trim().split(/[\s,;]+/).map(Number);
            } else {
                c1Decimals = Array.from(cipher1).map(ch => ch.charCodeAt(0));
            }
        }

        if (Array.isArray(cipher2)) {
            c2Decimals = cipher2.map(Number);
        } else if (typeof cipher2 === 'string') {
            if (/^[\d\s,;]+$/.test(cipher2.trim())) {
                c2Decimals = cipher2.trim().split(/[\s,;]+/).map(Number);
            } else {
                c2Decimals = Array.from(cipher2).map(ch => ch.charCodeAt(0));
            }
        }

        const minLen = Math.min(c1Decimals.length, c2Decimals.length);
        if (minLen === 0) {
            throw new Error('Forneça dois textos cifrados válidos para a análise de Two-Time Pad.');
        }

        const xorDecimals = [];
        const steps = [];

        for (let i = 0; i < minLen; i++) {
            const v1 = c1Decimals[i];
            const v2 = c2Decimals[i];
            const xorVal = v1 ^ v2;

            xorDecimals.push(xorVal);

            const b1 = v1.toString(2).padStart(8, '0');
            const b2 = v2.toString(2).padStart(8, '0');
            const bx = xorVal.toString(2).padStart(8, '0');

            steps.push({
                index: i,
                c1Dec: v1,
                c1Bin: b1,
                c2Dec: v2,
                c2Bin: b2,
                xorDec: xorVal,
                xorBin: bx,
                xorChar: (xorVal >= 32 && xorVal <= 126) ? String.fromCharCode(xorVal) : '·'
            });
        }

        return {
            c1Decimals: c1Decimals.slice(0, minLen),
            c2Decimals: c2Decimals.slice(0, minLen),
            xorDecimals: xorDecimals,
            steps: steps,
            proofExplanation: `
Matematicamente:
C₁ = M₁ ⊕ K
C₂ = M₂ ⊕ K

Ao realizar C₁ ⊕ C₂:
C₁ ⊕ C₂ = (M₁ ⊕ K) ⊕ (M₂ ⊕ K)
        = M₁ ⊕ M₂ ⊕ (K ⊕ K)
Como qualquer valor XOR ele mesmo é zero (K ⊕ K = 0):
        = M₁ ⊕ M₂ ⊕ 0
        = M₁ ⊕ M₂

Conclusão: A chave K foi completamente eliminada!
O adversário obtém diretamente o XOR entre as duas mensagens originais (M₁ ⊕ M₂),
permitindo técnicas como "Crib Dragging" ou análise estatística de n-gramas para recuperar M₁ e M₂ simultaneamente.
`
        };
    }

    return {
        PT_FREQUENCIES,
        calculatePortugueseFitness,
        bruteForceCaesar,
        demonstrateTwoTimePad
    };
}));
