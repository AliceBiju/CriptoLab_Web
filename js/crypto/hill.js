/**
 * Módulo de Criptografia: Cifra de Hill
 * Disciplina: Segurança de Sistemas - JCRSEGS
 * Prof. Tardelli Stekel
 * 
 * Critérios atendidos:
 * a) Mensagem e chave como palavra ou matriz numérica.
 * b) Algoritmo de decriptação via matriz inversa modular (mod 26).
 * c) Implementação pura da álgebra linear modular (determinante, MDC, inverso multiplicativo modular e matriz adjunta).
 */

(function (root, factory) {
    if (typeof define === 'function' && define.amd) {
        define([], factory);
    } else if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.HillModule = factory();
    }
}(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    /**
     * Módulo positivo (trata números negativos corretamente para o anel Z_26).
     */
    function mod(n, m = 26) {
        return ((n % m) + m) % m;
    }

    /**
     * Algoritmo Euclidiano Estendido para calcular MDC e coeficientes de Bézout.
     * ax + by = gcd(a, b)
     */
    function extendedGCD(a, b) {
        let x0 = 1, y0 = 0;
        let x1 = 0, y1 = 1;
        let r0 = a, r1 = b;

        while (r1 !== 0) {
            const q = Math.floor(r0 / r1);
            let tempR = r0 - q * r1;
            r0 = r1;
            r1 = tempR;

            let tempX = x0 - q * x1;
            x0 = x1;
            x1 = tempX;

            let tempY = y0 - q * y1;
            y0 = y1;
            y1 = tempY;
        }

        return { gcd: r0, x: x0, y: y0 };
    }

    /**
     * Calcula o inverso multiplicativo modular de `a` modulo `m`.
     * Retorna null se gcd(a, m) !== 1.
     */
    function modInverse(a, m = 26) {
        const normA = mod(a, m);
        const { gcd, x } = extendedGCD(normA, m);
        if (gcd !== 1) {
            return null; // Não possui inverso modular
        }
        return mod(x, m);
    }

    /**
     * Calcula o determinante de uma matriz 2x2 ou 3x3.
     */
    function determinant(matrix) {
        const n = matrix.length;
        if (n === 2) {
            return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0];
        } else if (n === 3) {
            const a = matrix[0][0], b = matrix[0][1], c = matrix[0][2];
            const d = matrix[1][0], e = matrix[1][1], f = matrix[1][2];
            const g = matrix[2][0], h = matrix[2][1], i = matrix[2][2];

            return a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g);
        }
        throw new Error(`Determinante não implementado para dimensão ${n}x${n}`);
    }

    /**
     * Calcula a matriz adjunta e a inversa modular mod 26 de uma matriz 2x2 ou 3x3.
     */
    function getInverseMatrix(matrix) {
        const n = matrix.length;
        const detRaw = determinant(matrix);
        const detMod = mod(detRaw, 26);
        const invDet = modInverse(detMod, 26);

        if (invDet === null) {
            const gcdVal = extendedGCD(detMod, 26).gcd;
            throw new Error(`A matriz NÃO é invertível módulo 26. Determinante = ${detRaw} (mod 26 = ${detMod}), mdc(${detMod}, 26) = ${gcdVal} ≠ 1. Escolha outra chave.`);
        }

        const invMatrix = [];

        if (n === 2) {
            const a = matrix[0][0], b = matrix[0][1];
            const c = matrix[1][0], d = matrix[1][1];

            // Matriz adjunta para 2x2: [[d, -b], [-c, a]]
            const adj = [
                [mod(d, 26), mod(-b, 26)],
                [mod(-c, 26), mod(a, 26)]
            ];

            for (let r = 0; r < 2; r++) {
                invMatrix[r] = [];
                for (let col = 0; col < 2; col++) {
                    invMatrix[r][col] = mod(invDet * adj[r][col], 26);
                }
            }

            return {
                detRaw,
                detMod,
                invDet,
                adjugate: adj,
                invMatrix
            };
        } else if (n === 3) {
            const adj = [];
            for (let i = 0; i < 3; i++) {
                adj[i] = [];
                for (let j = 0; j < 3; j++) {
                    // Menor complementar transposto (adjunta é a transposta dos cofatores)
                    const sub = [];
                    for (let r = 0; r < 3; r++) {
                        if (r === j) continue; // Note j e r trocados para transposição
                        const row = [];
                        for (let c = 0; c < 3; c++) {
                            if (c === i) continue;
                            row.push(matrix[r][c]);
                        }
                        sub.push(row);
                    }
                    const subDet = sub[0][0] * sub[1][1] - sub[0][1] * sub[1][0];
                    const sign = ((i + j) % 2 === 0) ? 1 : -1;
                    adj[i][j] = mod(sign * subDet, 26);
                }
            }

            for (let r = 0; r < 3; r++) {
                invMatrix[r] = [];
                for (let c = 0; c < 3; c++) {
                    invMatrix[r][c] = mod(invDet * adj[r][c], 26);
                }
            }

            return {
                detRaw,
                detMod,
                invDet,
                adjugate: adj,
                invMatrix
            };
        }

        throw new Error(`Dimensão ${n}x${n} não suportada.`);
    }

    /**
     * Converte uma palavra-chave em matriz nxn.
     * Ex: "HILL" -> 2x2: [[7, 8], [11, 11]]
     */
    function keyStringToMatrix(keyString, size = 2) {
        const clean = keyString.toUpperCase().replace(/[^A-Z]/g, '');
        const requiredLen = size * size;
        if (clean.length < requiredLen) {
            throw new Error(`A palavra-chave para Hill ${size}x${size} precisa de no mínimo ${requiredLen} letras (fornecido: ${clean.length}).`);
        }

        const matrix = [];
        let idx = 0;
        for (let r = 0; r < size; r++) {
            matrix[r] = [];
            for (let c = 0; c < size; c++) {
                matrix[r][c] = clean.charCodeAt(idx) - 65;
                idx++;
            }
        }
        return matrix;
    }

    /**
     * Normaliza e valida a matriz da chave.
     */
    function normalizeMatrix(keyInput, size = 2) {
        if (typeof keyInput === 'string') {
            return keyStringToMatrix(keyInput, size);
        }
        if (Array.isArray(keyInput)) {
            if (keyInput.length !== size) {
                throw new Error(`A matriz deve ter exatamente ${size} linhas.`);
            }
            return keyInput.map(row => {
                if (!Array.isArray(row) || row.length !== size) {
                    throw new Error(`Cada linha da matriz deve ter exatamente ${size} colunas.`);
                }
                return row.map(v => mod(Number(v), 26));
            });
        }
        throw new Error('Chave inválida. Forneça uma palavra ou matriz de números.');
    }

    /**
     * Multiplica matriz nxn por vetor n (C = K * P mod 26).
     */
    function multiplyMatrixVector(matrix, vector) {
        const n = matrix.length;
        const result = [];
        const breakdown = [];

        for (let r = 0; r < n; r++) {
            let sum = 0;
            const terms = [];
            for (let c = 0; c < n; c++) {
                const prod = matrix[r][c] * vector[c];
                sum += prod;
                terms.push(`(${matrix[r][c]} × ${vector[c]})`);
            }
            const resMod = mod(sum, 26);
            result.push(resMod);
            breakdown.push({
                row: r,
                terms: terms.join(' + '),
                sumRaw: sum,
                resMod: resMod,
                char: String.fromCharCode(resMod + 65)
            });
        }

        return { resultVector: result, breakdown: breakdown };
    }

    /**
     * Criptografa mensagem usando Cifra de Hill.
     * @param {string} message - Texto em claro
     * @param {string|number[][]} key - Palavra-chave ou matriz numérica
     * @param {number} size - 2 ou 3
     * @param {string} padChar - Caractere para padding ('X')
     */
    function encrypt(message, key, size = 2, padChar = 'X') {
        const cleanMsg = message.toUpperCase().replace(/[^A-Z]/g, '');
        if (cleanMsg.length === 0) {
            throw new Error('A mensagem deve conter pelo menos uma letra alfabética (A-Z).');
        }

        const K = normalizeMatrix(key, size);
        const invData = getInverseMatrix(K); // Garante que é invertível

        // Padding para ser múltiplo de size
        let paddedMsg = cleanMsg;
        let paddedCount = 0;
        while (paddedMsg.length % size !== 0) {
            paddedMsg += padChar.toUpperCase();
            paddedCount++;
        }

        let ciphertext = '';
        const blockSteps = [];

        for (let i = 0; i < paddedMsg.length; i += size) {
            const blockChars = paddedMsg.slice(i, i + size);
            const plainVec = Array.from(blockChars).map(ch => ch.charCodeAt(0) - 65);

            const mult = multiplyMatrixVector(K, plainVec);
            const cipherChars = mult.resultVector.map(v => String.fromCharCode(v + 65)).join('');
            ciphertext += cipherChars;

            blockSteps.push({
                blockIndex: i / size,
                plainLetters: blockChars,
                plainVector: plainVec,
                cipherLetters: cipherChars,
                cipherVector: mult.resultVector,
                breakdown: mult.breakdown
            });
        }

        return {
            ciphertext: ciphertext,
            paddedPlaintext: paddedMsg,
            paddedCount: paddedCount,
            matrixSize: size,
            keyMatrix: K,
            inverseData: invData,
            blockSteps: blockSteps
        };
    }

    /**
     * Decriptografa mensagem usando a Cifra de Hill.
     * P = K^(-1) * C mod 26
     * @param {string} ciphertext - Texto cifrado
     * @param {string|number[][]} key - Chave (mesma usada na cifra)
     * @param {number} size - 2 ou 3
     */
    function decrypt(ciphertext, key, size = 2) {
        const cleanCipher = ciphertext.toUpperCase().replace(/[^A-Z]/g, '');
        if (cleanCipher.length === 0) {
            throw new Error('O texto cifrado deve conter pelo menos uma letra alfabética (A-Z).');
        }
        if (cleanCipher.length % size !== 0) {
            throw new Error(`O comprimento do texto cifrado (${cleanCipher.length}) deve ser múltiplo de ${size} para a Cifra de Hill.`);
        }

        const K = normalizeMatrix(key, size);
        const invData = getInverseMatrix(K);
        const Kinv = invData.invMatrix;

        let plaintext = '';
        const blockSteps = [];

        for (let i = 0; i < cleanCipher.length; i += size) {
            const blockChars = cleanCipher.slice(i, i + size);
            const cipherVec = Array.from(blockChars).map(ch => ch.charCodeAt(0) - 65);

            const mult = multiplyMatrixVector(Kinv, cipherVec);
            const plainChars = mult.resultVector.map(v => String.fromCharCode(v + 65)).join('');
            plaintext += plainChars;

            blockSteps.push({
                blockIndex: i / size,
                cipherLetters: blockChars,
                cipherVector: cipherVec,
                plainLetters: plainChars,
                plainVector: mult.resultVector,
                breakdown: mult.breakdown
            });
        }

        return {
            plaintext: plaintext,
            matrixSize: size,
            keyMatrix: K,
            inverseData: invData,
            blockSteps: blockSteps
        };
    }

    return {
        mod,
        extendedGCD,
        modInverse,
        determinant,
        getInverseMatrix,
        keyStringToMatrix,
        normalizeMatrix,
        multiplyMatrixVector,
        encrypt,
        decrypt
    };
}));
