/**
 * Bateria de Testes Automatizados para os Algoritmos Criptográficos
 * Disciplina: Segurança de Sistemas - JCRSEGS
 * Prof. Tardelli Stekel
 */

const OTPModule = require('../js/crypto/otp.js');
const CaesarModule = require('../js/crypto/caesar.js');
const VigenereModule = require('../js/crypto/vigenere.js');
const HillModule = require('../js/crypto/hill.js');
const CryptanalysisModule = require('../js/crypto/cryptanalysis.js');

let totalTests = 0;
let passedTests = 0;

function assert(condition, message) {
    totalTests++;
    if (condition) {
        passedTests++;
        console.log(`  [PASS] ${message}`);
    } else {
        console.error(`  [FAIL] ${message}`);
    }
}

console.log('====================================================');
console.log('INICIANDO TESTES DO SISTEMA DE CRIPTOGRAFIA JCRSEGS');
console.log('====================================================\n');

// 1. TESTES ONE TIME PAD (OTP)
console.log('[1] Testando One Time Pad (OTP)...');
try {
    // a) Conversão decimal para binário
    const binConv = OTPModule.decimalToBinary(42, 8);
    assert(binConv.binaryString === '00101010', `Decimal 42 -> Binário ${binConv.binaryString}`);
    assert(OTPModule.binaryToDecimal('00101010') === 42, 'Binário 00101010 -> Decimal 42');

    // b) Cifra e decriptação com números decimais: 42 XOR 77
    // 42  = 00101010
    // 77  = 01001101
    // XOR = 01100111 = 103
    const otpEnc = OTPModule.encrypt(42, 77);
    assert(otpEnc.cipherDecimals[0] === 103, `Criptografia OTP: 42 ⊕ 77 = ${otpEnc.cipherDecimals[0]} (esperado 103)`);

    const otpDec = OTPModule.decrypt(103, 77);
    assert(otpDec.plainDecimals[0] === 42, `Decriptação OTP: 103 ⊕ 77 = ${otpDec.plainDecimals[0]} (esperado 42)`);

    // c) Vetor de decimais
    const msgVec = [79, 76, 65]; // "OLA"
    const keyVec = [10, 20, 30];
    const encVec = OTPModule.encrypt(msgVec, keyVec);
    const decVec = OTPModule.decrypt(encVec.cipherDecimals, keyVec);
    assert(JSON.stringify(decVec.plainDecimals) === JSON.stringify(msgVec), 'Vetor OTP Criptografado e Decriptografado com Sucesso');
} catch (e) {
    console.error('Erro no OTP:', e);
}

// 2. TESTES CIFRA DE CÉSAR
console.log('\n[2] Testando Cifra de César...');
try {
    // a) Deslocamento simples K = 3
    const caesarEnc1 = CaesarModule.encrypt('ATACAR AO AMANHECER', 3);
    assert(caesarEnc1.ciphertext === 'DWDFDU DR DPDQKHFHU', `César K=3: 'ATACAR AO AMANHECER' -> '${caesarEnc1.ciphertext}'`);
    const caesarDec1 = CaesarModule.decrypt(caesarEnc1.ciphertext, 3);
    assert(caesarDec1.plaintext === 'ATACAR AO AMANHECER', `Decriptação César K=3: '${caesarDec1.plaintext}'`);

    // b) K grande e K negativo
    const caesarEncLarge = CaesarModule.encrypt('Seguranca', 29); // 29 mod 26 = 3
    const caesarDecLarge = CaesarModule.decrypt(caesarEncLarge.ciphertext, 29);
    assert(caesarDecLarge.plaintext === 'Seguranca', 'César com K > 26 funciona perfeitamente');

    const caesarEncNeg = CaesarModule.encrypt('Zebra', -1);
    assert(caesarEncNeg.ciphertext === 'Ydaqz', `César com K=-1: 'Zebra' -> '${caesarEncNeg.ciphertext}'`);
    const caesarDecNeg = CaesarModule.decrypt(caesarEncNeg.ciphertext, -1);
    assert(caesarDecNeg.plaintext === 'Zebra', 'Decriptação César K=-1 funciona perfeitamente');
} catch (e) {
    console.error('Erro em César:', e);
}

// 3. TESTES CIFRA DE VIGENÈRE
console.log('\n[3] Testando Cifra de Vigenère...');
try {
    // a) Validação de no mínimo 4 palavras
    let errorThrown = false;
    try {
        VigenereModule.encrypt('Apenas tres palavras', 'CHAVE');
    } catch (err) {
        errorThrown = true;
    }
    assert(errorThrown, 'Validação de mínimo de 4 palavras rejeita frases com 3 palavras');

    // b) Frase válida (>= 4 palavras) e repetição de chave
    const phrase = 'ESTE E UM TESTE CRIPTOGRAFICO';
    const vigKey = 'CHAVE';
    const vigEnc = VigenereModule.encrypt(phrase, vigKey);
    assert(vigEnc.ciphertext.length === phrase.length, 'Comprimento do texto cifrado preservado');
    const vigDec = VigenereModule.decrypt(vigEnc.ciphertext, vigKey);
    assert(vigDec.plaintext === phrase, `Vigenère Decriptação idêntica ao original: '${vigDec.plaintext}'`);
} catch (e) {
    console.error('Erro em Vigenère:', e);
}

// 4. TESTES CIFRA DE HILL
console.log('\n[4] Testando Cifra de Hill (Álgebra Linear mod 26)...');
try {
    // a) Inverso modular mod 26
    const inv3 = HillModule.modInverse(3, 26);
    assert(inv3 === 9, `Inverso de 3 mod 26 é 9 (pois 3*9=27=1 mod 26)`);

    // b) Matriz 2x2 conhecida: [[3, 3], [2, 5]]
    // det = 3*5 - 3*2 = 15 - 6 = 9. gcd(9, 26) = 1.
    // inv(9) mod 26 = 3 (pois 9*3=27=1 mod 26)
    // adj = [[5, -3], [-2, 3]] mod 26 = [[5, 23], [24, 3]]
    // invMatrix = 3 * [[5, 23], [24, 3]] = [[15, 69], [72, 9]] mod 26 = [[15, 17], [20, 9]]
    const hillMatrix = [[3, 3], [2, 5]];
    const hillInv = HillModule.getInverseMatrix(hillMatrix);
    assert(hillInv.detMod === 9, `Determinante de [[3,3],[2,5]] mod 26 = ${hillInv.detMod} (esperado 9)`);
    assert(hillInv.invDet === 3, `Inverso do Determinante = ${hillInv.invDet} (esperado 3)`);
    assert(hillInv.invMatrix[0][0] === 15 && hillInv.invMatrix[0][1] === 17, `Linha 0 da matriz inversa: [${hillInv.invMatrix[0]}] (esperado [15, 17])`);

    // c) Criptografia e decriptação de "HELP" com [[3, 3], [2, 5]]
    const hillEnc = HillModule.encrypt('HELP', hillMatrix, 2);
    const hillDec = HillModule.decrypt(hillEnc.ciphertext, hillMatrix, 2);
    assert(hillDec.plaintext === 'HELP', `Hill Cripto e Decripto 'HELP' -> '${hillEnc.ciphertext}' -> '${hillDec.plaintext}'`);

    // d) Criptografia com palavra-chave "HILL" e padding de número ímpar de letras
    // "HILL" = [[7, 8], [11, 11]]. det = 7*11 - 8*11 = 77 - 88 = -11 = 15 mod 26. gcd(15, 26) = 1.
    const hillEncHill = HillModule.encrypt('SOL', 'HILL', 2, 'X'); // 'SOLX'
    const hillDecHill = HillModule.decrypt(hillEncHill.ciphertext, 'HILL', 2);
    assert(hillDecHill.plaintext === 'SOLX', `Hill com padding: 'SOL' + 'X' -> '${hillEncHill.ciphertext}' -> '${hillDecHill.plaintext}'`);

    // e) Matriz não-invertível (deve disparar erro claro)
    let nonInvertibleCaught = false;
    try {
        HillModule.encrypt('TESTE', [[2, 4], [4, 8]], 2); // det = 16 - 16 = 0
    } catch (e) {
        nonInvertibleCaught = true;
    }
    assert(nonInvertibleCaught, 'Matriz com det=0 rejeitada com erro explicativo');
} catch (e) {
    console.error('Erro em Hill:', e);
}

// 5. TESTES CRIPTOANÁLISE (MÓDULO LIVRE)
console.log('\n[5] Testando Criptoanálise...');
try {
    // a) Força Bruta César + Frequência em Português
    // Texto em português com chave 7:
    const originalPT = 'ESTA E UMA MENSAGEM SECRETA EM PORTUGUES PARA TESTAR A FREQUENCIA';
    const encryptedPT = CaesarModule.encrypt(originalPT, 7).ciphertext;
    const bruteResult = CryptanalysisModule.bruteForceCaesar(encryptedPT);

    assert(bruteResult.candidates.length === 25, 'Força bruta gerou todas as 25 possibilidades');
    assert(bruteResult.bestCandidate.shift === 7, `Melhor candidato identificado automaticamente pelo ranking PT-BR: K = ${bruteResult.bestCandidate.shift} (esperado 7)`);
    assert(bruteResult.bestCandidate.decryptedText === originalPT, 'Texto decifrado automaticamente é idêntico ao original');

    // b) Two-Time Pad (Reutilização de chave OTP)
    // C1 = 42 ^ 77 = 103
    // C2 = 99 ^ 77 = 46
    // C1 ^ C2 = 103 ^ 46 = 77 cancelado! 42 ^ 99 = 73
    const twoTimeResult = CryptanalysisModule.demonstrateTwoTimePad([103], [46]);
    assert(twoTimeResult.xorDecimals[0] === (42 ^ 99), `Two-Time Pad elimina chave: C1 ⊕ C2 = ${twoTimeResult.xorDecimals[0]} (esperado M1 ⊕ M2 = ${42 ^ 99})`);
} catch (e) {
    console.error('Erro em Criptoanálise:', e);
}

console.log('\n====================================================');
console.log(`TOTAL DE TESTES: ${totalTests} | PASSARAM: ${passedTests} | FALHAS: ${totalTests - passedTests}`);
console.log('====================================================');

if (passedTests === totalTests) {
    process.exit(0);
} else {
    process.exit(1);
}
