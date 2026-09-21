/**
 * Exemplos Prontos (Presets) para Apresentação em Sala de Aula
 * Disciplina: Segurança de Sistemas - JCRSEGS
 * Prof. Tardelli Stekel
 */

const PRESETS = {
    otp: [
        {
            title: "Exemplo Clássico (Decimal 42 e 77)",
            desc: "Mensagem decimal 42 e Chave decimal 77. Demonstração explícita da conversão para binário de 8 bits e operação XOR.",
            message: "42",
            key: "77"
        },
        {
            title: "Vetor Decimal (Palavra 'OLA' em ASCII)",
            desc: "Códigos decimais de 'O' (79), 'L' (76), 'A' (65) com chaves decimais correspondentes [120, 45, 93].",
            message: "79, 76, 65",
            key: "120, 45, 93"
        },
        {
            title: "Valores Decimais Maiores (16 bits)",
            desc: "Mensagem 12345 e chave 54321, demonstrando que o algoritmo escala perfeitamente para qualquer magnitude decimal.",
            message: "12345",
            key: "54321"
        }
    ],

    caesar: [
        {
            title: "Cifra Clássica do Imperador (K = 3)",
            desc: "Mensagem histórica 'ATACAR AO AMANHECER' com o clássico deslocamento de 3 posições.",
            message: "ATACAR AO AMANHECER",
            k: 3
        },
        {
            title: "Deslocamento Generalizado (K = 17)",
            desc: "Frase em português com pontuação preservada e deslocamento K = 17.",
            message: "Segurança de Sistemas: JCRSEGS e Criptografia!",
            k: 17
        },
        {
            title: "Deslocamento Maior que o Alfabeto (K = 55)",
            desc: "Demonstra o cálculo de K mod 26 (55 mod 26 = 3).",
            message: "Aritmetica Modular no Alfabeto",
            k: 55
        }
    ],

    vigenere: [
        {
            title: "Exemplo Didático (>= 4 palavras)",
            desc: "Frase completa com chave 'SECRETO', demonstrando a repetição periódica da chave até atingir o comprimento da frase.",
            message: "A SEGURANCA DA INFORMACAO E ESSENCIAL",
            key: "SECRETO"
        },
        {
            title: "Chave Frase com Múltiplas Palavras",
            desc: "Mensagem 'CRIPTOGRAFIA E FUNDAMENTAL PARA REDES' com a chave frase 'TEMA AULA'.",
            message: "CRIPTOGRAFIA E FUNDAMENTAL PARA REDES",
            key: "TEMA AULA"
        },
        {
            title: "Caso de Estudo Histórico",
            desc: "Mensagem clássica de Bellaso com chave 'LEMON'.",
            message: "ATAQUE AO FORTE NA MADRUGADA DE AMANHA",
            key: "LEMON"
        }
    ],

    hill: [
        {
            title: "Matriz 2x2 Clássica ([[3, 3], [2, 5]])",
            desc: "Matriz com determinante 9 (inverso modular = 3 mod 26). Mensagem 'HELP' -> 'HIAT'.",
            mode: "matrix",
            size: 2,
            matrix: [[3, 3], [2, 5]],
            message: "HELP"
        },
        {
            title: "Palavra-Chave 'HILL' (2x2 com Padding)",
            desc: "Chave textual 'HILL' = [[7, 8], [11, 11]]. Det = -11 = 15 mod 26 (inverso = 7). Mensagem 'SOL' recebe padding 'X' virando 'SOLX'.",
            mode: "word",
            size: 2,
            keyWord: "HILL",
            message: "SOL"
        },
        {
            title: "Palavra-Chave 'GYBN' (2x2)",
            desc: "Chave muito utilizada na literatura acadêmica: G(6), Y(24), B(1), N(13). Det = 6*13 - 24*1 = 54 = 2 mod 26 (não invertível!) vs 'BACD' = [[1, 0], [2, 3]].",
            mode: "matrix",
            size: 2,
            matrix: [[5, 8], [17, 3]],
            message: "CRIPTOGRAFIA"
        }
    ],

    cryptanalysis: [
        {
            title: "Texto Cifrado em Português (K Desconhecido)",
            desc: "Texto sem a chave: O sistema testa todas as 25 chaves e utiliza a análise de frequência da língua portuguesa para identificar a chave correta com precisão!",
            ciphertext: "LZAH L BTH TLUZHNLT ZLJYLAH LT WVYABNBLZ WHYH ALZAHY H MYLXBLUJPH" // Chave original = 7
        },
        {
            title: "Provérbio Cifrado (K Desconhecido)",
            desc: "Cifra de César de 'QUEM NAO TEM CAO CACA COM GATO' com deslocamento K = 11.",
            ciphertext: "BFPX YLZ EPP NIZ NLNL NZZ RLEZ"
        }
    ],

    twoTimePad: [
        {
            title: "Duas Mensagens Cifradas com a Mesma Chave",
            desc: "C1 = M1 ⊕ K (103) e C2 = M2 ⊕ K (46). Ao calcular C1 ⊕ C2, a chave K é cancelada resultando em 73 (M1 ⊕ M2)!",
            c1: "103",
            c2: "46"
        },
        {
            title: "Ataque em Textos Cifrados com Chave Reutilizada",
            desc: "Exemplo com dois blocos de bytes decimais cifrados sob a mesma chave One-Time Pad.",
            c1: "115, 101, 99, 114",
            c2: "100, 97, 100, 111"
        }
    ]
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = PRESETS;
}
