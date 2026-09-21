# CriptoLab Web
### Sistema Educacional de Criptografia Clássica e Criptoanálise

[![JavaScript](https://img.shields.io/badge/JavaScript-ES6%2B-F7DF1E?logo=javascript&logoColor=black)](https://developer.mozilla.org/pt-BR/docs/Web/JavaScript)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen)](#)
[![Tests Passing](https://img.shields.io/badge/Tests-24%2F24%20Passing-success)](tests/test_crypto.js)
[![Academic Project](https://img.shields.io/badge/IFSP-Campus%20Jacareí-blue)](https://jcr.ifsp.edu.br/)
[![Course](https://img.shields.io/badge/Seguran%C3%A7a%20de%20Sistemas-JCRSEGS-purple)](#)

> **Trabalho Prático da Disciplina de Segurança de Sistemas (JCRSEGS)**  
> **Curso:** Tecnologia em Análise e Desenvolvimento de Sistemas — **IFSP - Campus Jacareí**  
> **Docente:** Prof. Tardelli Stekel  
> **Integrantes da Equipe:** Alice Santos Monteiro de Barros, Felipe Rinaldi Sobreira e Nathan Henrique Guimarães de Oliveira  

---

## Sumário

- [Visão Geral](#visão-geral)
- [Diferenciais de Projeto](#diferenciais-de-projeto)
- [Algoritmos Implementados e Critérios](#algoritmos-implementados-e-critérios)
  - [1. One Time Pad (OTP)](#1-one-time-pad-otp)
  - [2. Cifra de César Generalizada](#2-cifra-de-césar-generalizada)
  - [3. Cifra de Vigenère](#3-cifra-de-vigenère)
  - [4. Cifra de Hill (2x2 Modular)](#4-cifra-de-hill-2x2-modular)
  - [5. Módulo Livre: Criptoanálise](#5-módulo-livre-criptoanálise)
- [Arquitetura de Código](#arquitetura-de-código)
- [Como Executar o Projeto](#como-executar-o-projeto)
- [Suíte de Testes Automatizados](#suíte-de-testes-automatizados)
- [Roteiro para a Apresentação Acadêmica](#roteiro-para-a-apresentação-acadêmica)
- [Licença e Uso Acadêmico](#licença-e-uso-acadêmico)

---

## Visão Geral

O **CriptoLab Web** é uma aplicação web interativa em formato Single Page Application (SPA), desenvolvida com o objetivo de demonstrar na prática os fundamentos matemáticos e operacionais de quatro algoritmos clássicos de criptografia e suas respectivas decriptações, além de dois métodos práticos de criptoanálise.

Todo o projeto foi construído **sem o auxílio de bibliotecas criptográficas externas**, implementando de maneira artesanal e transparente cada operação aritmética, lógica e algébrica (como conversões de base, algoritmos euclidianos, inversão de matrizes e testes estatísticos).

---

## Diferenciais de Projeto

- **Zero Bibliotecas Criptográficas:** Todo o motor matemático reside em módulos puros de JavaScript (`/js/crypto/`).
- **Interface Didática e Intuitiva:**
  - Layout focado em duas colunas (Controles de Entrada à esquerda, Resultados e Passo a Passo à direita).
  - Seletor de modo `[Criptografar] [Decriptografar]` que exibe apenas o contexto desejado, evitando poluição visual.
  - Acordeão expansível com a memória de cálculo minuciosa de cada algoritmo.
  - Tema escuro neutro com acentos em roxo e tipografia monoespaçada para clareza técnica.
- **Botões de Exemplos Rápidos (1-Click Presets):** Casos de teste pré-configurados para validação instantânea durante a apresentação em aula.
- **Suíte de Testes com 100% de Cobertura:** 24 testes unitários automatizados validando casos de borda e cálculos modulares.

---

## Algoritmos Implementados e Critérios

### 1. One Time Pad (OTP)
*Cifragem perfeitamente segura baseada exclusivamente em operações XOR bit a bit.*

- **Critério A — Entrada Decimal:** Aceita números inteiros na base 10 (ex: valor único ou vetor como `72, 101, 108, 108, 111`).
- **Critério B — Saída Decimal e Conversão Explícita:** Apresenta a saída criptografada em base 10, detalhando o passo a passo completo da conversão Decimal $\to$ Binário (divisões sucessivas por 2) e a tabela bit a bit:
  $$C_i = M_i \oplus K_i$$
- **Critério C — Decriptação Completa:** Processa o texto cifrado aplicando a mesma chave através da propriedade involutiva do XOR:
  $$M_i = C_i \oplus K_i$$

---

### 2. Cifra de César Generalizada
*Cifra de substituição monoalfabética com aritmética modular.*

- **Critério A — Suporte a Qualquer Chave Inteira $K \in \mathbb{Z}$:** Processa deslocamentos positivos, nulos, negativos ou maiores que 26 através da normalização modular:
  $$K_{\text{norm}} = ((K \bmod 26) + 26) \bmod 26$$
  $$C_i = (P_i + K_{\text{norm}}) \bmod 26$$
- **Critério B — Decriptação Exata:**
  $$P_i = (C_i - K_{\text{norm}} + 26) \bmod 26$$
- **Detalhamento:** Exibe tabela de mapeamento caractere por caractere preservando maiúsculas, minúsculas e pontuações.

---

### 3. Cifra de Vigenère
*Cifra de substituição polialfabética periódica.*

- **Critério A — Validação de Mensagem Longa:** Validação estrita exigindo que a mensagem a ser cifrada possua **no mínimo 4 palavras** antes de prosseguir.
- **Critério B — Extensão Cíclica da Chave:** Se o tamanho da chave for menor que a mensagem, a chave é estendida periodicamente de forma contínua até cobrir todo o texto:
  $$K_{\text{ext}} = (K_0, K_1, \dots, K_{m-1}, K_0, K_1, \dots)$$
- **Critério C — Decriptação:**
  $$P_i = (C_i - K_i + 26) \bmod 26$$

---

### 4. Cifra de Hill (2x2 Modular)
*Cifra de substituição poligráfica baseada em álgebra linear sobre o anel $\mathbb{Z}_{26}$.*

- **Critério A — Entrada Matricial e Mensagem:** Aceita mensagem alfanumérica e matriz de chave $2 \times 2$:
  $$K = \begin{pmatrix} k_{11} & k_{12} \\ k_{21} & k_{22} \end{pmatrix}$$
- **Critério B — Decriptação Algébrica Rigorosa:**
  - **Determinante:** $\det(K) = (k_{11} k_{22} - k_{12} k_{21}) \bmod 26$.
  - **Critério de Invertibilidade:** Verifica se $\gcd(\det(K), 26) = 1$. Caso não seja coprimo com 26, emite alerta imediato e bloqueia a operação.
  - **Inverso Modular via Algoritmo Euclidiano Estendido:** Determina $(\det(K))^{-1} \pmod{26}$.
  - **Matriz Adjugada Transposta e Matriz Inversa:**
    $$K^{-1} \equiv (\det(K))^{-1} \cdot \begin{pmatrix} k_{22} & -k_{12} \\ -k_{21} & k_{11} \end{pmatrix} \pmod{26}$$
  - **Padding Automático:** Insere o caractere nulo `'X'` ao final da mensagem quando o número de caracteres for ímpar.

---

### 5. Módulo Livre: Criptoanálise

O sistema implementa ambos os eixos propostos para o módulo avançado:

#### Opção A: Força Bruta em César com Ranking de Qui-Quadrado ($\chi^2$)
- Recebe um texto cifrado desconhecido e gera todas as **25 chaves possíveis**.
- Avalia cada frase gerada contra o perfil de frequência de letras da **Língua Portuguesa** através da estatística do Qui-Quadrado:
  $$\chi^2 = \sum_{c = \text{'A'}}^{\text{'Z'}} \frac{(O_c - E_c)^2}{E_c}$$
- Classifica e destaca automaticamente o candidato com maior coerência linguística (menor $\chi^2$).

#### Opção B: Ataque Two-Time Pad (Reutilização de Chave em OTP)
- Demonstra visualmente a falha catastrófica da reutilização de chave única em OTP:
  $$C_1 \oplus C_2 = (M_1 \oplus K) \oplus (M_2 \oplus K) = M_1 \oplus M_2$$
- Exibe o cancelamento numérico da chave $K$ e a exposição direta das mensagens cruzadas.

---

## Arquitetura de Código

```
JCRSEGS/
│
├── index.html                  # Interface gráfica Web (SPA estruturada e sem emojis)
├── server.js                   # Servidor de apoio HTTP nativo em Node.js (opcional)
├── README.md                   # Documentação acadêmica e guia do projeto
│
├── css/
│   └── styles.css              # Design system dark/purple com custom scrollbars
│
├── js/
│   ├── app.js                  # Controlador central de eventos, abas e renderização
│   ├── presets.js              # Exemplos rápidos pré-carregados para a apresentação
│   │
│   └── crypto/                 # Módulos puros (Zero bibliotecas terceiras)
│       ├── otp.js              # Aritmética base 10, divisões binárias e XOR
│       ├── caesar.js           # César com suporte a K negativo/infinito mod 26
│       ├── vigenere.js         # Validador de >= 4 palavras e repetição de chave
│       ├── hill.js             # Álgebra linear modular (det, gcd, inversa, matriz 2x2)
│       └── cryptanalysis.js    # Força bruta, frequências PT-BR e Two-Time Pad
│
└── tests/
    └── test_crypto.js          # Suíte de testes unitários automatizados (Node.js)
```

---

## Como Executar o Projeto

A aplicação é 100% autônoma e não exige `npm install`, downloads adicionais ou banco de dados.

### Método 1: Direto pelo Navegador (Sem Instalação)
1. Localize a pasta do projeto no computador.
2. Dê um duplo clique no arquivo `index.html` (ou arraste-o para o Chrome, Edge, Firefox ou Safari).
3. A aplicação funcionará com todas as suas funcionalidades prontas.

### Método 2: Via Servidor Local Node.js
Caso deseje rodar a aplicação através de um servidor HTTP local:
```bash
# Na raiz do projeto:
node server.js
```
Acesse no navegador:
```
http://localhost:3000
```

---

## Suíte de Testes Automatizados

Para certificar a integridade dos cálculos matemáticos e da decriptação, execute o script de testes:

```bash
node tests/test_crypto.js
```

**Resultado esperado:**
```text
====================================================
INICIANDO TESTES DO SISTEMA DE CRIPTOGRAFIA JCRSEGS
====================================================

[1] Testando One Time Pad (OTP)...
  [PASS] Decimal 42 -> Binário 00101010
  [PASS] Binário 00101010 -> Decimal 42
  [PASS] Criptografia OTP: 42 ⊕ 77 = 103 (esperado 103)
  [PASS] Decriptação OTP: 103 ⊕ 77 = 42 (esperado 42)
  [PASS] Vetor OTP Criptografado e Decriptografado com Sucesso

[2] Testando Cifra de César...
  [PASS] César K=3: 'ATACAR AO AMANHECER' -> 'DWDFDU DR DPDQKHFHU'
  [PASS] Decriptação César K=3: 'ATACAR AO AMANHECER'
  [PASS] César com K > 26 funciona perfeitamente
  [PASS] César com K=-1: 'Zebra' -> 'Ydaqz'
  [PASS] Decriptação César K=-1 funciona perfeitamente

[3] Testando Cifra de Vigenère...
  [PASS] Validação de mínimo de 4 palavras rejeita frases com 3 palavras
  [PASS] Comprimento do texto cifrado preservado
  [PASS] Vigenère Decriptação idêntica ao original: 'ESTE E UM TESTE CRIPTOGRAFICO'

[4] Testando Cifra de Hill (Álgebra Linear mod 26)...
  [PASS] Inverso de 3 mod 26 é 9 (pois 3*9=27=1 mod 26)
  [PASS] Determinante de [[3,3],[2,5]] mod 26 = 9 (esperado 9)
  [PASS] Inverso do Determinante = 3 (esperado 3)
  [PASS] Linha 0 da matriz inversa: [15,17] (esperado [15, 17])
  [PASS] Hill Cripto e Decripto 'HELP' -> 'HIAT' -> 'HELP'
  [PASS] Hill com padding: 'SOL' + 'X' -> 'EOBK' -> 'SOLX'
  [PASS] Matriz com det=0 rejeitada com erro explicativo

[5] Testando Criptoanálise...
  [PASS] Força bruta gerou todas as 25 possibilidades
  [PASS] Melhor candidato identificado automaticamente pelo ranking PT-BR: K = 7 (esperado 7)
  [PASS] Texto decifrado automaticamente é idêntico ao original
  [PASS] Two-Time Pad elimina chave: C1 ⊕ C2 = 73 (esperado M1 ⊕ M2 = 73)

====================================================
TOTAL DE TESTES: 24 | PASSARAM: 24 | FALHAS: 0
====================================================
```

---

## Roteiro para a Apresentação Acadêmica

Orientações práticas para os integrantes da equipe durante a apresentação com o **Prof. Tardelli Stekel**:

1. **Demonstração com Exemplos Prontos:** Utilize os botões de presets no topo de cada aba para preencher e testar os algoritmos instantaneamente, sem risco de erros de digitação ao vivo.
2. **Evidência de Construção Autoral:** Mostre ao professor os arquivos em `js/crypto/` para evidenciar a ausência de bibliotecas prontas:
   - `otp.js`: cálculo das divisões manuais para binário e a operação de bitwise XOR;
   - `hill.js`: implementação da função estendida de Euclides para encontrar o inverso multiplicativo modular e cálculo manual da matriz adjugada transposta;
   - `cryptanalysis.js`: modelo de frequência da língua portuguesa e cálculo da fórmula de $\chi^2$.
3. **Passo a Passo Interativo:** Abra a seção colapsável de **Passo a Passo Matemático** em cada cifra para explicar os passos intermediários do algoritmo diretamente pela interface.
4. **Validação de Restrições:** Mostre a mensagem de bloqueio da Cifra de Vigenère caso sejam digitadas menos de 4 palavras, e o alerta imediato na Cifra de Hill caso uma matriz com $\gcd(\det(K), 26) \neq 1$ seja fornecida.

---

## Licença e Uso Acadêmico

Desenvolvido para fins estritamente didáticos como requisito avaliativo do curso de Tecnologia em Análise e Desenvolvimento de Sistemas do **Instituto Federal de Educação, Ciência e Tecnologia de São Paulo (IFSP) - Campus Jacareí**.
