# Sistema Web de Criptografia Clássica e Criptoanálise

**Instituição:** IFSP - Campus Jacareí  
**Curso:** Tecnologia em Análise e Desenvolvimento de Sistemas  
**Disciplina:** Segurança de Sistemas – JCRSEGS  
**Professor:** Prof. Tardelli Stekel  
**Alunos:** Alice Santos Monteiro de Barros, Felipe Rinaldi Sobreira e ...  
**Atividade:** Introdução à Criptografia  
**Prazo Moodle:** até 28/09/2026 | **Apresentação:** 29/09/2026  

---

## Objetivo e Conformidade com os Critérios

Desenvolvimento de um sistema Web completo, responsivo e didático que implementa do zero (sem uso de bibliotecas criptográficas externas prontas) os seguintes algoritmos de criptografia e suas respectivas decriptações:

1. **One Time Pad (OTP)**:
   - **Critério (a):** Entrada da mensagem e da chave em **números no sistema decimal (base 10)**.
   - **Critério (b):** Saída criptografada em **base 10**, com a **conversão Decimal para Binária** explícita no algoritmo e na interface.
   - **Critério (c):** Algoritmo de **decriptação** completo ($C \oplus K = M$).
   - *Recurso Adicional:* Suporta tanto valores decimais individuais quanto vetores de decimais, exibindo a tabela comparativa de bits e as divisões sucessivas por 2.

2. **Cifra de César Generalizada**:
   - **Critério (a):** Mensagem como palavra ou frase e chave como um **número inteiro qualquer $K$** (deslocamento). Trata $K > 26$ e $K < 0$ via aritmética modular $\bmod 26$.
   - **Critério (b):** Algoritmo de **decriptação** ($P = (C - K) \bmod 26$).
   - *Recurso Adicional:* Preserva formatação, pontuação e maiúsculas/minúsculas, com tabela detalhada passo a passo de posições no alfabeto.

3. **Cifra de Vigenère**:
   - **Critério (a):** Mensagem com validação obrigatória de **no mínimo quatro palavras**. Chave como palavra ou frase.
   - **Critério (b):** Caso a chave tenha tamanho inferior à mensagem, o algoritmo **repete a chave ciclicamente** até cobrir toda a extensão do texto.
   - **Critério (c):** Algoritmo de **decriptação** ($P_i = (C_i - K_i + 26) \bmod 26$).

4. **Cifra de Hill**:
   - **Critério (a):** Mensagem e chave fornecidas como palavra ou matriz numérica ($2 \times 2$).
   - **Critério (b):** Algoritmo de **decriptação** rigoroso baseado em álgebra linear modular no anel $\mathbb{Z}_{26}$.
   - **Álgebra Linear Implementada:**
     - Cálculo manual de determinante $\det(K) = ad - bc \pmod{26}$.
     - Verificação de invertibilidade $\gcd(\det(K), 26) = 1$ com feedback em tempo real.
     - Inverso multiplicativo modular $\det(K)^{-1} \pmod{26}$ via **Algoritmo Euclidiano Estendido**.
     - Cálculo da matriz adjunta transposta e da matriz inversa $K^{-1} \pmod{26}$.
     - Padding com caractere 'X' caso a mensagem tenha comprimento ímpar.
     - Multiplicação matricial bloco a bloco passo a passo.

5. **Módulo Livre: Expansão Criptográfica / Criptoanálise**:
   - **Opção A (Força Bruta em César + Análise de Frequência PT-BR):**
     - Recebe apenas o texto cifrado (sem a chave).
     - Gera e exibe automaticamente todas as **25 possibilidades de deslocamento** na tela.
     - **Bônus Completo:** Aplica modelo estatístico com as frequências relativas de letras da língua portuguesa e o teste do **Qui-Quadrado ($\chi^2$)** para indicar e destacar visualmente a chave mais provável e o texto original.
   - **Opção B (Two-Time Pad - Quebra de OTP por Reutilização de Chave):**
     - Recebe dois textos cifrados $C_1$ e $C_2$ com a mesma chave $K$.
     - Calcula e exibe $C_1 \oplus C_2$, provando algebricamente e numericamente que a chave foi eliminada e restou apenas $M_1 \oplus M_2$.

---

## Como Executar o Projeto

O projeto foi construído **sem dependências externas**, podendo ser executado de duas formas simples:

### Opção 1: Diretamente no Navegador (Sem Instalar Nada)
1. Basta abrir o arquivo `index.html` em qualquer navegador web moderno (Google Chrome, Microsoft Edge, Mozilla Firefox, Safari, etc.).
2. Toda a lógica criptográfica é executada localmente pelo navegador via JavaScript vanilla.

### Opção 2: Via Servidor Local Node.js
Caso prefira rodar um servidor HTTP local:
```bash
node server.js
```
Abra o navegador no endereço indicado:
```
http://localhost:3000
```

---

## Bateria de Testes Automatizados

Para executar os 24 testes unitários automatizados cobrindo todos os casos de borda, matrizes, inversa modular, padding, validações e criptoanálise:

```bash
node tests/test_crypto.js
```

**Resultado:**
```
====================================================
TOTAL DE TESTES: 24 | PASSARAM: 24 | FALHAS: 0
====================================================
```

---

## Estrutura de Arquivos

```
JCRSEGS/
│
├── index.html              # Interface gráfica Web SPA moderna e responsiva
├── server.js               # Servidor HTTP nativo Node.js (opcional para rodar localmente)
├── README.md               # Documentação técnica e guia de apresentação
│
├── css/
│   └── styles.css          # Folha de estilos preta/cinza escuro e roxo
│
├── js/
│   ├── app.js              # Controlador de UI, abas, eventos e renderização matemática
│   ├── presets.js          # Exemplos prontos com 1 clique para a apresentação em aula
│   └── crypto/
│       ├── otp.js          # Módulo autoral do One Time Pad (base 10 / binário / XOR)
│       ├── caesar.js       # Módulo autoral da Cifra de César Generalizada
│       ├── vigenere.js     # Módulo autoral da Cifra de Vigenère (validação 4 palavras)
│       ├── hill.js         # Módulo autoral da Cifra de Hill (álgebra linear mod 26)
│       └── cryptanalysis.js# Módulo de Criptoanálise (Opção A e Opção B)
│
└── tests/
    └── test_crypto.js      # Suíte de testes unitários para verificação em terminal
```

---

## Dicas para a Apresentação em Sala de Aula (29/09/26)

Durante a apresentação com o Prof. Tardelli Stekel:
1. **Utilize os botões de "Exemplos Prontos":** Cada aba possui botões no topo que preenchem e executam os testes com 1 clique, economizando tempo e evitando erros de digitação.
2. **Destaque a Ausência de Bibliotecas Criptográficas:** Abra os arquivos da pasta `js/crypto/` para demonstrar ao professor que todos os algoritmos foram programados artesanalmente (desde a divisão sucessiva para binário, o Algoritmo Euclidiano Estendido para matriz inversa mod 26 até o cálculo do Qui-Quadrado para a análise de frequência em português).
3. **Mostre os Passos Matemáticos:** Cada aba gera um detalhamento minucioso dos cálculos intermediários, matrizes e tabelas de bits, comprovando o domínio conceitual da equipe.
