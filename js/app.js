/**
 * Controlador de Interface e Interatividade - Sistema Criptográfico Web
 * Disciplina: Segurança de Sistemas - JCRSEGS
 * Prof. Tardelli Stekel
 */

document.addEventListener('DOMContentLoaded', () => {
    // -------------------------------------------------------------
    // GERENCIAMENTO DE ABAS PRINCIPAIS
    // -------------------------------------------------------------
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabPanes = document.querySelectorAll('.tab-pane');

    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTab = btn.getAttribute('data-tab');
            tabButtons.forEach(b => b.classList.remove('active'));
            tabPanes.forEach(p => p.classList.remove('active'));

            btn.classList.add('active');
            const activePane = document.getElementById(targetTab);
            if (activePane) activePane.classList.add('active');
        });
    });

    // Utilitário de Cópia para Clipboard
    window.copyToClipboard = function(elementId, btnElement) {
        const target = document.getElementById(elementId);
        if (!target) return;
        const text = target.innerText.trim();
        if (!text || text === 'Nenhum resultado gerado.') return;

        navigator.clipboard.writeText(text).then(() => {
            const originalText = btnElement.innerText;
            btnElement.innerText = 'Copiado!';
            btnElement.style.color = '#10b981';
            setTimeout(() => {
                btnElement.innerText = originalText;
                btnElement.style.color = '';
            }, 1800);
        }).catch(err => {
            console.error('Falha ao copiar:', err);
        });
    };

    // -------------------------------------------------------------
    // GERENCIAMENTO DE MODO (CRIPTOGRAFAR / DECRIPTOGRAFAR)
    // -------------------------------------------------------------
    window.switchMode = function(cipher, mode) {
        const encBtn = document.getElementById(`${cipher}-seg-enc`);
        const decBtn = document.getElementById(`${cipher}-seg-dec`);
        const encForm = document.getElementById(`${cipher}-form-enc`);
        const decForm = document.getElementById(`${cipher}-form-dec`);
        const label = document.getElementById(`${cipher}-result-label`);

        if (mode === 'enc') {
            if (encBtn) encBtn.classList.add('active');
            if (decBtn) decBtn.classList.remove('active');
            if (encForm) encForm.style.display = 'block';
            if (decForm) decForm.style.display = 'none';
            if (label) label.innerText = 'Resultado Criptografado';
            // Executa cálculo de cifra
            const runBtn = document.getElementById(`${cipher}-enc-btn`);
            if (runBtn) runBtn.click();
        } else {
            if (encBtn) encBtn.classList.remove('active');
            if (decBtn) decBtn.classList.add('active');
            if (encForm) encForm.style.display = 'none';
            if (decForm) decForm.style.display = 'block';
            if (label) label.innerText = 'Texto Claro Recuperado';
            // Executa cálculo de decriptação
            const runBtn = document.getElementById(`${cipher}-dec-btn`);
            if (runBtn) runBtn.click();
        }
    };

    // -------------------------------------------------------------
    // 1. ONE TIME PAD (OTP)
    // -------------------------------------------------------------
    const otpMsgInput = document.getElementById('otp-msg-input');
    const otpKeyInput = document.getElementById('otp-key-input');
    const otpEncBtn = document.getElementById('otp-enc-btn');

    const otpDecMsgInput = document.getElementById('otp-dec-msg-input');
    const otpDecKeyInput = document.getElementById('otp-dec-key-input');
    const otpDecBtn = document.getElementById('otp-dec-btn');

    const otpOutput = document.getElementById('otp-active-output');
    const otpSteps = document.getElementById('otp-active-steps');

    // Criptografar OTP
    otpEncBtn.addEventListener('click', () => {
        try {
            const rawMsg = otpMsgInput.value.trim();
            const rawKey = otpKeyInput.value.trim();
            if (!rawMsg || !rawKey) {
                alert('Informe a mensagem decimal e a chave decimal.');
                return;
            }

            const msgDecs = rawMsg.split(/[\s,;]+/).map(Number);
            const keyDecs = rawKey.split(/[\s,;]+/).map(Number);

            const result = OTPModule.encrypt(msgDecs, keyDecs);
            otpOutput.innerText = result.cipherDecimals.join(', ');

            let htmlSteps = '';
            result.items.forEach(item => {
                htmlSteps += `
                    <div class="step-card">
                        <div style="display:flex; justify-content:space-between; margin-bottom:0.4rem;">
                            <strong>Item #${item.index + 1}: M = ${item.messageDecimal}₁₀ | K = ${item.keyDecimal}₁₀</strong>
                            <span class="badge badge-info">C = ${item.cipherDecimal}₁₀</span>
                        </div>
                        
                        <div class="math-block">
                            1. Decimal para Binário: M = ${item.messageDecimal}₁₀ (${item.messageBinary}₂) | K = ${item.keyDecimal}₁₀ (${item.keyBinary}₂)<br>
                            2. Operação XOR Bit a Bit: ${item.messageBinary} ⊕ ${item.keyBinary} = <strong>${item.cipherBinary}₂</strong><br>
                            3. Binário para Decimal: ${item.cipherBinary}₂ = <strong>${item.cipherDecimal}₁₀</strong>
                        </div>

                        <div class="xor-table-container">
                            <table class="xor-table">
                                <thead>
                                    <tr>
                                        <th>Bit</th>
                                        ${item.bitSteps.map(s => `<th>#${s.index + 1}</th>`).join('')}
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td><strong>M</strong></td>
                                        ${item.bitSteps.map(s => `<td class="${s.b1 === '1' ? 'bit-1' : 'bit-0'}">${s.b1}</td>`).join('')}
                                    </tr>
                                    <tr>
                                        <td><strong>K</strong></td>
                                        ${item.bitSteps.map(s => `<td class="${s.b2 === '1' ? 'bit-1' : 'bit-0'}">${s.b2}</td>`).join('')}
                                    </tr>
                                    <tr class="xor-result-row">
                                        <td><strong>C</strong></td>
                                        ${item.bitSteps.map(s => `<td>${s.xor}</td>`).join('')}
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                `;
            });
            otpSteps.innerHTML = htmlSteps;

        } catch (e) {
            alert('Erro no OTP: ' + e.message);
        }
    });

    // Decriptografar OTP
    otpDecBtn.addEventListener('click', () => {
        try {
            const rawC = otpDecMsgInput.value.trim();
            const rawKey = otpDecKeyInput.value.trim();
            if (!rawC || !rawKey) {
                alert('Informe o texto cifrado decimal e a chave decimal.');
                return;
            }

            const cDecs = rawC.split(/[\s,;]+/).map(Number);
            const keyDecs = rawKey.split(/[\s,;]+/).map(Number);

            const result = OTPModule.decrypt(cDecs, keyDecs);
            otpOutput.innerText = result.plainDecimals.join(', ');

            let htmlSteps = '';
            result.items.forEach(item => {
                htmlSteps += `
                    <div class="step-card">
                        <div style="display:flex; justify-content:space-between; margin-bottom:0.4rem;">
                            <strong>Decriptação #${item.index + 1}: C = ${item.cipherDecimal} | K = ${item.keyDecimal}</strong>
                            <span class="badge badge-info">M = ${item.plainDecimal}</span>
                        </div>
                        <div class="math-block">
                            Propriedade Involutiva: M = C ⊕ K = (M ⊕ K) ⊕ K<br>
                            &nbsp;&nbsp;• C = ${item.cipherBinary}₂ (${item.cipherDecimal})<br>
                            &nbsp;&nbsp;• K = ${item.keyBinary}₂ (${item.keyDecimal})<br>
                            &nbsp;&nbsp;• M = ${item.plainBinary}₂ = <strong>${item.plainDecimal}₁₀</strong>
                        </div>
                    </div>
                `;
            });
            otpSteps.innerHTML = htmlSteps;

        } catch (e) {
            alert('Erro na Decriptação OTP: ' + e.message);
        }
    });

    // Inverter OTP (Cifrado vai para decriptação ou vice-versa)
    window.swapOtpData = function() {
        const isEnc = document.getElementById('otp-seg-enc').classList.contains('active');
        if (isEnc) {
            otpDecMsgInput.value = otpOutput.innerText.trim();
            otpDecKeyInput.value = otpKeyInput.value.trim();
            switchMode('otp', 'dec');
        } else {
            otpMsgInput.value = otpOutput.innerText.trim();
            otpKeyInput.value = otpDecKeyInput.value.trim();
            switchMode('otp', 'enc');
        }
    };

    // -------------------------------------------------------------
    // 2. CIFRA DE CÉSAR
    // -------------------------------------------------------------
    const caesarMsgInput = document.getElementById('caesar-msg-input');
    const caesarKeyInput = document.getElementById('caesar-key-input');
    const caesarEncBtn = document.getElementById('caesar-enc-btn');

    const caesarDecMsgInput = document.getElementById('caesar-dec-msg-input');
    const caesarDecKeyInput = document.getElementById('caesar-dec-key-input');
    const caesarDecBtn = document.getElementById('caesar-dec-btn');

    const caesarOutput = document.getElementById('caesar-active-output');
    const caesarSteps = document.getElementById('caesar-active-steps');

    // Criptografar César
    caesarEncBtn.addEventListener('click', () => {
        try {
            const msg = caesarMsgInput.value;
            const k = caesarKeyInput.value;
            if (!msg) {
                alert('Informe a mensagem.');
                return;
            }

            const res = CaesarModule.encrypt(msg, k);
            caesarOutput.innerText = res.ciphertext;

            let tableRows = res.steps.map(s => `
                <tr>
                    <td><code>${s.originalChar === ' ' ? '(espaço)' : s.originalChar}</code></td>
                    <td>${s.p !== null ? s.p : '-'}</td>
                    <td>${s.normK}</td>
                    <td>${s.c !== null ? s.c : '-'}</td>
                    <td><strong style="color:var(--primary); font-size:1rem;">${s.cipherChar === ' ' ? '(espaço)' : s.cipherChar}</strong></td>
                    <td style="font-family:var(--font-mono); font-size:0.78rem; color:var(--text-muted);">${s.formula}</td>
                </tr>
            `).join('');

            caesarSteps.innerHTML = `
                <div class="math-block" style="margin-bottom:0.65rem;">
                    Fórmula da Cifra: <strong>C = (P + K) mod 26</strong> | Deslocamento K = ${res.k} (normalizado: <strong>${res.normalizedK}</strong>)
                </div>
                <div class="table-responsive">
                    <table class="custom-table">
                        <thead>
                            <tr>
                                <th>Caractere</th>
                                <th>Posição P</th>
                                <th>K Efetivo</th>
                                <th>Posição C</th>
                                <th>Cifrado</th>
                                <th>Cálculo</th>
                            </tr>
                        </thead>
                        <tbody>${tableRows}</tbody>
                    </table>
                </div>
            `;
        } catch (e) {
            alert('Erro em César: ' + e.message);
        }
    });

    // Decriptografar César
    caesarDecBtn.addEventListener('click', () => {
        try {
            const cipher = caesarDecMsgInput.value;
            const k = caesarDecKeyInput.value;
            if (!cipher) {
                alert('Informe o texto cifrado.');
                return;
            }

            const res = CaesarModule.decrypt(cipher, k);
            caesarOutput.innerText = res.plaintext;

            let tableRows = res.steps.map(s => `
                <tr>
                    <td><code>${s.cipherChar === ' ' ? '(espaço)' : s.cipherChar}</code></td>
                    <td>${s.c !== null ? s.c : '-'}</td>
                    <td>${s.normK}</td>
                    <td>${s.p !== null ? s.p : '-'}</td>
                    <td><strong style="color:var(--success); font-size:1rem;">${s.plainChar === ' ' ? '(espaço)' : s.plainChar}</strong></td>
                    <td style="font-family:var(--font-mono); font-size:0.78rem; color:var(--text-muted);">${s.formula}</td>
                </tr>
            `).join('');

            caesarSteps.innerHTML = `
                <div class="math-block" style="margin-bottom:0.65rem;">
                    Fórmula da Decriptação: <strong>P = (C - K) mod 26</strong> | K = ${res.k} (normalizado: <strong>${res.normalizedK}</strong>)
                </div>
                <div class="table-responsive">
                    <table class="custom-table">
                        <thead>
                            <tr>
                                <th>Cifrado</th>
                                <th>Posição C</th>
                                <th>K Efetivo</th>
                                <th>Posição P</th>
                                <th>Texto Claro</th>
                                <th>Cálculo</th>
                            </tr>
                        </thead>
                        <tbody>${tableRows}</tbody>
                    </table>
                </div>
            `;
        } catch (e) {
            alert('Erro na Decriptação de César: ' + e.message);
        }
    });

    window.swapCaesarData = function() {
        const isEnc = document.getElementById('caesar-seg-enc').classList.contains('active');
        if (isEnc) {
            caesarDecMsgInput.value = caesarOutput.innerText.trim();
            caesarDecKeyInput.value = caesarKeyInput.value;
            switchMode('caesar', 'dec');
        } else {
            caesarMsgInput.value = caesarOutput.innerText.trim();
            caesarKeyInput.value = caesarDecKeyInput.value;
            switchMode('caesar', 'enc');
        }
    };

    // -------------------------------------------------------------
    // 3. CIFRA DE VIGENÈRE
    // -------------------------------------------------------------
    const vigMsgInput = document.getElementById('vig-msg-input');
    const vigKeyInput = document.getElementById('vig-key-input');
    const vigWordBadge = document.getElementById('vig-word-badge');
    const vigEncBtn = document.getElementById('vig-enc-btn');

    const vigDecMsgInput = document.getElementById('vig-dec-msg-input');
    const vigDecKeyInput = document.getElementById('vig-dec-key-input');
    const vigDecBtn = document.getElementById('vig-dec-btn');

    const vigOutput = document.getElementById('vig-active-output');
    const vigSteps = document.getElementById('vig-active-steps');

    function updateVigWordCount() {
        const count = VigenereModule.countWords(vigMsgInput.value);
        vigWordBadge.innerText = `${count} palavra(s) (Mínimo: 4)`;
        vigWordBadge.className = count >= 4 ? 'word-counter-badge word-count-valid' : 'word-counter-badge word-count-invalid';
    }
    vigMsgInput.addEventListener('input', updateVigWordCount);

    vigEncBtn.addEventListener('click', () => {
        try {
            const msg = vigMsgInput.value;
            const key = vigKeyInput.value;

            const res = VigenereModule.encrypt(msg, key);
            vigOutput.innerText = res.ciphertext;

            let tableRows = res.steps.map(s => `
                <tr>
                    <td><code>${s.plainChar === ' ' ? '(espaço)' : s.plainChar}</code></td>
                    <td>${s.p !== null ? s.p : '-'}</td>
                    <td><strong style="color:#c4b5fd;">${s.keyChar}</strong> (${s.kShift !== null ? s.kShift : '-'})</td>
                    <td>${s.c !== null ? s.c : '-'}</td>
                    <td><strong style="color:var(--primary); font-size:0.95rem;">${s.cipherChar === ' ' ? '(espaço)' : s.cipherChar}</strong></td>
                    <td style="font-family:var(--font-mono); font-size:0.76rem; color:var(--text-muted);">${s.formula}</td>
                </tr>
            `).join('');

            vigSteps.innerHTML = `
                <div class="math-block" style="margin-bottom:0.65rem;">
                    <strong>Chave Expandida Ciclicamente:</strong> ${res.expandedKey}<br>
                    Fórmula Polialfabética: <strong>C[i] = (P[i] + K[i]) mod 26</strong> | Total de Palavras Validadas: <strong>${res.wordCount}</strong>
                </div>
                <div class="table-responsive">
                    <table class="custom-table">
                        <thead>
                            <tr>
                                <th>Original</th>
                                <th>Pos P[i]</th>
                                <th>Chave K[i]</th>
                                <th>Pos C[i]</th>
                                <th>Cifrado</th>
                                <th>Passo a Passo</th>
                            </tr>
                        </thead>
                        <tbody>${tableRows}</tbody>
                    </table>
                </div>
            `;
        } catch (e) {
            alert('Erro em Vigenère: ' + e.message);
        }
    });

    vigDecBtn.addEventListener('click', () => {
        try {
            const cipher = vigDecMsgInput.value;
            const key = vigDecKeyInput.value;

            const res = VigenereModule.decrypt(cipher, key);
            vigOutput.innerText = res.plaintext;

            let tableRows = res.steps.map(s => `
                <tr>
                    <td><code>${s.cipherChar === ' ' ? '(espaço)' : s.cipherChar}</code></td>
                    <td>${s.c !== null ? s.c : '-'}</td>
                    <td><strong style="color:#c4b5fd;">${s.keyChar}</strong> (${s.kShift !== null ? s.kShift : '-'})</td>
                    <td>${s.p !== null ? s.p : '-'}</td>
                    <td><strong style="color:var(--success); font-size:0.95rem;">${s.plainChar === ' ' ? '(espaço)' : s.plainChar}</strong></td>
                    <td style="font-family:var(--font-mono); font-size:0.76rem; color:var(--text-muted);">${s.formula}</td>
                </tr>
            `).join('');

            vigSteps.innerHTML = `
                <div class="math-block" style="margin-bottom:0.65rem;">
                    Decriptação Polialfabética: <strong>P[i] = (C[i] - K[i] + 26) mod 26</strong>
                </div>
                <div class="table-responsive">
                    <table class="custom-table">
                        <thead>
                            <tr>
                                <th>Cifrado</th>
                                <th>Pos C[i]</th>
                                <th>Chave K[i]</th>
                                <th>Pos P[i]</th>
                                <th>Texto Claro</th>
                                <th>Passo a Passo</th>
                            </tr>
                        </thead>
                        <tbody>${tableRows}</tbody>
                    </table>
                </div>
            `;
        } catch (e) {
            alert('Erro na Decriptação de Vigenère: ' + e.message);
        }
    });

    window.swapVigData = function() {
        const isEnc = document.getElementById('vig-seg-enc').classList.contains('active');
        if (isEnc) {
            vigDecMsgInput.value = vigOutput.innerText.trim();
            vigDecKeyInput.value = vigKeyInput.value;
            switchMode('vig', 'dec');
        } else {
            vigMsgInput.value = vigOutput.innerText.trim();
            vigKeyInput.value = vigDecKeyInput.value;
            updateVigWordCount();
            switchMode('vig', 'enc');
        }
    };

    // -------------------------------------------------------------
    // 4. CIFRA DE HILL
    // -------------------------------------------------------------
    const hillKeyWord = document.getElementById('hill-key-word');
    const hillMatrixStatus = document.getElementById('hill-matrix-status');

    const hillMsgInput = document.getElementById('hill-msg-input');
    const hillEncBtn = document.getElementById('hill-enc-btn');

    const hillDecMsgInput = document.getElementById('hill-dec-msg-input');
    const hillDecBtn = document.getElementById('hill-dec-btn');

    const hillOutput = document.getElementById('hill-active-output');
    const hillSteps = document.getElementById('hill-active-steps');

    function getHillKeyFromUI() {
        const m00 = parseInt(document.getElementById('hill-m00').value, 10) || 0;
        const m01 = parseInt(document.getElementById('hill-m01').value, 10) || 0;
        const m10 = parseInt(document.getElementById('hill-m10').value, 10) || 0;
        const m11 = parseInt(document.getElementById('hill-m11').value, 10) || 0;
        return [[m00, m01], [m10, m11]];
    }

    function checkHillMatrixInvertibility() {
        try {
            const K = getHillKeyFromUI();
            const detRaw = HillModule.determinant(K);
            const detMod = HillModule.mod(detRaw, 26);
            const { gcd } = HillModule.extendedGCD(detMod, 26);

            if (gcd === 1) {
                const invDet = HillModule.modInverse(detMod, 26);
                hillMatrixStatus.innerHTML = `
                    <span class="badge" style="background:var(--success-bg); color:var(--success); border:1px solid var(--success-border); font-size:0.7rem;">
                        Invertível: det = ${detMod}, det⁻¹ = ${invDet}
                    </span>
                `;
            } else {
                hillMatrixStatus.innerHTML = `
                    <span class="badge" style="background:var(--danger-bg); color:var(--danger); border:1px solid var(--danger-border); font-size:0.7rem;">
                        Não Invertível: mdc(${detMod}, 26) = ${gcd} ≠ 1
                    </span>
                `;
            }
        } catch (e) {
            hillMatrixStatus.innerHTML = `<span class="badge" style="background:var(--warning-bg); color:var(--warning); font-size:0.7rem;">${e.message}</span>`;
        }
    }

    // Ao digitar palavra-chave, atualiza a matriz
    hillKeyWord.addEventListener('input', () => {
        const val = hillKeyWord.value.trim().toUpperCase().replace(/[^A-Z]/g, '');
        if (val.length >= 4) {
            document.getElementById('hill-m00').value = val.charCodeAt(0) - 65;
            document.getElementById('hill-m01').value = val.charCodeAt(1) - 65;
            document.getElementById('hill-m10').value = val.charCodeAt(2) - 65;
            document.getElementById('hill-m11').value = val.charCodeAt(3) - 65;
            checkHillMatrixInvertibility();
        }
    });

    document.querySelectorAll('.matrix-cell').forEach(input => {
        input.addEventListener('input', checkHillMatrixInvertibility);
    });
    checkHillMatrixInvertibility();

    hillEncBtn.addEventListener('click', () => {
        try {
            const msg = hillMsgInput.value.trim();
            if (!msg) {
                alert('Informe a mensagem.');
                return;
            }
            const K = getHillKeyFromUI();
            const res = HillModule.encrypt(msg, K, 2, 'X');
            hillOutput.innerText = res.ciphertext;

            const inv = res.inverseData;

            let blocksHtml = res.blockSteps.map(b => `
                <div class="step-card" style="margin-bottom:0.45rem;">
                    <div style="display:flex; justify-content:space-between; margin-bottom:0.25rem;">
                        <strong>Bloco #${b.blockIndex + 1}: '${b.plainLetters}' [${b.plainVector.join(', ')}]</strong>
                        <span style="color:var(--primary); font-weight:bold;">Cifrado: '${b.cipherLetters}' [${b.cipherVector.join(', ')}]</span>
                    </div>
                    <div style="font-family:var(--font-mono); font-size:0.8rem; color:var(--text-secondary);">
                        ${b.breakdown.map(bd => `Linha ${bd.row}: [${bd.terms}] = ${bd.sumRaw} mod 26 = <strong>${bd.resMod} ('${bd.char}')</strong>`).join('<br>')}
                    </div>
                </div>
            `).join('');

            hillSteps.innerHTML = `
                <div class="math-block" style="margin-bottom:0.65rem;">
                    <strong>Álgebra Linear Modular:</strong><br>
                    Matriz K: <code>[[${res.keyMatrix[0]}], [${res.keyMatrix[1]}]]</code> | det(K) mod 26 = <strong>${inv.detMod}</strong> | det⁻¹ mod 26 = <strong>${inv.invDet}</strong><br>
                    Matriz Inversa K⁻¹ mod 26: <code>[[${inv.invMatrix[0]}], [${inv.invMatrix[1]}]]</code><br>
                    ${res.paddedCount > 0 ? `<span style="color:var(--warning);">Padding adicionado: +${res.paddedCount} letra(s) 'X' (Texto: '${res.paddedPlaintext}').</span>` : ''}
                </div>
                <div style="font-size:0.8rem; font-weight:600; color:var(--text-muted); text-transform:uppercase; margin-bottom:0.5rem;">
                    Multiplicações Matriciais (C = K · P mod 26):
                </div>
                ${blocksHtml}
            `;
        } catch (e) {
            alert('Erro na Cifra de Hill: ' + e.message);
        }
    });

    hillDecBtn.addEventListener('click', () => {
        try {
            const cipher = hillDecMsgInput.value.trim();
            if (!cipher) {
                alert('Informe o texto cifrado.');
                return;
            }
            const K = getHillKeyFromUI();
            const res = HillModule.decrypt(cipher, K, 2);
            hillOutput.innerText = res.plaintext;

            const inv = res.inverseData;

            let blocksHtml = res.blockSteps.map(b => `
                <div class="step-card" style="margin-bottom:0.45rem;">
                    <div style="display:flex; justify-content:space-between; margin-bottom:0.25rem;">
                        <strong>Bloco #${b.blockIndex + 1}: '${b.cipherLetters}' [${b.cipherVector.join(', ')}]</strong>
                        <span style="color:var(--success); font-weight:bold;">Decifrado: '${b.plainLetters}' [${b.plainVector.join(', ')}]</span>
                    </div>
                    <div style="font-family:var(--font-mono); font-size:0.8rem; color:var(--text-secondary);">
                        ${b.breakdown.map(bd => `Linha ${bd.row}: [${bd.terms}] = ${bd.sumRaw} mod 26 = <strong>${bd.resMod} ('${bd.char}')</strong>`).join('<br>')}
                    </div>
                </div>
            `).join('');

            hillSteps.innerHTML = `
                <div class="math-block" style="margin-bottom:0.65rem;">
                    Decriptação via Matriz Inversa: <strong>P = K⁻¹ · C mod 26</strong><br>
                    Matriz Inversa K⁻¹: <code>[[${inv.invMatrix[0]}], [${inv.invMatrix[1]}]]</code>
                </div>
                <div style="font-size:0.8rem; font-weight:600; color:var(--text-muted); text-transform:uppercase; margin-bottom:0.5rem;">
                    Multiplicações Matriciais (P = K⁻¹ · C mod 26):
                </div>
                ${blocksHtml}
            `;
        } catch (e) {
            alert('Erro na Decriptação de Hill: ' + e.message);
        }
    });

    window.swapHillData = function() {
        const isEnc = document.getElementById('hill-seg-enc').classList.contains('active');
        if (isEnc) {
            hillDecMsgInput.value = hillOutput.innerText.trim();
            switchMode('hill', 'dec');
        } else {
            hillMsgInput.value = hillOutput.innerText.trim();
            switchMode('hill', 'enc');
        }
    };

    // -------------------------------------------------------------
    // 5. MÓDULO LIVRE: CRIPTOANÁLISE
    // -------------------------------------------------------------
    window.switchCryptoOption = function(opt) {
        const tabA = document.getElementById('subtab-crypto-a');
        const tabB = document.getElementById('subtab-crypto-b');
        const paneA = document.getElementById('crypto-pane-a');
        const paneB = document.getElementById('crypto-pane-b');

        if (opt === 'a') {
            tabA.classList.add('active');
            tabB.classList.remove('active');
            paneA.style.display = 'block';
            paneB.style.display = 'none';
        } else {
            tabA.classList.remove('active');
            tabB.classList.add('active');
            paneA.style.display = 'none';
            paneB.style.display = 'block';
        }
    };

    const bruteInput = document.getElementById('brute-input');
    const bruteBtn = document.getElementById('brute-btn');
    const bruteResultsContainer = document.getElementById('brute-results-container');
    const bruteBestBox = document.getElementById('brute-best-box');

    bruteBtn.addEventListener('click', () => {
        try {
            const cipher = bruteInput.value.trim();
            if (!cipher) {
                alert('Informe um texto cifrado.');
                return;
            }

            const res = CryptanalysisModule.bruteForceCaesar(cipher);
            const best = res.bestCandidate;

            bruteBestBox.innerHTML = `
                <div class="alert alert-success" style="margin-bottom:1.25rem;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
                        <strong style="color:var(--success); font-size:0.95rem;">
                            Chave Mais Provável: K = ${best.shift}
                        </strong>
                        <span class="rank-badge">Similaridade PT-BR: ${best.confidenceScore}%</span>
                    </div>
                    <div style="background:#090a0f; border:1px solid #1c1e2b; padding:0.65rem 0.85rem; border-radius:4px; font-family:var(--font-mono); color:#10b981; font-weight:600; font-size:1.05rem;">
                        ${best.decryptedText}
                    </div>
                    <div style="margin-top:0.35rem; font-size:0.78rem; color:var(--text-muted);">
                        Estatística Qui-Quadrado (χ²): <strong>${best.chiSquare}</strong>
                    </div>
                </div>
            `;

            let rowsHtml = res.candidates.map(c => `
                <tr class="${c.isBestMatch ? 'highlight-best' : ''}">
                    <td><strong>K = ${c.shift}</strong></td>
                    <td style="font-family:var(--font-mono); font-size:0.86rem;">
                        ${c.isBestMatch ? `<span class="rank-badge" style="margin-right:0.35rem;">Sugerido</span>` : ''}
                        ${c.decryptedText}
                    </td>
                    <td>${c.confidenceScore}%</td>
                    <td style="color:var(--text-muted);">${c.chiSquare}</td>
                </tr>
            `).join('');

            bruteResultsContainer.innerHTML = `
                <div class="table-responsive" style="max-height:360px; overflow-y:auto;">
                    <table class="custom-table">
                        <thead>
                            <tr>
                                <th style="width:85px;">Chave K</th>
                                <th>Texto Claro Decifrado (Todas as 25 Opções)</th>
                                <th style="width:120px;">Score PT-BR</th>
                                <th style="width:100px;">Qui-Quadrado</th>
                            </tr>
                        </thead>
                        <tbody>${rowsHtml}</tbody>
                    </table>
                </div>
            `;
        } catch (e) {
            alert('Erro na Força Bruta: ' + e.message);
        }
    });

    // Two-Time Pad
    const ttpC1Input = document.getElementById('ttp-c1-input');
    const ttpC2Input = document.getElementById('ttp-c2-input');
    const ttpBtn = document.getElementById('ttp-btn');
    const ttpResultBox = document.getElementById('ttp-result-box');

    ttpBtn.addEventListener('click', () => {
        try {
            const c1 = ttpC1Input.value.trim();
            const c2 = ttpC2Input.value.trim();
            if (!c1 || !c2) {
                alert('Informe os dois textos cifrados.');
                return;
            }

            const res = CryptanalysisModule.demonstrateTwoTimePad(c1, c2);

            let tableRows = res.steps.map(s => `
                <tr>
                    <td>#${s.index + 1}</td>
                    <td><strong>${s.c1Dec}</strong> (<code>${s.c1Bin}</code>)</td>
                    <td><strong>${s.c2Dec}</strong> (<code>${s.c2Bin}</code>)</td>
                    <td style="color:#c4b5fd; font-weight:bold;">${s.xorDec}</td>
                    <td><code>${s.xorBin}</code></td>
                    <td style="color:var(--success); font-weight:bold;">'${s.xorChar}'</td>
                </tr>
            `).join('');

            ttpResultBox.innerHTML = `
                <div class="alert alert-info" style="margin-bottom:1rem;">
                    <strong style="color:#ffffff; font-size:0.9rem; display:block; margin-bottom:0.25rem;">
                        Prova Prática: A Chave foi Eliminada (K ⊕ K = 0)
                    </strong>
                    <pre style="font-family:var(--font-mono); font-size:0.82rem; white-space:pre-wrap; color:var(--text-secondary);">${res.proofExplanation}</pre>
                </div>
                
                <div style="background:#12131f; border:1px solid #23263b; border-radius:var(--radius-md); padding:0.85rem 1rem; margin-bottom:1rem;">
                    <span style="font-size:0.75rem; color:var(--primary); font-weight:700; text-transform:uppercase;">Resultado Decimal (M1 ⊕ M2):</span>
                    <div style="font-family:var(--font-mono); font-size:1.1rem; color:#ffffff; margin-top:0.2rem;">${res.xorDecimals.join(', ')}</div>
                </div>

                <div class="table-responsive">
                    <table class="custom-table">
                        <thead>
                            <tr>
                                <th>Pos</th>
                                <th>C1 (Dec / Bin)</th>
                                <th>C2 (Dec / Bin)</th>
                                <th>C1 ⊕ C2 (Dec)</th>
                                <th>C1 ⊕ C2 (Bin)</th>
                                <th>Caractere ASCII</th>
                            </tr>
                        </thead>
                        <tbody>${tableRows}</tbody>
                    </table>
                </div>
            `;
        } catch (e) {
            alert('Erro no Two-Time Pad: ' + e.message);
        }
    });

    // -------------------------------------------------------------
    // PRESETS
    // -------------------------------------------------------------
    window.loadPreset = function(type, index) {
        if (type === 'otp') {
            const p = PRESETS.otp[index];
            if (p) {
                switchMode('otp', 'enc');
                otpMsgInput.value = p.message;
                otpKeyInput.value = p.key;
                otpEncBtn.click();
            }
        } else if (type === 'caesar') {
            const p = PRESETS.caesar[index];
            if (p) {
                switchMode('caesar', 'enc');
                caesarMsgInput.value = p.message;
                caesarKeyInput.value = p.k;
                caesarEncBtn.click();
            }
        } else if (type === 'vigenere') {
            const p = PRESETS.vigenere[index];
            if (p) {
                switchMode('vig', 'enc');
                vigMsgInput.value = p.message;
                vigKeyInput.value = p.key;
                updateVigWordCount();
                vigEncBtn.click();
            }
        } else if (type === 'hill') {
            const p = PRESETS.hill[index];
            if (p) {
                switchMode('hill', 'enc');
                hillMsgInput.value = p.message;
                if (p.mode === 'matrix') {
                    document.getElementById('hill-m00').value = p.matrix[0][0];
                    document.getElementById('hill-m01').value = p.matrix[0][1];
                    document.getElementById('hill-m10').value = p.matrix[1][0];
                    document.getElementById('hill-m11').value = p.matrix[1][1];
                } else {
                    hillKeyWord.value = p.keyWord;
                    hillKeyWord.dispatchEvent(new Event('input'));
                }
                checkHillMatrixInvertibility();
                hillEncBtn.click();
            }
        } else if (type === 'cryptanalysis') {
            const p = PRESETS.cryptanalysis[index];
            if (p) {
                bruteInput.value = p.ciphertext;
                bruteBtn.click();
            }
        } else if (type === 'twoTimePad') {
            const p = PRESETS.twoTimePad[index];
            if (p) {
                ttpC1Input.value = p.c1;
                ttpC2Input.value = p.c2;
                ttpBtn.click();
            }
        }
    };

    // Inicialização Limpa
    otpEncBtn.click();
    caesarEncBtn.click();
    vigEncBtn.click();
    hillEncBtn.click();
    bruteBtn.click();
    ttpBtn.click();
});
