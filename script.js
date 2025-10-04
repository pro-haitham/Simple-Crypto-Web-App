// script.js - handles UI and ciphers (vanilla JS)

// ---------- Navigation ----------
document.querySelectorAll('nav button').forEach(b=>{
b.addEventListener('click',()=> {
document.querySelectorAll('.panel').forEach(p=>p.hidden = true);
document.getElementById(b.dataset.target).hidden = false;
});
});
// default view
document.getElementById('ciphers').hidden = false;

// ---------- Caesar Cipher ----------
function caesarShift(str, shift, decrypt=false){
shift = parseInt(shift) || 0;
if(decrypt) shift = (26 - (shift % 26)) % 26;
return str.split('').map(ch=>{
const code = ch.charCodeAt(0);
if(code >= 65 && code <= 90) {
return String.fromCharCode(((code - 65 + shift) % 26) + 65);
}
if(code >= 97 && code <= 122) {
return String.fromCharCode(((code - 97 + shift) % 26) + 97);
}
return ch;
}).join('');
}
document.getElementById('caesar-go').onclick = ()=>{
const txt = document.getElementById('caesar-input').value;
const shift = document.getElementById('caesar-shift').value;
const mode = document.getElementById('caesar-mode').value;
const out = caesarShift(txt, shift, mode === 'decrypt');
document.getElementById('caesar-output').value = out;
};

// ---------- Vigenère Cipher ----------
function vigenere(text, key, decrypt=false){
if(!key) return text;
key = key.replace(/[^A-Za-z]/g,'').toLowerCase();
let ki = 0;
return text.split('').map(ch=>{
const isUpper = ch >= 'A' && ch <= 'Z';
const isLower = ch >= 'a' && ch <= 'z';
if(!isUpper && !isLower) return ch;
const base = isUpper ? 65 : 97;
const tIdx = ch.charCodeAt(0) - base;
const k = key[ki % key.length].charCodeAt(0) - 97;
const shift = decrypt ? (26 - k) : k;
ki++;
return String.fromCharCode((tIdx + shift) % 26 + base);
}).join('');
}
document.getElementById('vigenere-go').onclick = ()=>{
const txt = document.getElementById('vigenere-input').value;
const key = document.getElementById('vigenere-key').value;
const mode = document.getElementById('vigenere-mode').value;
document.getElementById('vigenere-output').value = vigenere(txt, key, mode === 'decrypt');
};

// ---------- Playfair Cipher ----------
function buildPlayfairSquare(key){
key = (key || '').toUpperCase().replace(/[^A-Z]/g,'').replace(/J/g,'I');
const used = {};
const arr = [];
for(const ch of key){
if(!used[ch]){ used[ch]=true; arr.push(ch); }
}
for(let c=65;c<=90;c++){
const ch = String.fromCharCode(c);
if(ch === 'J') continue;
if(!used[ch]){ used[ch]=true; arr.push(ch); }
}
// 5x5 as array
return arr;
}
function playfairProcess(text, key, decrypt=false){
if(!key) return text;
let sq = buildPlayfairSquare(key);
// prepare text: uppercase, remove non letters, J->I
text = text.toUpperCase().replace(/[^A-Z]/g,'').replace(/J/g,'I');
// split into digrams with filler 'X'
let digrams = [];
for(let i=0;i<text.length;i++){
let a = text[i];
let b = text[i+1] || '';
if(b === ''){ digrams.push(a+'X'); }
else if(a === b){ digrams.push(a+'X'); }
else { digrams.push(a+b); i++; }
}
// helper index
function idx(ch){ const pos = sq.indexOf(ch); return [Math.floor(pos/5), pos%5]; }
function charAt(r,c){ return sq[r*5 + c]; }
// process pairs
const res = digrams.map(pair=>{
let [a,b] = pair.split('');
let [ar,ac] = idx(a), [br,bc] = idx(b);
if(ar === br){
// same row
if(decrypt){ ac = (ac+4)%5; bc = (bc+4)%5; } else { ac = (ac+1)%5; bc = (bc+1)%5; }
return charAt(ar,ac) + charAt(br,bc);
} else if(ac === bc){
// same column
if(decrypt){ ar = (ar+4)%5; br = (br+4)%5; } else { ar = (ar+1)%5; br = (br+1)%5; }
return charAt(ar,ac) + charAt(br,bc);
} else {
return charAt(ar,bc) + charAt(br,ac);
}
}).join('');
return res;
}
document.getElementById('playfair-go').onclick = ()=>{
const txt = document.getElementById('playfair-input').value;
const key = document.getElementById('playfair-key').value;
const mode = document.getElementById('playfair-mode').value;
document.getElementById('playfair-output').value = playfairProcess(txt, key, mode === 'decrypt');
};

// ---------- Password Strength Analyzer ----------
const commonPasswords = [
'123456','password','123456789','qwerty','12345678','111111','1234567','dragon','letmein'
];

function estimateCrackTime(password){
// rough charset estimate
let charset = 0;
if(/[a-z]/.test(password)) charset += 26;
if(/[A-Z]/.test(password)) charset += 26;
if(/[0-9]/.test(password)) charset += 10;
if(/[^A-Za-z0-9]/.test(password)) charset += 32; // punctuation approx
if(charset === 0) charset = 1;
const combos = Math.pow(charset, password.length);
// guesses per second for attacker (conservative - high GPU): 1e9
const guessesPerSecond = 1e9;
const seconds = combos / guessesPerSecond;
return seconds;
}
function humanTime(seconds){
if(seconds < 1) return 'less than 1 second';
const units = [
['year', 31536000],
['day', 86400],
['hour', 3600],
['minute', 60],
['second', 1]
];
let out = [];
for(const [name,sec] of units){
if(seconds >= sec){
const val = Math.floor(seconds / sec);
seconds -= val * sec;
out.push(val + ' ' + name + (val>1? 's':''));
if(out.length >= 2) break;
}
}
return out.join(', ');
}
document.getElementById('pwd-check').onclick = ()=>{
const p = document.getElementById('password-input').value || '';
const results = document.getElementById('pwd-results');
const scoreEl = document.getElementById('pwd-score');
const strengthEl = document.getElementById('pwd-strength');
const bar = document.getElementById('pwd-bar-fill');
const estimateEl = document.getElementById('pwd-estimate');
const notesEl = document.getElementById('pwd-notes');

// simple scoring
let score = 0;
if(p.length >= 8) score += 1;
if(p.length >= 12) score += 1;
if(/[A-Z]/.test(p)) score += 1;
if(/[0-9]/.test(p)) score += 1;
if(/[^A-Za-z0-9]/.test(p)) score += 1;
if(commonPasswords.includes(p)) score = 0;

const strength = score <= 1 ? 'Weak' : (score <= 3 ? 'Medium' : 'Strong');
scoreEl.textContent = 'Score: ' + score + ' / 5';
strengthEl.textContent = 'Strength: ' + strength;
const percent = Math.min(100, (score/5)*100);
bar.style.width = percent + '%';

// crack estimate
const secs = estimateCrackTime(p);
estimateEl.textContent = 'Crack time estimate (approx): ' + humanTime(secs);

// notes
let notes = [];
if(commonPasswords.includes(p)) notes.push('Password is a top common password — do NOT use.');
if(p.length < 8) notes.push('Password is short — aim for 12+ characters.');
if(!(/[A-Z]/.test(p) && /[0-9]/.test(p) && /[^A-Za-z0-9]/.test(p))) notes.push('Use mix of upper, lower, numbers, and symbols for better security.');
notesEl.textContent = notes.join(' ');
};

// allow Enter to check password
document.getElementById('password-input').addEventListener('keydown', e=>{
if(e.key === 'Enter'){ e.preventDefault(); document.getElementById('pwd-check').click(); }
});
// Password Generator
function generatePassword(length, useUpper, useLower, useNumbers, useSymbols) {
  const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const lower = "abcdefghijklmnopqrstuvwxyz";
  const numbers = "0123456789";
  const symbols = "!@#$%^&*()-_=+[]{};:,.<>?";

  let chars = "";
  if (useUpper) chars += upper;
  if (useLower) chars += lower;
  if (useNumbers) chars += numbers;
  if (useSymbols) chars += symbols;

  if (!chars) return "";

  let password = "";
  for (let i = 0; i < length; i++) {
    password += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return password;
}

document.getElementById("generate-password").addEventListener("click", () => {
  const length = parseInt(document.getElementById("gen-length").value);
  const useUpper = document.getElementById("gen-uppercase").checked;
  const useLower = document.getElementById("gen-lowercase").checked;
  const useNumbers = document.getElementById("gen-numbers").checked;
  const useSymbols = document.getElementById("gen-symbols").checked;

  const pwd = generatePassword(length, useUpper, useLower, useNumbers, useSymbols);
  document.getElementById("generated-password").value = pwd;
});

document.getElementById("copy-password").addEventListener("click", () => {
  const pwdField = document.getElementById("generated-password");
  pwdField.select();
  pwdField.setSelectionRange(0, 99999); // For mobile
  document.execCommand("copy");
  alert("Password copied to clipboard!");
});

// Password Manager SPA
const pmForm = document.getElementById('manager-form');
const viewBtn = document.getElementById('view-passwords');
const tableBody = document.querySelector('#pm-table tbody');
const generateBtn = document.getElementById('generate-pwd');

function generatePassword(length = 12){
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>?";
  let pwd = "";
  for(let i=0;i<length;i++) pwd += chars.charAt(Math.floor(Math.random()*chars.length));
  return pwd;
}

generateBtn.addEventListener('click',()=>{
  const pwdInput = document.getElementById('pm-password');
  pwdInput.value = generatePassword(16);
});

// Save password
pmForm.addEventListener('submit', e => {
  e.preventDefault();
  const master = document.getElementById('master-password').value;
  const site = document.getElementById('pm-site').value;
  const password = document.getElementById('pm-password').value;

  fetch('password_manager.php', {
    method: 'POST',
    body: JSON.stringify({action:'save', master, site, password})
  })
  .then(res=>res.json())
  .then(res=>{
    alert(res.message);
    pmForm.reset();
    loadPasswords(master);
  });
});

// Load passwords
function loadPasswords(master){
  fetch('password_manager.php',{
    method:'POST',
    body: JSON.stringify({action:'view', master})
  })
  .then(res=>res.json())
  .then(res=>{
    tableBody.innerHTML = '';
    if(res.entries){
      for(const site in res.entries){
        const row = document.createElement('tr');
        row.innerHTML = `
          <td>${site}</td>
          <td>${res.entries[site].hash}</td>
          <td><input type="password" value="${res.entries[site].password}" readonly class="pwd-field"></td>
          <td>
            <button class="action-btn show-btn">Show</button>
            <button class="action-btn copy-btn">Copy</button>
            <button class="action-btn delete-btn">Delete</button>
          </td>`;
        tableBody.appendChild(row);

        const pwdField = row.querySelector('.pwd-field');
        row.querySelector('.show-btn').addEventListener('click',()=> {
          if(pwdField.type === 'password') pwdField.type='text';
          else pwdField.type='password';
        });
        row.querySelector('.copy-btn').addEventListener('click',()=> {
          pwdField.select();
          document.execCommand('copy');
          alert('Password copied!');
        });
        row.querySelector('.delete-btn').addEventListener('click', ()=>{
          if(confirm(`Delete password for ${site}?`)){
            fetch('password_manager.php',{
              method:'POST',
              body: JSON.stringify({action:'delete', master, site})
            }).then(res=>res.json()).then(r=>loadPasswords(master));
          }
        });
      }
    }
  });
}

// View passwords button
viewBtn.addEventListener('click', ()=>{
  const master = document.getElementById('master-password').value;
  loadPasswords(master);
});
// ---------- Vault with Master Password Encryption ----------

let vaultItems = JSON.parse(localStorage.getItem('vaultItems')) || [];

// ---------- Crypto Helpers ----------
async function getKey(master) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        enc.encode(master),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: enc.encode('vault_salt'),
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptData(data, master) {
    const key = await getKey(master);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        enc.encode(data)
    );
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encrypted), iv.length);
    return btoa(String.fromCharCode(...combined));
}

async function decryptData(data, master) {
    try {
        const combined = Uint8Array.from(atob(data), c => c.charCodeAt(0));
        const iv = combined.slice(0, 12);
        const encrypted = combined.slice(12);
        const key = await getKey(master);
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            encrypted
        );
        return new TextDecoder().decode(decrypted);
    } catch {
        return null;
    }
}

// ---------- Utility ----------
function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(2) + ' KB';
    return (bytes / 1048576).toFixed(2) + ' MB';
}

// ---------- Render Vault ----------
async function renderVault() {
    const tbody = document.querySelector("#vault-table tbody");
    tbody.innerHTML = "";
    vaultItems.forEach((item, index) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td>${item.name}</td>
            <td>${item.type}</td>
            <td>${item.size}</td>
            <td>
                <button onclick="viewVaultItem(${index})">👁 View / Download</button>
                <button onclick="deleteVaultItem(${index})">🗑 Delete</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

// ---------- Add Note ----------
document.getElementById("vault-add-note").addEventListener("click", async () => {
    const note = document.getElementById("vault-note").value.trim();
    const master = document.getElementById("vault-master").value.trim();
    if (!note || !master) return alert("Enter note and master password");

    const encrypted = await encryptData(note, master);
    vaultItems.push({
        name: "Note " + (vaultItems.length + 1),
        type: "note",
        size: note.length + " chars",
        content: encrypted
    });
    localStorage.setItem("vaultItems", JSON.stringify(vaultItems));
    document.getElementById("vault-note").value = "";
    renderVault();
});

// ---------- Add File ----------
document.getElementById("vault-form").addEventListener("submit", async e => {
    e.preventDefault();
    const fileInput = document.getElementById("vault-file");
    const master = document.getElementById("vault-master").value.trim();
    if (!fileInput.files.length || !master) return alert("Select file and enter master password");

    const file = fileInput.files[0];
    const reader = new FileReader();
    reader.onload = async () => {
        const encrypted = await encryptData(reader.result, master);
        vaultItems.push({
            name: file.name,
            type: "file",
            size: formatSize(file.size),
            content: encrypted
        });
        localStorage.setItem("vaultItems", JSON.stringify(vaultItems));
        fileInput.value = "";
        renderVault();
    };
    reader.readAsBinaryString(file);
});

// ---------- View / Download Item ----------
async function viewVaultItem(index) {
    const item = vaultItems[index];
    const master = document.getElementById("vault-master").value.trim();
    if (!master) return alert("Enter master password!");

    const decrypted = await decryptData(item.content, master);
    if (!decrypted) return alert("Wrong master password or corrupted item!");

    if (item.type === "note" || item.name.endsWith(".txt") || item.name.endsWith(".js") || item.name.endsWith(".html") || item.name.endsWith(".css")) {
        const preview = document.createElement("textarea");
        preview.value = decrypted;
        preview.readOnly = true;
        preview.style.width = "100%";
        preview.style.height = "300px";

        const modal = document.createElement("div");
        modal.style.position = "fixed";
        modal.style.top = "50%";
        modal.style.left = "50%";
        modal.style.transform = "translate(-50%, -50%)";
        modal.style.background = "#fff";
        modal.style.border = "2px solid #000";
        modal.style.padding = "10px";
        modal.style.zIndex = 9999;
        modal.style.maxWidth = "90%";
        modal.style.maxHeight = "90%";
        modal.style.overflow = "auto";

        const closeBtn = document.createElement("button");
        closeBtn.textContent = "Close";
        closeBtn.style.marginBottom = "10px";
        closeBtn.onclick = () => document.body.removeChild(modal);

        modal.appendChild(closeBtn);
        modal.appendChild(preview);
        document.body.appendChild(modal);
    } else {
        const blob = new Blob([decrypted], { type: "application/octet-stream" });
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = item.name;
        link.click();
    }
}

// ---------- Delete Item ----------
function deleteVaultItem(index) {
    if (confirm("Delete this item?")) {
        vaultItems.splice(index, 1);
        localStorage.setItem("vaultItems", JSON.stringify(vaultItems));
        renderVault();
    }
}

// ---------- Initial Render ----------
renderVault();

