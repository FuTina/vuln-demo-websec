
# Web Security Demo (SQLi & XSS)

> Intentionally vulnerable endpoints for **educational purposes only**.  
> ⚠️ **Run locally – do NOT expose to the internet.**

This project demonstrates common web vulnerabilities in a modern, simple interface:  
- **SQL Injection** – unsafe string concatenation vs. parameterized queries  
- **Cross-Site Scripting (XSS)** – unsafe `innerHTML` vs. safe `textContent`  
- **Role-based data masking** – User vs Admin view (E-mail & phone)

## 🚀 Quickstart

---
```bash
# Install dependencies
npm install

# Start demo (user role, masked data)
npm start

# Open in browser
http://localhost:5173
```
---

### Admin View (full data)
---
```bash
# macOS/Linux
DEMO_ROLE=admin npm start

# Windows PowerShell
$env:DEMO_ROLE="admin"; npm start

# Windows CMD
set DEMO_ROLE=admin && npm start
```
---

## 📂 Pages

- `/sqli.html` — **SQL Injection**: vulnerable vs safe (parameterized)
- `/xss.html` — **Cross-Site Scripting**: innerHTML vs textContent
- `/users.html` — **Role-based masking** (E-mail & phone masked for normal users)

## 🧠 Feature Explanations

### 🔹 SQL Injection
- **Vulnerable:** Input directly concatenated into SQL → query logic can be manipulated.  
- **Safe:** Parameterized queries (`?`) → input treated as value, not code.  

➡️ *Message:* Always use **Prepared Statements**, never string concatenation.

### 🔹 Cross-Site Scripting (XSS)
- **Vulnerable:** Comments rendered with `innerHTML` → input is executed as HTML/JS.  
- **Safe:** Comments rendered with `textContent` → input is neutral text.  

➡️ *Message:* Avoid unsafe `innerHTML`. Use escaping, safe template engines, and Content-Security-Policy (CSP).

### 🔹 Role-based Data Masking
- **User Role:** Masked data (e.g., `al***@example.com`, `••••••22`).  
- **Admin Role:** Full data visible.  

➡️ *Message:* Access to sensitive data should be controlled via **roles & permissions**, not via vulnerabilities.

## 🎤 Demo Flow (3–5 minutes)

1. **SQL Injection**  
   - Open `/sqli.html`.  
   - Search for `Alice` → show query in *vulnerable* vs. *safe* mode.  
   - Try SQLi (x' OR 1=1--)
   - Concatenation vs. parametrization.

2. **Users (Masking)**  
   - Open `/users.html`.  
   - Default (user): E-mail & phone masked.  
   - Restart server with `DEMO_ROLE=admin` → Admin sees full fields.  
   - Sensitive data access is about **authorization**, not exploits.

3. **Cross-Site Scripting**  
   - Open `/xss.html`.  
   - Post a comment → left (vulnerable) interprets HTML, right (safe) shows plain text.  
   - Test a html input: `<b>Wichtiger Text!</b><span style="color:red">Achtung</span>` or: `<img src="x" onerror="alert('XSS')" alt="Bild nicht gefunden">` or: `<a href="https://example.com">Klick mich</a>`
   - `innerHTML` vs. `textContent`.

## ⚠️ Notes
- This project is for **learning/demo purposes** only.  
- Contains intentionally vulnerable endpoints.  
- Do **not** deploy publicly, use only locally/in isolated environments.
