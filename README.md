# Simple system login with TOTP

A complete example of a secure user authentication and account management system written in pure PHP.

Includes:
- user login and registration with 2FA verification (TOTP, e.g., Google Authenticator),
- backup codes and 2FA reset,
- password reset via one-time email link,
- trusted devices (skip TOTP on recognized browsers),
- security logs and login history,
- rate limiting for login attempts,
- encrypted TOTP secrets,
- CSRF protection on all forms.

---

## 🔧 Configuration

1. Copy the files to your web server directory.  
2. In `config.php`:
   - set your database connection (`$pdo`),
   - set your custom TOTP encryption key:
     ```php
     const TOTP_ENC_KEY = 'PASTE_YOUR_BASE64_32_BYTES_KEY_HERE';
     ```
     (generate with `base64_encode(random_bytes(32))`)
3. In `forgot_password.php`, update your reset link:
   ```php
   $resetLink = 'https://your-domain.com/reset_password.php?token=' . urlencode($rawToken);
   ```
4. Make sure your server uses HTTPS (required for trusted devices).  
5. Open `register.php` in your browser to create the first account.

---

## 🚀 Usage

After registration, log in via `login.php`.  
The system will prompt for a TOTP or a backup code.  
Once logged in, you can manage your password, 2FA, and trusted devices.

---

## 📁 Main Files

| File | Description |
|------|--------------|
| `register.php` | User registration + initial TOTP setup |
| `login.php` | Login (password + TOTP) |
| `totp.php` | TOTP or backup code verification |
| `totp_setup.php` | Reconfigure TOTP |
| `trusted_devices.php` | List and manage trusted devices |
| `forgot_password.php` / `reset_password.php` | Password reset via email |
| `change_password.php` | Change password (after login) |
| `dashboard.php` | Example protected page |
| `functions.php` | Common helper functions (TOTP, encryption, rate limit, logs) |
| `config.php` | Configuration and database connection |

---

## ⚙️ Requirements

- PHP 8.0+
- MySQL / MariaDB
- `openssl` extension enabled
- HTTPS web server (recommended)
- Working `mail()` function or SMTP setup

---

## 🧩 License

Released under the **MIT License**.  
You are free to use, modify, and distribute it in both personal and commercial projects.
