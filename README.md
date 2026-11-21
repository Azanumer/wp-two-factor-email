# WP Two-Factor Email

Email one-time-code two-factor authentication for `wp-login.php`. No authenticator app, no TOTP — after a correct password, a 6-digit code is emailed to the user and must be entered to sign in.

## How it works

1. User enters username + password as usual.
2. If 2FA applies to them, the login is paused and a code is emailed to their account address.
3. The user re-submits the login form with the code in the **Security code** field.
4. The code is verified (hashed, expiring, attempt-capped) and the login completes.

## Who gets 2FA

**Settings → Email 2FA**

- **Force for administrators** (default on) — every admin must use a code, no opt-out.
- **Roles that may opt in** — users in these roles see an "Email security code" checkbox on their profile page (default: Administrator, Editor).

## Security details

- Codes are stored only as `wp_hash_password()` hashes — the plain code exists only in the email.
- Codes expire after 10 minutes by default (1–60 configurable).
- After 5 wrong attempts (configurable 1–10) the code is discarded and a fresh one is issued, so guessing is useless.
- Codes are single-use: a correct code is deleted immediately.
- If a code expires, signing in again automatically sends a fresh one.

## Settings

- **Code length** — 4–8 digits (default 6).
- **Code expiry** — minutes (default 10).
- **Wrong-code attempts** — before a fresh code is issued (default 5).

## Requirements

- Your site must actually send email (`wp_mail()`). If mail doesn't work, users can't sign in — test with a password reset email first, or use an SMTP plugin.

## License

MIT — see [LICENSE](LICENSE).
