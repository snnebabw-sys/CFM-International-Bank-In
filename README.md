# CFM International Bank — Simulation Only

This is an educational simulated banking app. It does not hold, move, or represent real money and is not a licensed bank. Do not use real customer identity documents or present demo receipts as real payment confirmations.

## Files
- `public/index.html` — user interface
- `public/index.css` — styles and CFM logo
- `public/index.js` — login, language selector, customer/admin screens, transfer form, receipt printing
- `server.js` — Express API
- `supabase.sql` — schema, permissions, and atomic database functions
- `package.json` — Render start configuration

## 1. Supabase setup
1. Create a Supabase project.
2. Open SQL Editor and run the full `supabase.sql`.
3. In Authentication > Users, create the administrator user with a strong password and confirm the email.
4. Copy the admin user's UUID. Replace `REPLACE-WITH-ADMIN-USER-UUID` in the final commented SQL snippet in `supabase.sql`, uncomment the insert, and run it. The profile role must be `admin`.
5. In Project Settings > API, copy Project URL, publishable/anon key, and service-role secret. The service-role secret is sensitive and must only be stored in Render environment variables, never in GitHub or frontend code.

## 2. GitHub
Upload this project's files preserving the structure:
- `public/index.html`
- `public/index.css`
- `public/index.js`
- `server.js`
- `package.json`
- `supabase.sql`
- `.gitignore`
- `README.md`

Never upload `.env` or service-role secrets.

## 3. Render
1. Create a **Web Service** from your GitHub repository.
2. Runtime: Node.
3. Build command: `npm install`
4. Start command: `npm start`
5. Add environment variables `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and `SUPABASE_SERVICE_ROLE_KEY`.
6. Deploy and open the Render URL.

## 4. Create customers
Sign in using the admin user created in Supabase. Use the admin dashboard to create customer demo accounts. Customer passwords are temporary demo credentials; share them privately and encourage password changes in a future improvement. Initial balances and all admin credits are simulated.

## Important limitations / next improvements
- The language selector translates the interface labels included in the dictionaries. It is not machine translation of every arbitrary sentence.
- This starter does not include password reset, mandatory password change, email invitation, two-factor authentication, or admin account suspension controls.
- For real-money services, this demo is not suitable; real financial services require licensed infrastructure, security review, and regulatory compliance.
