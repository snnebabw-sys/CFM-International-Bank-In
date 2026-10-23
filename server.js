require("dotenv").config();
const express = require("express");
const path = require("path");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "30kb" }));
app.use("/api", rateLimit({ windowMs: 15 * 60 * 1000, limit: 150, standardHeaders: "draft-7", legacyHeaders: false }));

const { SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY, PORT = 3000 } = process.env;
if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error("Missing SUPABASE_URL, SUPABASE_ANON_KEY, or SUPABASE_SERVICE_ROLE_KEY environment variable.");
  process.exit(1);
}
const adminDb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { autoRefreshToken: false, persistSession: false } });
const authClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, { auth: { autoRefreshToken: false, persistSession: false } });

const fail = (res, status, error) => res.status(status).json({ error });
const clean = (v, max = 120) => typeof v === "string" ? v.trim().slice(0, max) : "";
const validAmount = v => Number.isFinite(Number(v)) && Number(v) > 0 && Math.round(Number(v) * 100) === Number(v) * 100;

async function auth(req, res, next) {
  const match = (req.headers.authorization || "").match(/^Bearer (.+)$/);
  if (!match) return fail(res, 401, "Please sign in.");
  const { data, error } = await authClient.auth.getUser(match[1]);
  if (error || !data.user) return fail(res, 401, "Session expired. Sign in again.");
  const { data: profile, error: profileError } = await adminDb.from("profiles")
    .select("id,full_name,role,status").eq("id", data.user.id).maybeSingle();
  if (profileError || !profile || profile.status !== "active") return fail(res, 403, "Account profile is unavailable.");
  req.user = data.user; req.profile = profile; req.accessToken = match[1]; next();
}
function adminOnly(req, res, next) {
  if (req.profile.role !== "admin") return fail(res, 403, "Administrator permission required.");
  next();
}
app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));

app.get("/api/health", (_req, res) => res.json({ ok: true, mode: "simulation-only" }));

app.post("/api/login", async (req, res) => {
  const email = clean(req.body?.email, 254).toLowerCase();
  const password = typeof req.body?.password === "string" ? req.body.password : "";
  if (!email || !password) return fail(res, 400, "Email and password are required.");
  const { data, error } = await authClient.auth.signInWithPassword({ email, password });
  if (error || !data.session || !data.user) return fail(res, 401, "Invalid email or password.");
  const { data: profile, error: pe } = await adminDb.from("profiles")
    .select("id,full_name,role,status").eq("id", data.user.id).maybeSingle();
  if (pe || !profile || profile.status !== "active") {
    await authClient.auth.signOut();
    return fail(res, 403, "Account profile is not active. Contact the demo administrator.");
  }
  res.json({ access_token: data.session.access_token, profile });
});
app.post("/api/logout", auth, async (req, res) => {
  await authClient.auth.admin; // no admin operation is performed; invalidate client session where supported below
  res.json({ ok: true });
});
app.get("/api/me", auth, (req, res) => res.json({ profile: req.profile }));
app.get("/api/me/account", auth, async (req, res) => {
  if (req.profile.role === "admin") return fail(res, 400, "Admin users do not have a customer account.");
  const { data, error } = await adminDb.from("accounts")
    .select("account_number,full_name,balance,currency,status")
    .eq("owner_id", req.user.id).maybeSingle();
  if (error || !data) return fail(res, 404, "Demo account not found.");
  res.json({ account: data });
});
app.get("/api/transactions", auth, async (req, res) => {
  if (req.profile.role === "admin") return fail(res, 400, "Use the admin dashboard.");
  const { data, error } = await adminDb.rpc("cfm_list_my_transactions", { p_user_id: req.user.id });
  if (error) return fail(res, 500, "Could not load transactions.");
  res.json({ transactions: data || [] });
});
app.post("/api/transfers", auth, async (req, res) => {
  if (req.profile.role !== "customer") return fail(res, 403, "Only customer demo accounts can transfer.");
  const receiver_name = clean(req.body?.receiver_name, 100);
  const receiver_account = clean(req.body?.receiver_account, 24);
  const receiver_country = clean(req.body?.receiver_country, 80);
  const description = clean(req.body?.description, 120);
  const amount = Number(req.body?.amount);
  if (!receiver_name || !/^[A-Za-z0-9-]{6,24}$/.test(receiver_account) || !receiver_country || !validAmount(amount))
    return fail(res, 400, "Enter a valid receiver name, account number, country, and positive amount (maximum two decimals).");
  const { data, error } = await adminDb.rpc("cfm_transfer", {
    p_sender_id: req.user.id, p_receiver_account: receiver_account,
    p_receiver_name: receiver_name, p_receiver_country: receiver_country,
    p_amount: amount, p_description: description || "Demo transfer"
  });
  if (error) return fail(res, 400, error.message.includes("CFM:") ? error.message.replace("CFM:", "").trim() : "Transfer could not be completed.");
  res.json({ receipt: data });
});
app.post("/api/admin/accounts", auth, adminOnly, async (req, res) => {
  const full_name = clean(req.body?.full_name, 100);
  const email = clean(req.body?.email, 254).toLowerCase();
  const phone = clean(req.body?.phone, 30);
  const country = clean(req.body?.country, 80);
  const currency = clean(req.body?.currency, 3).toUpperCase();
  const password = typeof req.body?.password === "string" ? req.body.password : "";
  const initial_balance = Number(req.body?.initial_balance);
  const opening_note = clean(req.body?.opening_note, 120) || "Opening demo balance";
  if (!full_name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !country ||
      !["GBP","NGN","USD","EUR","CAD"].includes(currency) ||
      password.length < 12 || !Number.isFinite(initial_balance) || initial_balance < 0 ||
      Math.round(initial_balance * 100) !== initial_balance * 100) {
    return fail(res, 400, "Check all required fields. Password must be at least 12 characters.");
  }
  const { data: created, error: createError } = await adminDb.auth.admin.createUser({
    email, password, email_confirm: true, user_metadata: { full_name }
  });
  if (createError || !created.user) return fail(res, 400, createError?.message || "Could not create user.");
  const userId = created.user.id;
  const { data: account, error: accountError } = await adminDb.rpc("cfm_create_customer_account", {
    p_user_id: userId, p_full_name: full_name, p_phone: phone, p_country: country,
    p_currency: currency, p_initial_balance: initial_balance, p_opening_note: opening_note,
    p_admin_id: req.user.id
  });
  if (accountError) {
    await adminDb.auth.admin.deleteUser(userId);
    return fail(res, 500, "Could not create demo account. No account was kept.");
  }
  res.status(201).json({ account });
});
app.post("/api/admin/credit", auth, adminOnly, async (req, res) => {
  const account_number = clean(req.body?.account_number, 24);
  const reason = clean(req.body?.reason, 120);
  const amount = Number(req.body?.amount);
  if (!account_number || !reason || !validAmount(amount)) return fail(res, 400, "Enter an account number, reason and valid positive amount.");
  const { data, error } = await adminDb.rpc("cfm_admin_credit", {
    p_admin_id: req.user.id, p_account_number: account_number, p_amount: amount, p_reason: reason
  });
  if (error) return fail(res, 400, error.message.includes("CFM:") ? error.message.replace("CFM:", "").trim() : "Credit failed.");
  res.json({ ok: true, result: data });
});
app.get("/api/admin/accounts", auth, adminOnly, async (_req, res) => {
  const { data, error } = await adminDb.from("accounts")
    .select("account_number,full_name,balance,currency,status,email:profiles!accounts_owner_id_fkey(email)")
    .order("created_at", { ascending: false }).limit(200);
  if (error) return fail(res, 500, "Could not load accounts. Check the SQL setup and foreign key relationship.");
  res.json({ accounts: (data || []).map(a => ({ ...a, email: a.email?.email || "" })) });
});

app.get("*", (req, res, next) => {
  if (req.path.startsWith("/api/")) return fail(res, 404, "API route not found.");
  res.sendFile(path.join(__dirname, "public", "index.html"), err => { if (err) next(err); });
});
app.use((err, _req, res, _next) => {
  console.error("Request failed:", err.message);
  res.status(500).json({ error: "Unexpected server error." });
});
app.listen(PORT, () => console.log(`CFM demo server listening on ${PORT}`));
