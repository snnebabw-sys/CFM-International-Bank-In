
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.set("trust proxy", 1);
const PORT = process.env.PORT || 3000;

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "30kb" }));

// Set ALLOWED_ORIGINS in Render to your exact GitHub Pages origin,
// e.g. https://YOUR-USERNAME.github.io
// Add a second comma-separated origin only if you use another frontend.
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((origin) => origin.trim().replace(/\/$/, ""))
  .filter(Boolean);

app.use((req, res, next) => {
  const origin = (req.headers.origin || "").replace(/\/$/, "");

  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Authorization, Content-Type"
    );
    res.setHeader(
      "Access-Control-Allow-Methods",
      "GET, POST, PATCH, DELETE, OPTIONS"
    );
  } else if (origin) {
    return res.status(403).json({ error: "Origin not allowed." });
  }

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

app.use(
  "/api",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 150,
    standardHeaders: "draft-7",
    legacyHeaders: false,
  })
);

const {
  SUPABASE_URL,
  SUPABASE_ANON_KEY,
  SUPABASE_SERVICE_ROLE_KEY,
} = process.env;

if (
  !SUPABASE_URL ||
  !SUPABASE_ANON_KEY ||
  !SUPABASE_SERVICE_ROLE_KEY
) {
  console.error("Required Supabase environment variables are missing.");
  process.exit(1);
}

const adminDb = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

const authClient = createClient(
  SUPABASE_URL,
  SUPABASE_ANON_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

const fail = (res, status, error) => res.status(status).json({ error });

const clean = (value, max = 120) =>
  typeof value === "string" ? value.trim().slice(0, max) : "";

const validAmount = (value) =>
  Number.isFinite(Number(value)) &&
  Number(value) > 0 &&
  Math.round(Number(value) * 100) === Number(value) * 100;

// Authentication: validate the Supabase token and active profile.
async function auth(req, res, next) {
  try {
    const match = (req.headers.authorization || "").match(/^Bearer (.+)$/);

    if (!match) return fail(res, 401, "Please sign in.");

    const { data, error } = await authClient.auth.getUser(match[1]);

    if (error || !data.user) {
      return fail(res, 401, "Session expired. Please sign in again.");
    }

    const { data: profile, error: profileError } = await adminDb
      .from("profiles")
      .select("id,full_name,role,status")
      .eq("id", data.user.id)
      .maybeSingle();

    if (profileError || !profile || profile.status !== "active") {
      return fail(res, 403, "Account profile is unavailable or inactive.");
    }

    req.user = data.user;
    req.profile = profile;
    next();
  } catch (error) {
    next(error);
  }
}

function adminOnly(req, res, next) {
  if (req.profile.role !== "admin") {
    return fail(res, 403, "Administrator permission required.");
  }
  next();
}

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, mode: "simulation-only" });
});

// Sign in for customer and administrator accounts.
app.post("/api/login", async (req, res, next) => {
  try {
    const email = clean(req.body?.email, 254).toLowerCase();
    const password =
      typeof req.body?.password === "string" ? req.body.password : "";

    if (!email || !password) {
      return fail(res, 400, "Email and password are required.");
    }

    const { data, error } = await authClient.auth.signInWithPassword({
      email,
      password,
    });

    if (error || !data.session || !data.user) {
      return fail(res, 401, "Invalid email or password.");
    }

    const { data: profile, error: profileError } = await adminDb
      .from("profiles")
      .select("id,full_name,role,status")
      .eq("id", data.user.id)
      .maybeSingle();

    if (profileError || !profile || profile.status !== "active") {
      return fail(res, 403, "Account profile is not active.");
    }

    res.json({
      access_token: data.session.access_token,
      profile,
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/logout", auth, (_req, res) => {
  // The frontend must discard its stored access token on logout.
  res.json({ ok: true });
});

app.get("/api/me", auth, (req, res) => {
  res.json({ profile: req.profile });
});

// Customer's own simulated account.
app.get("/api/me/account", auth, async (req, res, next) => {
  try {
    if (req.profile.role !== "customer") {
      return fail(res, 403, "Customer account required.");
    }

    const { data, error } = await adminDb
      .from("accounts")
      .select("account_number,full_name,balance,currency,status")
      .eq("owner_id", req.user.id)
      .maybeSingle();

    if (error) return fail(res, 500, "Could not load account.");
    if (!data) return fail(res, 404, "Demo account not found.");

    res.json({ account: data });
  } catch (error) {
    next(error);
  }
});

app.get("/api/transactions", auth, async (req, res, next) => {
  try {
    if (req.profile.role !== "customer") {
      return fail(res, 403, "Customer account required.");
    }

    const { data, error } = await adminDb.rpc(
      "cfm_list_my_transactions",
      { p_user_id: req.user.id }
    );

    if (error) {
      console.error("Transaction query failed:", error.message);
      return fail(res, 500, "Could not load transactions.");
    }

    res.json({ transactions: data || [] });
  } catch (error) {
    next(error);
  }
});

// Existing simulated transfer function.
app.post("/api/transfers", auth, async (req, res, next) => {
  try {
    if (req.profile.role !== "customer") {
      return fail(res, 403, "Customer demo account required.");
    }

    const receiver_name = clean(req.body?.receiver_name, 100);
    const receiver_account = clean(req.body?.receiver_account, 24);
    const receiver_country = clean(req.body?.receiver_country, 80);
    const description = clean(req.body?.description, 120);
    const amount = Number(req.body?.amount);

    if (
      !receiver_name ||
      !/^[A-Za-z0-9-]{6,24}$/.test(receiver_account) ||
      !receiver_country ||
      !validAmount(amount)
    ) {
      return fail(res, 400, "Enter valid transfer details and amount.");
    }

    const { data, error } = await adminDb.rpc("cfm_transfer", {
      p_sender_id: req.user.id,
      p_receiver_account: receiver_account,
      p_receiver_name: receiver_name,
      p_receiver_country: receiver_country,
      p_amount: amount,
      p_description: description || "Demo transfer",
    });

    if (error) {
      console.error("Demo transfer failed:", error.message);
      return fail(res, 400, "Demo transfer could not be completed.");
    }

    res.json({ receipt: data });
  } catch (error) {
    next(error);
  }
});

// ADMIN: list simulated customer accounts.
// Uses separate queries to avoid relying on a guessed Supabase join name.
app.get("/api/admin/accounts", auth, adminOnly, async (_req, res, next) => {
  try {
    const { data: accounts, error } = await adminDb
      .from("accounts")
      .select("owner_id,account_number,full_name,balance,currency,status")
      .order("created_at", { ascending: false })
      .limit(200);

    if (error) {
      console.error("Account list failed:", error.message);
      return fail(res, 500, "Could not load accounts. Check your accounts schema.");
    }

    const ids = [...new Set((accounts || []).map((a) => a.owner_id).filter(Boolean))];
    let profiles = [];

    if (ids.length) {
      const result = await adminDb
        .from("profiles")
        .select("id,full_name,status")
        .in("id", ids);

      if (result.error) {
        return fail(res, 500, "Could not load customer profile details.");
      }
      profiles = result.data || [];
    }

    const byId = new Map(profiles.map((p) => [p.id, p]));

    res.json({
      accounts: (accounts || []).map((account) => ({
        ...account,
        customer_status: byId.get(account.owner_id)?.status || "unknown",
      })),
    });
  } catch (error) {
    next(error);
  }
});

// ADMIN: create customer login and simulated account using your existing RPC.
app.post("/api/admin/accounts", auth, adminOnly, async (req, res, next) => {
  let newUserId;

  try {
    const full_name = clean(req.body?.full_name, 100);
    const email = clean(req.body?.email, 254).toLowerCase();
    const phone = clean(req.body?.phone, 30);
    const country = clean(req.body?.country, 80);
    const currency = clean(req.body?.currency, 3).toUpperCase();
    const password = typeof req.body?.password === "string" ? req.body.password : "";
    const initial_balance = Number(req.body?.initial_balance);
    const opening_note = clean(req.body?.opening_note, 120) || "Opening demo balance";

    if (
      !full_name ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      !country ||
      !["GBP", "NGN", "USD", "EUR", "CAD"].includes(currency) ||
      password.length < 12 ||
      !Number.isFinite(initial_balance) ||
      initial_balance < 0 ||
      Math.round(initial_balance * 100) !== initial_balance * 100
    ) {
      return fail(res, 400, "Check the fields. Use a password of at least 12 characters and a valid non-negative balance.");
    }

    const { data: created, error: createError } =
      await adminDb.auth.admin.createUser({
        email,
        password,
        email_confirm: true,
        user_metadata: { full_name },
      });

    if (createError || !created.user) {
      return fail(res, 400, createError?.message || "Could not create customer login.");
    }

    newUserId = created.user.id;

    const { data: account, error: accountError } = await adminDb.rpc(
      "cfm_create_customer_account",
      {
        p_user_id: newUserId,
        p_full_name: full_name,
        p_phone: phone,
        p_country: country,
        p_currency: currency,
        p_initial_balance: initial_balance,
        p_opening_note: opening_note,
        p_admin_id: req.user.id,
      }
    );

    if (accountError) {
      console.error("Customer account RPC failed:", accountError.message);
      // Try cleanup if account creation failed.
      await adminDb.auth.admin.deleteUser(newUserId).catch(() => {});
      return fail(res, 500, "Account setup failed. Check the required Supabase SQL function.");
    }

    newUserId = null;
    res.status(201).json({ ok: true, account });
  } catch (error) {
    if (newUserId) {
      await adminDb.auth.admin.deleteUser(newUserId).catch(() => {});
    }
    next(error);
  }
});

// ADMIN: credit simulated balance using your existing RPC.
app.post("/api/admin/credit", auth, adminOnly, async (req, res, next) => {
  try {
    const account_number = clean(req.body?.account_number, 24);
    const reason = clean(req.body?.reason, 120);
    const amount = Number(req.body?.amount);

    if (!account_number || !reason || !validAmount(amount)) {
      return fail(res, 400, "Enter an account number, reason and valid positive amount.");
    }

    const { data, error } = await adminDb.rpc("cfm_admin_credit", {
      p_admin_id: req.user.id,
      p_account_number: account_number,
      p_amount: amount,
      p_reason: reason,
    });

    if (error) {
      console.error("Simulated credit failed:", error.message);
      return fail(res, 400, "Simulated credit failed. Check the RPC and account number.");
    }

    res.json({ ok: true, result: data });
  } catch (error) {
    next(error);
  }
});

// ADMIN: suspend/restore a customer by account number.
app.patch("/api/admin/accounts/:accountNumber/status", auth, adminOnly, async (req, res, next) => {
  try {
    const accountNumber = clean(req.params.accountNumber, 24);
    const status = clean(req.body?.status, 20);

    if (!accountNumber || !["active", "suspended"].includes(status)) {
      return fail(res, 400, "Provide a valid account number and status.");
    }

    const { data: account, error: accountError } = await adminDb
      .from("accounts")
      .select("owner_id")
      .eq("account_number", accountNumber)
      .maybeSingle();

    if (accountError) return fail(res, 500, "Could not look up account.");
    if (!account) return fail(res, 404, "Account not found.");

    const { data: targetProfile, error: profileError } = await adminDb
      .from("profiles")
      .select("id,role")
      .eq("id", account.owner_id)
      .maybeSingle();

    if (profileError || !targetProfile) return fail(res, 404, "Customer profile not found.");
    if (targetProfile.role !== "customer") return fail(res, 403, "Only customer accounts can be changed.");

    const { error: updateError } = await adminDb
      .from("profiles")
      .update({ status })
      .eq("id", targetProfile.id);

    if (updateError) {
      console.error("Profile status update failed:", updateError.message);
      return fail(res, 500, "Could not update customer status.");
    }

    res.json({ ok: true, account_number: accountNumber, status });
  } catch (error) {
    next(error);
  }
});

// ADMIN: delete a customer login.
// Database foreign keys must permit deleting the user and related demo records.
// Test this only with disposable simulation accounts.
app.delete("/api/admin/accounts/:accountNumber", auth, adminOnly, async (req, res, next) => {
  try {
    const accountNumber = clean(req.params.accountNumber, 24);

    const { data: account, error: accountError } = await adminDb
      .from("accounts")
      .select("owner_id,account_number")
      .eq("account_number", accountNumber)
      .maybeSingle();

    if (accountError) return fail(res, 500, "Could not look up account.");
    if (!account) return fail(res, 404, "Account not found.");

    const { data: targetProfile, error: profileError } = await adminDb
      .from("profiles")
      .select("id,role")
      .eq("id", account.owner_id)
      .maybeSingle();

    if (profileError || !targetProfile) return fail(res, 404, "Customer profile not found.");
    if (targetProfile.role !== "customer") return fail(res, 403, "Admin accounts cannot be deleted here.");

    const { error: deleteError } = await adminDb.auth.admin.deleteUser(targetProfile.id);

    if (deleteError) {
      console.error("Customer deletion failed:", deleteError.message);
      return fail(res, 500, "Deletion failed. Check database foreign-key constraints and cleanup rules.");
    }

    res.json({ ok: true, message: "Customer login deleted. Verify related demo records are removed by your database rules." });
  } catch (error) {
    next(error);
  }
});

// API-only backend: do not try to serve index.html from this repository.
app.use((req, res) => {
  if (req.path.startsWith("/api/")) {
    return fail(res, 404, "API route not found.");
  }
  res.status(404).json({ error: "This server provides API endpoints only." });
});

app.use((error, _req, res, _next) => {
  console.error("Request failed:", error.message);
  if (res.headersSent) return;
  res.status(500).json({ error: "Unexpected server error." });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`CFM simulation API listening on port ${PORT}`);
});
