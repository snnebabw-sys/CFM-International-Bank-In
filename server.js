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
app.use(express.json({ limit: "10mb" }));

// ====================== CORS ======================
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((origin) => origin.trim().replace(/\/$/, ""))
  .filter(Boolean);

app.use((req, res, next) => {
  const origin = (req.headers.origin || "").replace(/\/$/, "");

  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
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

// ====================== SUPABASE ======================
const {
  SUPABASE_URL,
  SUPABASE_ANON_KEY,
  SUPABASE_SERVICE_ROLE_KEY,
} = process.env;

if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error("Required Supabase environment variables are missing.");
  process.exit(1);
}

const adminDb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});

const authClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});

const fail = (res, status, error) => res.status(status).json({ error });

const clean = (value, max = 120) =>
  typeof value === "string" ? value.trim().slice(0, max) : "";

const validAmount = (value) =>
  Number.isFinite(Number(value)) &&
  Number(value) > 0 &&
  Math.round(Number(value) * 100) === Number(value) * 100;

// ====================== AUTH MIDDLEWARE ======================
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
      .select("id,full_name,role,status,avatar_url")
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

// ====================== ROUTES ======================

app.get("/api/health", (_req, res) => {
  res.json({ ok: true });
});

// LOGIN
app.post("/api/login", async (req, res, next) => {
  try {
    const email = clean(req.body?.email, 254).toLowerCase();
    const password = typeof req.body?.password === "string" ? req.body.password : "";

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
      .select("id,full_name,role,status,avatar_url")
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
  res.json({ ok: true });
});

app.get("/api/me", auth, (req, res) => {
  res.json({ profile: req.profile });
});

// CUSTOMER ACCOUNT
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
    if (!data) return fail(res, 404, "Account not found.");

    res.json({
      account: {
        ...data,
        avatar_url: req.profile.avatar_url || null,
      },
    });
  } catch (error) {
    next(error);
  }
});

// TRANSACTIONS
app.get("/api/transactions", auth, async (req, res, next) => {
  try {
    if (req.profile.role !== "customer") {
      return fail(res, 403, "Customer account required.");
    }

    const { data, error } = await adminDb.rpc("cfm_list_my_transactions", {
      p_user_id: req.user.id,
    });

    if (error) {
      console.error("Transaction query failed:", error.message);
      return fail(res, 500, "Could not load transactions.");
    }

    res.json({ transactions: data || [] });
  } catch (error) {
    next(error);
  }
});

// TRANSFER
app.post("/api/transfers", auth, async (req, res, next) => {
  try {
    if (req.profile.role !== "customer") {
      return fail(res, 403, "Customer account required.");
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
      p_description: description || "Transfer",
    });

    if (error) {
      console.error("Transfer failed:", error.message);
      return fail(res, 400, "Transfer could not be completed.");
    }

    res.json({ receipt: data });
  } catch (error) {
    next(error);
  }
});

// ====================== ADMIN ======================

// LIST ACCOUNTS
app.get("/api/admin/accounts", auth, adminOnly, async (_req, res, next) => {
  try {
    const { data: accounts, error } = await adminDb
      .from("accounts")
      .select("owner_id,account_number,full_name,balance,currency,status")
      .order("created_at", { ascending: false })
      .limit(200);

    if (error) {
      return fail(res, 500, "Could not load accounts.");
    }

    const ids = [...new Set((accounts || []).map((a) => a.owner_id).filter(Boolean))];
    let profiles = [];

    if (ids.length) {
      const result = await adminDb
        .from("profiles")
        .select("id,full_name,status,avatar_url")
        .in("id", ids);

      if (result.error) return fail(res, 500, "Could not load profiles.");
      profiles = result.data || [];
    }

    const byId = new Map(profiles.map((p) => [p.id, p]));

    res.json({
      accounts: (accounts || []).map((account) => ({
        ...account,
        customer_status: byId.get(account.owner_id)?.status || "unknown",
        avatar_url: byId.get(account.owner_id)?.avatar_url || null,
      })),
    });
  } catch (error) {
    next(error);
  }
});

// CREATE ACCOUNT + PHOTO + 5 RANDOM HISTORY (2 Transfer + 3 Receive)
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
    const opening_note = clean(req.body?.opening_note, 120) || "Opening balance";
    const avatarBase64 = req.body?.avatar;

    if (
      !full_name ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      !country ||
      !["GBP", "NGN", "USD", "EUR", "CAD"].includes(currency) ||
      password.length < 6 ||
      !Number.isFinite(initial_balance) ||
      initial_balance < 0
    ) {
      return fail(res, 400, "Check the fields. Password must be at least 6 characters.");
    }

    // 1. Create user
    const { data: created, error: createError } = await adminDb.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { full_name },
    });

    if (createError || !created.user) {
      return fail(res, 400, createError?.message || "Could not create customer login.");
    }

    newUserId = created.user.id;

    // 2. Create bank account
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
      await adminDb.auth.admin.deleteUser(newUserId).catch(() => {});
      return fail(res, 500, "Account setup failed.");
    }

    // 3. Upload photo
    let avatar_url = null;
    if (avatarBase64 && typeof avatarBase64 === "string" && avatarBase64.startsWith("data:image")) {
      try {
        const matches = avatarBase64.match(/^data:image\/([a-zA-Z]+);base64,(.+)$/);
        if (matches) {
          const ext = matches[1] === "jpeg" ? "jpg" : matches[1];
          const buffer = Buffer.from(matches[2], "base64");
          const fileName = `${newUserId}-${Date.now()}.${ext}`;

          const { error: uploadError } = await adminDb.storage
            .from("avatars")
            .upload(fileName, buffer, {
              contentType: `image/${matches[1]}`,
              upsert: true,
            });

          if (!uploadError) {
            const { data: publicUrl } = adminDb.storage
              .from("avatars")
              .getPublicUrl(fileName);

            avatar_url = publicUrl.publicUrl;

            await adminDb
              .from("profiles")
              .update({ avatar_url })
              .eq("id", newUserId);
          }
        }
      } catch (err) {
        console.error("Avatar upload failed:", err.message);
      }
    }

    // 4. Generate 5 random transactions (2 Transfer + 3 Receive) over last 6 months
    try {
      const accountNumber = account?.account_number;

      if (accountNumber) {
        const incomingDescriptions = [
          "Salary payment",
          "Incoming transfer",
          "Payment received",
          "Client payment",
          "Refund received",
          "Bonus credit",
          "Investment return"
        ];

        const outgoingDescriptions = [
          "Transfer sent",
          "Bill payment",
          "Online purchase",
          "Service payment",
          "Subscription payment",
          "Merchant payment"
        ];

        const transactions = [];

        // 3 Incoming (Receive)
        for (let i = 0; i < 3; i++) {
          const daysAgo = Math.floor(Math.random() * 180) + 5;
          const createdAt = new Date();
          createdAt.setDate(createdAt.getDate() - daysAgo);

          transactions.push({
            owner_id: newUserId,
            account_number: accountNumber,
            amount: Number((Math.random() * 2800 + 80).toFixed(2)),
            currency: currency,
            direction: "in",
            description: incomingDescriptions[Math.floor(Math.random() * incomingDescriptions.length)],
            counterparty: "External Sender",
            status: "completed",
            created_at: createdAt.toISOString()
          });
        }

        // 2 Outgoing (Transfer)
        for (let i = 0; i < 2; i++) {
          const daysAgo = Math.floor(Math.random() * 180) + 5;
          const createdAt = new Date();
          createdAt.setDate(createdAt.getDate() - daysAgo);

          transactions.push({
            owner_id: newUserId,
            account_number: accountNumber,
            amount: Number((Math.random() * 1200 + 40).toFixed(2)),
            currency: currency,
            direction: "out",
            description: outgoingDescriptions[Math.floor(Math.random() * outgoingDescriptions.length)],
            counterparty: "External Receiver",
            status: "completed",
            created_at: createdAt.toISOString()
          });
        }

        // Sort by date
        transactions.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));

        const { error: txError } = await adminDb
          .from("transactions")
          .insert(transactions);

        if (txError) {
          console.error("Failed to insert history:", txError.message);
        }
      }
    } catch (err) {
      console.error("History generation error:", err.message);
    }

    newUserId = null;

    res.status(201).json({
      ok: true,
      account: {
        ...account,
        avatar_url,
      },
    });
  } catch (error) {
    if (newUserId) {
      await adminDb.auth.admin.deleteUser(newUserId).catch(() => {});
    }
    next(error);
  }
});

// CREDIT
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
      return fail(res, 400, "Credit failed.");
    }

    res.json({ ok: true, result: data });
  } catch (error) {
    next(error);
  }
});

// 404
app.use((req, res) => {
  if (req.path.startsWith("/api/")) {
    return fail(res, 404, "API route not found.");
  }
  res.status(404).json({ error: "This server provides API endpoints only." });
});

// Error handler
app.use((error, _req, res, _next) => {
  console.error("Request failed:", error.message);
  if (res.headersSent) return;
  res.status(500).json({ error: "Unexpected server error." });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`CFM API listening on port ${PORT}`);
});
