"use strict";

const API_BASE = "https://cfm-international-bank-in.onrender.com";
const $ = id => document.getElementById(id);

let token = sessionStorage.getItem("cfm-access-token") || "";
let profile = null;
let lastReceipt = null;

function currencyFormat(amount, currency = "EUR") {
  try {
    return new Intl.NumberFormat("en", {
      style: "currency",
      currency: currency || "EUR",
      minimumFractionDigits: 2
    }).format(Number(amount));
  } catch {
    return `€${Number(amount).toFixed(2)}`;
  }
}

function message(id, text, kind = "error") {
  const el = $(id);
  if (!el) return;
  el.textContent = text || "";
  el.className = `message ${kind}`;
}

async function api(path, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {})
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, { ...options, headers });
  } catch {
    throw new Error("Cannot reach the server. Check your connection.");
  }

  const data = await response.json().catch(() => ({ error: "Invalid server response." }));

  if (!response.ok) {
    if (response.status === 401) {
      token = "";
      profile = null;
      sessionStorage.removeItem("cfm-access-token");
    }
    throw new Error(data.error || `Request failed (${response.status})`);
  }
  return data;
}

function show(view) {
  ["authView", "customerView", "adminView"].forEach(id => {
    if ($(id)) $(id).classList.add("hidden");
  });
  if ($(view)) $(view).classList.remove("hidden");
}

async function boot() {
  if (!token) {
    show("authView");
    return;
  }
  try {
    const data = await api("/api/me");
    profile = data.profile;
    if (!profile || profile.status !== "active") throw new Error("Account inactive.");

    if (profile.role === "admin") {
      show("adminView");
      await loadAccounts();
    } else {
      show("customerView");
      await loadDashboard();
    }
  } catch {
    token = "";
    profile = null;
    sessionStorage.removeItem("cfm-access-token");
    show("authView");
  }
}

/* ========== LOGIN ========== */
if ($("loginForm")) {
  $("loginForm").addEventListener("submit", async e => {
    e.preventDefault();
    message("authMessage", "Signing in…", "");
    try {
      const data = await api("/api/login", {
        method: "POST",
        body: JSON.stringify({
          email: $("email").value.trim(),
          password: $("password").value
        })
      });
      if (!data.access_token || !data.profile) throw new Error("Invalid login response.");

      token = data.access_token;
      profile = data.profile;
      sessionStorage.setItem("cfm-access-token", token);

      if (profile.status !== "active") {
        token = "";
        profile = null;
        sessionStorage.removeItem("cfm-access-token");
        throw new Error("This account is inactive.");
      }

      if (profile.role === "admin") {
        show("adminView");
        await loadAccounts();
      } else {
        show("customerView");
        await loadDashboard();
      }
      message("authMessage", "", "");
    } catch (err) {
      message("authMessage", err.message || "Unable to sign in.");
    }
  });
}

if ($("signout")) {
  $("signout").addEventListener("click", async () => {
    try { await api("/api/logout", { method: "POST", body: "{}" }); } catch {}
    token = "";
    profile = null;
    sessionStorage.removeItem("cfm-access-token");
    show("authView");
  });
}

/* ========== DASHBOARD ========== */
async function loadDashboard() {
  const data = await api("/api/me/account");
  const account = data.account;
  if (!account) throw new Error("Account not found.");

  const name = account.full_name || "Customer";
  if ($("customerAvatar")) $("customerAvatar").textContent = name.charAt(0).toUpperCase();

  const bal = currencyFormat(account.balance, account.currency);
  if ($("balance")) $("balance").textContent = bal;
  if ($("netWorth")) $("netWorth").textContent = bal;
  if ($("cashBalance")) $("cashBalance").textContent = bal;

  const txData = await api("/api/transactions");
  renderTransactions(txData.transactions || []);
}

function renderTransactions(items) {
  const box = $("transactionList");
  if (!box) return;
  box.replaceChildren();

  if (!items.length) {
    const p = document.createElement("p");
    p.className = "muted";
    p.style.padding = "12px 0";
    p.textContent = "No transactions yet";
    box.append(p);
    return;
  }

  items.slice(0, 6).forEach(tx => {
    const incoming = tx.direction === "in";
    const row = document.createElement("div");
    row.className = "tx-item";

    const flag = document.createElement("div");
    flag.className = "tx-flag";
    flag.textContent = incoming ? "🇺🇸" : "🇬🇧";

    const info = document.createElement("div");
    info.className = "tx-info";

    const title = document.createElement("div");
    title.className = "tx-title";
    title.textContent = tx.description || (incoming ? "Received" : "Sent");

    const time = document.createElement("div");
    time.className = "tx-time";
    const d = new Date(tx.created_at);
    time.textContent = Number.isNaN(d.getTime()) ? "" : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

    info.append(title, time);

    const amount = document.createElement("div");
    amount.className = `tx-amount ${incoming ? "positive" : "negative"}`;
    amount.textContent = `${incoming ? "+" : "−"}${currencyFormat(tx.amount, tx.currency)}`;

    row.append(flag, info, amount);
    box.append(row);
  });
}

/* ========== TRANSFER SHEET ========== */
function openTransfer() {
  $("transferSheet")?.classList.remove("hidden");
}
function closeTransfer() {
  $("transferSheet")?.classList.add("hidden");
  message("transferMessage", "", "");
}

if ($("sendBtn")) $("sendBtn").addEventListener("click", openTransfer);
if ($("topUpBtn")) $("topUpBtn").addEventListener("click", () => alert("Top-up coming soon"));
if ($("withdrawBtn")) $("withdrawBtn").addEventListener("click", () => alert("Withdraw coming soon"));
if ($("closeTransfer")) $("closeTransfer").addEventListener("click", closeTransfer);

if ($("transferForm")) {
  $("transferForm").addEventListener("submit", async e => {
    e.preventDefault();
    message("transferMessage", "Processing…", "");

    const amount = Number($("amount").value);
    if (!Number.isFinite(amount) || amount <= 0) {
      message("transferMessage", "Enter a valid amount.");
      return;
    }

    try {
      const result = await api("/api/transfers", {
        method: "POST",
        body: JSON.stringify({
          receiver_name: $("receiverName").value.trim(),
          receiver_account: $("receiverAccount").value.trim(),
          receiver_country: $("receiverCountry").value,
          amount,
          description: $("description").value.trim()
        })
      });

      message("transferMessage", "Transfer completed", "success");
      $("transferForm").reset();
      await loadDashboard();

      lastReceipt = result.receipt;
      if (lastReceipt) showReceipt(lastReceipt);
      closeTransfer();
    } catch (err) {
      message("transferMessage", err.message || "Transfer failed");
    }
  });
}

function showReceipt(receipt) {
  if (!receipt || !$("receiptView") || !$("receiptDetails")) return;
  $("receiptView").classList.remove("hidden");

  const date = new Date(receipt.created_at);
  const rows = [
    ["Status", "Completed"],
    ["Reference", receipt.reference],
    ["Date", Number.isNaN(date.getTime()) ? "—" : date.toLocaleString()],
    ["Sender", receipt.sender_name],
    ["Sender account", receipt.sender_account],
    ["Receiver", receipt.receiver_name],
    ["Receiver account", receipt.receiver_account],
    ["Country", receipt.receiver_country],
    ["Amount", currencyFormat(receipt.amount, receipt.currency)],
    ["Description", receipt.description || "—"]
  ];

  $("receiptDetails").replaceChildren();
  rows.forEach(([label, value]) => {
    const row = document.createElement("div");
    row.className = "receipt-row";
    const l = document.createElement("span");
    l.textContent = label;
    const v = document.createElement("strong");
    v.textContent = value || "—";
    row.append(l, v);
    $("receiptDetails").append(row);
  });
}

if ($("printReceipt")) $("printReceipt").addEventListener("click", () => window.print());
if ($("closeReceipt")) $("closeReceipt").addEventListener("click", () => {
  $("receiptView")?.classList.add("hidden");
});

/* ========== ADMIN ========== */
if ($("createForm")) {
  $("createForm").addEventListener("submit", async e => {
    e.preventDefault();
    message("createMessage", "Creating…", "");

    const password = $("newPassword").value;
    const initialBalance = Number($("initialBalance").value);

    if (password.length < 12) {
      message("createMessage", "Password must be at least 12 characters.");
      return;
    }
    if (!Number.isFinite(initialBalance) || initialBalance < 0) {
      message("createMessage", "Enter a valid balance.");
      return;
    }

    try {
      const data = await api("/api/admin/accounts", {
        method: "POST",
        body: JSON.stringify({
          full_name: $("newName").value.trim(),
          email: $("newEmail").value.trim(),
          phone: $("newPhone").value.trim(),
          country: $("newCountry").value.trim(),
          currency: $("newCurrency").value,
          password,
          initial_balance: initialBalance,
          opening_note: "Opening balance"
        })
      });

      message("createMessage", `Account created: ${data.account?.account_number || "—"}`, "success");
      $("createForm").reset();
      if ($("newCountry")) $("newCountry").value = "United Kingdom";
      if ($("initialBalance")) $("initialBalance").value = "0";
      await loadAccounts();
    } catch (err) {
      message("createMessage", err.message || "Failed to create account");
    }
  });
}

if ($("creditForm")) {
  $("creditForm").addEventListener("submit", async e => {
    e.preventDefault();
    message("creditMessage", "Processing…", "");

    const amount = Number($("creditAmount").value);
    if (!Number.isFinite(amount) || amount <= 0) {
      message("creditMessage", "Enter a valid amount.");
      return;
    }

    try {
      await api("/api/admin/credit", {
        method: "POST",
        body: JSON.stringify({
          account_number: $("creditAccount").value.trim(),
          amount,
          reason: $("creditReason").value.trim()
        })
      });
      message("creditMessage", "Balance credited", "success");
      $("creditForm").reset();
      await loadAccounts();
    } catch (err) {
      message("creditMessage", err.message || "Credit failed");
    }
  });
}

if ($("refreshAccounts")) {
  $("refreshAccounts").addEventListener("click", () => loadAccounts());
}

async function loadAccounts() {
  const box = $("accountList");
  if (!box) return;
  box.textContent = "Loading…";

  try {
    const data = await api("/api/admin/accounts");
    box.replaceChildren();

    if (!Array.isArray(data.accounts) || data.accounts.length === 0) {
      box.textContent = "No accounts yet.";
      return;
    }

    data.accounts.forEach(acc => {
      const item = document.createElement("div");
      item.className = "account-item";
      item.innerHTML = `
        <b>${acc.full_name || "Customer"}</b><br>
        ${acc.account_number || ""} · ${acc.email || ""}<br>
        ${currencyFormat(acc.balance, acc.currency)} · ${acc.status || "active"}
      `;
      box.append(item);
    });
  } catch (err) {
    box.textContent = err.message || "Failed to load accounts";
  }
}

boot();
