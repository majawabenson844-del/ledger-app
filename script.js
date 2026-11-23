const BACKUP_FORMAT = "benson-ledger-encrypted";
const BACKUP_VERSION = 2;
const PBKDF2_ITERATIONS = 310000;
const DEFAULT_CURRENCY = "USD";
const CATEGORIES = {
  income: ["Salary", "Business", "Gift", "Family support", "Investment", "Other"],
  expense: ["Living expenses", "Food", "Transport", "Housing", "Bills", "Health", "Shopping", "Family support", "Other"]
};

const authScreen = document.querySelector("#auth-screen");
const authForm = document.querySelector("#auth-form");
const authEmail = document.querySelector("#auth-email");
const authPassword = document.querySelector("#auth-password");
const authMessage = document.querySelector("#auth-message");
const lockScreen = document.querySelector("#lock-screen");
const lockTitle = document.querySelector("#lock-title");
const lockDescription = document.querySelector("#lock-description");
const unlockForm = document.querySelector("#unlock-form");
const passphraseInput = document.querySelector("#passphrase");
const confirmField = document.querySelector("#confirm-field");
const confirmInput = document.querySelector("#passphrase-confirm");
const unlockButton = document.querySelector("#unlock-button");
const lockMessage = document.querySelector("#lock-message");
const app = document.querySelector("#ledger-app");
const syncStatus = document.querySelector("#sync-status");
const currencyInput = document.querySelector("#currency");
const monthFilter = document.querySelector("#month-filter");
const transactionDialog = document.querySelector("#transaction-dialog");
const transactionForm = document.querySelector("#transaction-form");
const transactionMessage = document.querySelector("#transaction-message");
const transactionCategory = document.querySelector("#category");
const transactionTypeInput = document.querySelector("#transaction-type");
const transactionIdInput = document.querySelector("#transaction-id");
const descriptionInput = document.querySelector("#description");
const amountInput = document.querySelector("#amount");
const dateInput = document.querySelector("#date");
const noteInput = document.querySelector("#note");
const loanDialog = document.querySelector("#loan-dialog");
const loanForm = document.querySelector("#loan-form");
const loanMessage = document.querySelector("#loan-message");
const savingsDialog = document.querySelector("#savings-dialog");
const savingsForm = document.querySelector("#savings-form");
const savingsMessage = document.querySelector("#savings-message");
const restoreDialog = document.querySelector("#restore-dialog");
const restoreForm = document.querySelector("#restore-form");
const restoreFileInput = document.querySelector("#restore-file");
const restoreMessage = document.querySelector("#restore-message");

let client = null;
let session = null;
let ledgerAccessRole = "owner";
let sharedRecord = null;
let sharedKey = null;
let sharedSalt = null;
let revision = 0;
let remoteRevision = 0;
let ledger = emptyLedger();
let activeView = "overview";
let saveQueue = Promise.resolve();
let realtimeChannel = null;
let inviteOnlyReady = false;
let authAction = "signin";
let restoreFile = null;
let activationPromise = null;

function emptyLedger() {
  return { currency: DEFAULT_CURRENCY, transactions: [], loans: [], savings: [] };
}

function setMessage(element, message, success = false) {
  element.textContent = message;
  element.className = success ? "status-message success" : "status-message";
}

function setSyncStatus(message, isError = false) {
  syncStatus.textContent = message;
  syncStatus.style.color = isError ? "var(--expense)" : "";
}

function localDateString(date = new Date()) {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
}

function isValidDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00`);
  return !Number.isNaN(date.getTime()) && localDateString(date) === value;
}

function newId() {
  return crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function formatAmount(value) {
  return new Intl.NumberFormat(undefined, {
    style: "currency",
    currency: ledger.currency,
    maximumFractionDigits: 2
  }).format(value);
}

function encodeBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function decodeBase64(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

async function deriveKey(passphrase, salt) {
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptPayload(value, key, salt) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return {
    salt: encodeBase64(salt),
    iv: encodeBase64(iv),
    ciphertext: encodeBase64(new Uint8Array(ciphertext))
  };
}

async function decryptPayload(payload, key) {
  const salt = decodeBase64(payload.salt);
  const iv = decodeBase64(payload.iv);
  if (salt.length !== 16 || iv.length !== 12 || typeof payload.ciphertext !== "string") {
    throw new Error("The encrypted ledger data is damaged.");
  }
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    decodeBase64(payload.ciphertext)
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}

function validMoney(value, allowZero = false) {
  return Number.isFinite(value) && (allowZero ? value >= 0 : value > 0) && value < 1000000000000;
}

function validateLedger(value) {
  if (!value || typeof value !== "object") throw new Error("The ledger data is not valid.");
  const currencies = ["USD", "ZWG", "ZAR"];
  if (!currencies.includes(value.currency)) throw new Error("The ledger has an unsupported currency.");
  if (!Array.isArray(value.transactions) || !Array.isArray(value.loans) || !Array.isArray(value.savings)) {
    throw new Error("The ledger data is incomplete or damaged.");
  }

  const transactions = value.transactions.map(item => {
    if (
      !item || typeof item.id !== "string" || typeof item.description !== "string" ||
      typeof item.category !== "string" || typeof item.note !== "string" ||
      !["income", "expense"].includes(item.type) || !validMoney(item.amount) || !isValidDate(item.date)
    ) throw new Error("The ledger contains an invalid transaction.");
    return {
      id: item.id,
      description: item.description.slice(0, 100),
      category: item.category.slice(0, 60),
      note: item.note.slice(0, 180),
      type: item.type,
      amount: item.amount,
      date: item.date
    };
  });

  const loans = value.loans.map(item => {
    if (
      !item || typeof item.id !== "string" || typeof item.name !== "string" ||
      typeof item.phone !== "string" || typeof item.note !== "string" ||
      !validMoney(item.amount) || !isValidDate(item.date) ||
      (item.dueDate && !isValidDate(item.dueDate)) || !Array.isArray(item.payments)
    ) throw new Error("The ledger contains an invalid loan.");
    const payments = item.payments.map(payment => {
      if (!payment || typeof payment.id !== "string" || !validMoney(payment.amount) || !isValidDate(payment.date)) {
        throw new Error("The ledger contains an invalid loan repayment.");
      }
      return { id: payment.id, amount: payment.amount, date: payment.date };
    });
    if (payments.reduce((sum, payment) => sum + payment.amount, 0) > item.amount + 0.01) {
      throw new Error("A loan's repayments exceed the original amount.");
    }
    return {
      id: item.id,
      name: item.name.slice(0, 100),
      phone: item.phone.slice(0, 30),
      amount: item.amount,
      date: item.date,
      dueDate: item.dueDate || "",
      note: item.note.slice(0, 180),
      payments
    };
  });

  const savings = value.savings.map(item => {
    if (
      !item || typeof item.id !== "string" || typeof item.name !== "string" ||
      !validMoney(item.balance, true) ||
      (item.goal !== null && item.goal !== undefined && !validMoney(item.goal, true))
    ) throw new Error("The ledger contains an invalid savings place.");
    return {
      id: item.id,
      name: item.name.slice(0, 80),
      balance: item.balance,
      goal: item.goal === null || item.goal === undefined ? null : item.goal
    };
  });

  return { currency: value.currency, transactions, loans, savings };
}

function setMonthOptions() {
  const months = new Set([localDateString().slice(0, 7)]);
  for (const transaction of ledger.transactions) months.add(transaction.date.slice(0, 7));
  const sorted = [...months].sort().reverse();
  monthFilter.replaceChildren();
  const allOption = document.createElement("option");
  allOption.value = "all";
  allOption.textContent = "All time";
  monthFilter.append(allOption);
  for (const month of sorted) {
    const option = document.createElement("option");
    option.value = month;
    option.textContent = new Date(`${month}-02T00:00:00`).toLocaleDateString(undefined, {
      month: "long",
      year: "numeric"
    });
    monthFilter.append(option);
  }
  if (!monthFilter.value || !sorted.includes(monthFilter.value)) {
    monthFilter.value = sorted[0] || "all";
  }
}

function activeTransactions(type = "") {
  return ledger.transactions
    .filter(item => monthFilter.value === "all" || item.date.startsWith(monthFilter.value))
    .filter(item => !type || item.type === type)
    .sort((a, b) => b.date.localeCompare(a.date) || b.id.localeCompare(a.id));
}

function element(tag, className = "", text = "") {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text) node.textContent = text;
  return node;
}

function createEmpty(message) {
  return element("p", "empty-state", message);
}

function renderSummary() {
  const monthTransactions = activeTransactions();
  const income = monthTransactions.filter(item => item.type === "income");
  const expenses = monthTransactions.filter(item => item.type === "expense");
  const incomeTotal = income.reduce((sum, item) => sum + item.amount, 0);
  const expenseTotal = expenses.reduce((sum, item) => sum + item.amount, 0);
  const outstanding = ledger.loans.reduce((total, loan) =>
    total + Math.max(0, loan.amount - loan.payments.reduce((sum, payment) => sum + payment.amount, 0)), 0);
  const savingsTotal = ledger.savings.reduce((total, pot) => total + pot.balance, 0);
  const period = monthFilter.value === "all"
    ? "all time"
    : new Date(`${monthFilter.value}-02T00:00:00`).toLocaleDateString(undefined, { month: "long", year: "numeric" });

  document.querySelector("#period-title").textContent = `in ${period}`;
  document.querySelector("#income-total").textContent = formatAmount(incomeTotal);
  document.querySelector("#income-count").textContent = `${income.length} ${income.length === 1 ? "entry" : "entries"}`;
  document.querySelector("#expense-total").textContent = formatAmount(expenseTotal);
  document.querySelector("#expense-count").textContent = `${expenses.length} ${expenses.length === 1 ? "entry" : "entries"}`;
  document.querySelector("#balance-total").textContent = formatAmount(incomeTotal - expenseTotal);
  document.querySelector("#loans-total").textContent = formatAmount(outstanding);
  document.querySelector("#loans-count").textContent = `${ledger.loans.filter(loan =>
    loan.amount - loan.payments.reduce((sum, payment) => sum + payment.amount, 0) > 0.009).length} people`;
  document.querySelector("#savings-total").textContent = formatAmount(savingsTotal);
  document.querySelector("#savings-count").textContent = `${ledger.savings.length} ${ledger.savings.length === 1 ? "place" : "places"}`;
}

function renderBreakdown(targetId, type) {
  const target = document.querySelector(targetId);
  target.replaceChildren();
  const totals = new Map();
  for (const item of activeTransactions(type)) {
    totals.set(item.category, (totals.get(item.category) || 0) + item.amount);
  }
  const sorted = [...totals].sort((a, b) => b[1] - a[1]);
  const max = sorted[0]?.[1] || 0;
  if (!sorted.length) {
    target.append(createEmpty(type === "expense" ? "No costs recorded for this period." : "No income recorded for this period."));
    return;
  }
  for (const [name, amount] of sorted.slice(0, 6)) {
    const row = element("div", "breakdown-item");
    const top = element("div", "breakdown-top");
    top.append(element("span", "breakdown-name", name), element("span", "breakdown-amount", formatAmount(amount)));
    const track = element("div", "progress-track");
    const bar = element("div", "progress-bar");
    bar.style.width = `${Math.max(3, (amount / max) * 100)}%`;
    track.append(bar);
    row.append(top, track);
    target.append(row);
  }
}

function createEntryRow(transaction, compact = false) {
  const row = element("article", compact ? "latest-row" : "entry-row");
  const icon = element("span", `entry-symbol ${transaction.type}`, transaction.type === "income" ? "↙" : "▤");
  icon.setAttribute("aria-hidden", "true");
  const copy = element("div", "entry-copy");
  const description = element("p", "entry-description", transaction.description);
  const meta = element("p", "entry-meta", `${new Date(`${transaction.date}T00:00:00`).toLocaleDateString()} · ${transaction.category}${transaction.note ? ` · ${transaction.note}` : ""}`);
  copy.append(description, meta);
  const amount = element("span", `entry-amount ${transaction.type}`, `${transaction.type === "income" ? "+" : "−"}${formatAmount(transaction.amount)}`);
  row.append(icon, copy, amount);

  if (!compact) {
    const edit = element("button", "entry-delete", "✎");
    edit.type = "button";
    edit.dataset.action = "edit-transaction";
    edit.dataset.id = transaction.id;
    edit.setAttribute("aria-label", `Edit ${transaction.description}`);
    const remove = element("button", "entry-delete", "♲");
    remove.type = "button";
    remove.dataset.action = "delete-transaction";
    remove.dataset.id = transaction.id;
    remove.setAttribute("aria-label", `Delete ${transaction.description}`);
    row.append(edit, remove);
  }
  return row;
}

function renderEntries(targetId, transactions, message, compact = false) {
  const target = document.querySelector(targetId);
  target.replaceChildren();
  if (!transactions.length) {
    target.append(createEmpty(message));
    return;
  }
  for (const transaction of transactions) target.append(createEntryRow(transaction, compact));
}

function renderLoans() {
  const target = document.querySelector("#loan-list");
  target.replaceChildren();
  const openLoans = ledger.loans.filter(loan => loan.amount - loan.payments.reduce((sum, p) => sum + p.amount, 0) > 0.009);
  document.querySelector("#loan-summary-copy").textContent =
    `${formatAmount(openLoans.reduce((sum, loan) => sum + loan.amount - loan.payments.reduce((part, p) => part + p.amount, 0), 0))} outstanding from ${openLoans.length} ${openLoans.length === 1 ? "person" : "people"}.`;
  if (!ledger.loans.length) {
    target.append(createEmpty("No loans yet. Add a person who owes you money."));
    return;
  }

  for (const loan of [...ledger.loans].sort((a, b) => b.date.localeCompare(a.date))) {
    const paid = loan.payments.reduce((sum, payment) => sum + payment.amount, 0);
    const due = Math.max(0, loan.amount - paid);
    const card = element("article", "loan-card");
    const top = element("div", "loan-card-top");
    const person = element("div");
    person.append(element("h3", "loan-person", loan.name));
    if (loan.phone) {
      const phone = element("a", "loan-phone", loan.phone);
      phone.href = `tel:${loan.phone.replace(/[^\d+]/g, "")}`;
      person.append(phone);
    }
    const balance = element("div", "loan-balance");
    balance.append(element("span", "loan-balance-label", due > 0.009 ? "Still owes" : "Repaid"));
    balance.append(element("span", "loan-balance-value", formatAmount(due)));
    top.append(person, balance);
    const details = [`Lent ${new Date(`${loan.date}T00:00:00`).toLocaleDateString()} · ${formatAmount(loan.amount)}`];
    if (loan.dueDate) details.push(`due ${new Date(`${loan.dueDate}T00:00:00`).toLocaleDateString()}`);
    card.append(top, element("p", "loan-meta", details.join(" · ")));
    if (loan.note) card.append(element("p", "loan-note", `"${loan.note}"`));
    const progressTrack = element("div", "loan-progress");
    const progressBar = element("div", "progress-bar");
    progressBar.style.width = `${loan.amount ? Math.min(100, (paid / loan.amount) * 100) : 0}%`;
    progressTrack.append(progressBar);
    card.append(progressTrack);

    if (loan.phone) {
      const contactActions = element("div", "loan-actions");
      const call = element("a", "button button-small button-call", "☎ Call");
      call.href = `tel:${loan.phone.replace(/[^\d+]/g, "")}`;
      const digits = loan.phone.replace(/\D/g, "");
      const whatsapp = element("a", "button button-small button-whatsapp", "◉ WhatsApp");
      whatsapp.href = `https://wa.me/${digits}`;
      whatsapp.target = "_blank";
      whatsapp.rel = "noopener noreferrer";
      contactActions.append(call, whatsapp);
      card.append(contactActions);
    }

    const actions = element("div", "loan-actions");
    if (due > 0.009) {
      const record = element("button", "button button-small button-soft", "Record paid back");
      record.type = "button";
      record.dataset.action = "repay-loan";
      record.dataset.id = loan.id;
      const fullyPaid = element("button", "button button-small button-soft", "Mark fully repaid");
      fullyPaid.type = "button";
      fullyPaid.dataset.action = "full-repay";
      fullyPaid.dataset.id = loan.id;
      actions.append(record, fullyPaid);
    }
    const edit = element("button", "button button-small button-soft", "Edit");
    edit.type = "button";
    edit.dataset.action = "edit-loan";
    edit.dataset.id = loan.id;
    const remove = element("button", "button button-small button-soft", "Delete");
    remove.type = "button";
    remove.dataset.action = "delete-loan";
    remove.dataset.id = loan.id;
    actions.append(edit, remove);
    card.append(actions);

    if (loan.payments.length) {
      const repayment = [...loan.payments].sort((a, b) => b.date.localeCompare(a.date))[0];
      card.append(element("p", "loan-repayment-row", `Last repayment · ${new Date(`${repayment.date}T00:00:00`).toLocaleDateString()} · ${formatAmount(repayment.amount)}`));
    }
    target.append(card);
  }
}

function renderSavings() {
  const target = document.querySelector("#savings-list");
  target.replaceChildren();
  if (!ledger.savings.length) {
    target.append(createEmpty("No savings places yet. Add a fund or savings goal to start tracking."));
    return;
  }
  for (const pot of ledger.savings) {
    const card = element("article", "savings-card");
    const top = element("div", "savings-card-top");
    top.append(element("h3", "savings-name", pot.name), element("span", "savings-balance", formatAmount(pot.balance)));
    card.append(top);
    if (pot.goal && pot.goal > 0) {
      card.append(element("p", "savings-meta", `${formatAmount(pot.balance)} saved of ${formatAmount(pot.goal)} goal`));
      const track = element("div", "savings-progress");
      const bar = element("div", "progress-bar");
      bar.style.width = `${Math.min(100, (pot.balance / pot.goal) * 100)}%`;
      track.append(bar);
      card.append(track);
    } else {
      card.append(element("p", "savings-meta", "No target set"));
    }
    const actions = element("div", "savings-actions");
    for (const [action, label] of [["deposit", "+ Add money"], ["withdraw", "− Take out"], ["edit-savings", "Edit"], ["delete-savings", "Delete"]]) {
      const button = element("button", "button button-small button-soft", label);
      button.type = "button";
      button.dataset.action = action;
      button.dataset.id = pot.id;
      actions.append(button);
    }
    card.append(actions);
    target.append(card);
  }
}

function render() {
  if (!app || app.hidden) return;
  setMonthOptions();
  renderSummary();
  renderBreakdown("#expense-breakdown", "expense");
  renderBreakdown("#income-breakdown", "income");
  renderEntries("#latest-entries", activeTransactions().slice(0, 6), "No entries recorded for this period.", true);
  renderEntries("#income-list", activeTransactions("income"), "No income recorded for this period.");
  renderEntries("#costs-list", activeTransactions("expense"), "No costs recorded for this period.");
  renderLoans();
  renderSavings();
  currencyInput.value = ledger.currency;
}

function setActiveView(viewName) {
  const views = ["overview", "income", "costs", "loans", "savings"];
  if (!views.includes(viewName)) return;
  activeView = viewName;
  document.querySelectorAll(".tab").forEach(tab => {
    const selected = tab.dataset.view === activeView;
    tab.classList.toggle("active", selected);
    if (selected) tab.setAttribute("aria-current", "page");
    else tab.removeAttribute("aria-current");
  });
  document.querySelectorAll(".view").forEach(view => view.classList.toggle("active", view.id === `view-${activeView}`));
}

function setCategoryOptions(type, selected = "") {
  transactionTypeInput.value = type;
  transactionCategory.replaceChildren();
  for (const category of CATEGORIES[type]) {
    const option = document.createElement("option");
    option.value = category;
    option.textContent = category;
    transactionCategory.append(option);
  }
  if (selected && !CATEGORIES[type].includes(selected)) {
    const option = document.createElement("option");
    option.value = selected;
    option.textContent = selected;
    transactionCategory.append(option);
  }
  transactionCategory.value = selected && [...transactionCategory.options].some(option => option.value === selected)
    ? selected
    : CATEGORIES[type][0];
}

function openTransactionForm(type, transaction = null) {
  transactionForm.reset();
  transactionMessage.textContent = "";
  transactionIdInput.value = transaction?.id || "";
  setCategoryOptions(type, transaction?.category || "");
  descriptionInput.value = transaction?.description || "";
  amountInput.value = transaction ? String(transaction.amount) : "";
  dateInput.value = transaction?.date || localDateString();
  noteInput.value = transaction?.note || "";
  document.querySelector("#transaction-title").textContent =
    `${transaction ? "Edit" : "Add"} ${type === "income" ? "money in" : "a cost"}`;
  document.querySelector("#save-transaction").textContent = transaction ? "Save changes" : "Save entry";
  transactionDialog.showModal();
  descriptionInput.focus();
}

function showAuthScreen(message = "") {
  session = null;
  sharedRecord = null;
  sharedKey = null;
  sharedSalt = null;
  revision = 0;
  remoteRevision = 0;
  ledger = emptyLedger();
  app.hidden = true;
  lockScreen.hidden = true;
  authScreen.hidden = false;
  authPassword.value = "";
  document.querySelector("#reload-button").hidden = true;
  setMessage(authMessage, message);
  if (realtimeChannel) {
    client?.removeChannel(realtimeChannel);
    realtimeChannel = null;
  }
}

async function loadSharedRecord() {
  const { data, error } = await client
    .from("shared_ledger")
    .select("id, revision, salt, iv, ciphertext, updated_at, updated_by")
    .eq("id", 1)
    .maybeSingle();
  if (error) throw error;
  return data;
}

async function showPassphraseGate() {
  const row = await loadSharedRecord();
  sharedRecord = row;
  authScreen.hidden = true;
  app.hidden = true;
  lockScreen.hidden = false;
  passphraseInput.value = "";
  confirmInput.value = "";
  setMessage(lockMessage, "");
  const initialSetup = !row;
  lockTitle.textContent = initialSetup ? "Set the shared passphrase" : "Unlock your dashboard";
  lockDescription.textContent = initialSetup
    ? "Choose a shared passphrase. Share it only with invited people; it encrypts all financial data before syncing."
    : "Enter the shared passphrase. It encrypts the financial data before it is sent to the database.";
  confirmField.hidden = !initialSetup;
  confirmInput.required = initialSetup;
  passphraseInput.autocomplete = initialSetup ? "new-password" : "current-password";
  unlockButton.textContent = initialSetup ? "Create shared ledger" : "Unlock dashboard";
  unlockButton.dataset.setup = String(initialSetup);
  setSyncStatus("Signed in. Ledger is encrypted.");
}

function applyLedgerAccessRole() {
  const hideLoans = ledgerAccessRole === "no_loans";
  document.querySelector("#members-button")?.toggleAttribute("hidden", ledgerAccessRole !== "owner");
  document.querySelector("#loans-summary")?.toggleAttribute("hidden", hideLoans);
  document.querySelector('[data-view="loans"]')?.toggleAttribute("hidden", hideLoans);
  document.querySelector("#view-loans")?.toggleAttribute("hidden", hideLoans);
}

async function loadLedgerAccessRole() {
  ledgerAccessRole = "owner";
  const { data, error } = await client
    .from("ledger_members")
    .select("role")
    .eq("user_id", session.user.id)
    .maybeSingle();
  if (!error && data?.role) ledgerAccessRole = data.role;
  applyLedgerAccessRole();
}

async function activateSession(nextSession) {
  if (!nextSession?.user) return;
  if (activationPromise) return activationPromise;
  if (session?.user?.id === nextSession.user.id) return;
  session = nextSession;
  authScreen.hidden = true;
  activationPromise = (async () => {
    try {
      await loadLedgerAccessRole();
      await showPassphraseGate();
      document.querySelector("#greeting").textContent = `Good to see you, ${nextSession.user.email?.split("@")[0] || "there"}.`;
    } catch (error) {
      showAuthScreen(`Could not connect to the shared ledger: ${error.message}`);
    } finally {
      activationPromise = null;
    }
  })();
  return activationPromise;
}

function openEntry(type) {
  openTransactionForm(type);
}

function initializeRealtime() {
  if (realtimeChannel) client.removeChannel(realtimeChannel);
  realtimeChannel = client
    .channel("shared-ledger-updates")
    .on("postgres_changes", {
      event: "UPDATE",
      schema: "public",
      table: "shared_ledger",
      filter: "id=eq.1"
    }, payload => {
      const incomingRevision = Number(payload.new.revision);
      if (incomingRevision > revision) {
        remoteRevision = Math.max(remoteRevision, incomingRevision);
        document.querySelector("#reload-button").hidden = false;
        setSyncStatus("A new shared update is available. Reload before making more changes.", true);
      }
    })
    .subscribe(status => {
      if (status === "SUBSCRIBED") {
        setSyncStatus("Live shared ledger connected.");
      } else if (status === "CHANNEL_ERROR" || status === "TIMED_OUT") {
        setSyncStatus("Live updates unavailable. Your changes still use revision checks.", true);
      }
    });
}

function showDashboard() {
  lockScreen.hidden = true;
  authScreen.hidden = true;
  app.hidden = false;
  document.querySelector("#reload-button").hidden = true;
  currencyInput.value = ledger.currency;
  render();
  initializeRealtime();
}

async function saveSharedLedger(snapshot) {
  if (!session?.user || !sharedKey || !sharedSalt) throw new Error("Unlock the ledger before saving.");
  if (remoteRevision > revision) throw new Error("Another user updated the ledger. Reload the latest version before saving.");
  const encrypted = await encryptPayload(snapshot, sharedKey, sharedSalt);
  const { data, error } = await client.rpc("save_shared_ledger", {
    p_expected_revision: revision,
    p_salt: encrypted.salt,
    p_iv: encrypted.iv,
    p_ciphertext: encrypted.ciphertext
  });
  if (error) throw error;
  revision = Number(data);
  remoteRevision = revision;
  setSyncStatus("All changes saved and synced.");
}

function persist() {
  const snapshot = JSON.parse(JSON.stringify(ledger));
  const pendingSave = saveQueue.catch(() => {}).then(() => saveSharedLedger(snapshot));
  saveQueue = pendingSave;
  pendingSave.catch(error => {
    if (error.code === "40001" || /another user updated/i.test(error.message)) {
      document.querySelector("#reload-button").hidden = false;
    }
    setSyncStatus(`Could not save: ${error.message}`, true);
  });
  return pendingSave;
}

async function unlockSharedLedger(passphrase, isSetup) {
  if (passphrase.length < 10) throw new Error("Use a passphrase with at least 10 characters.");
  const row = sharedRecord;
  if (!row && !isSetup) throw new Error("No shared ledger exists yet. Sign out and set it up first.");
  if (row && isSetup) throw new Error("The shared ledger already exists. Enter its passphrase to unlock it.");

  if (!row) {
    if (passphrase !== confirmInput.value) throw new Error("The passphrases do not match.");
    sharedSalt = crypto.getRandomValues(new Uint8Array(16));
    sharedKey = await deriveKey(passphrase, sharedSalt);
    ledger = emptyLedger();
    revision = 0;
    remoteRevision = 0;
    await saveSharedLedger(ledger);
    showDashboard();
    return;
  }

  const salt = decodeBase64(row.salt);
  if (salt.length !== 16) throw new Error("The shared ledger has invalid encryption data.");
  const key = await deriveKey(passphrase, salt);
  const payload = await decryptPayload(row, key);
  const validated = validateLedger(payload);
  sharedSalt = salt;
  sharedKey = key;
  ledger = validated;
  revision = Number(row.revision);
  remoteRevision = revision;
  showDashboard();
  setSyncStatus("Shared ledger unlocked and synced.");
}

function setAuthMode(mode) {
  authAction = mode;
  const passwordField = document.querySelector("#auth-password-field");
  passwordField.hidden = mode === "reset";
  authPassword.required = mode !== "reset";
  document.querySelector("#auth-title").textContent = mode === "reset" ? "Reset your password" : "Welcome back";
  document.querySelector("#auth-submit").textContent = mode === "reset" ? "Send reset link" : "Sign in";
}

document.querySelector("#reset-password").addEventListener("click", () => {
  setAuthMode(authAction === "reset" ? "signin" : "reset");
  setMessage(authMessage, authAction === "reset" ? "Enter your email and we’ll send a reset link." : "");
});

authForm.addEventListener("submit", async event => {
  event.preventDefault();
  setMessage(authMessage, "");
  const button = document.querySelector("#auth-submit");
  button.disabled = true;
  try {
    if (!client) throw new Error("Supabase could not load. Check your internet connection and reload.");
    if (!inviteOnlyReady) {
      throw new Error("This dashboard is paused until public sign-ups are disabled in Supabase Authentication settings.");
    }
    if (authAction === "reset") {
      const { error } = await client.auth.resetPasswordForEmail(authEmail.value.trim(), {
        redirectTo: window.location.href.split("#")[0]
      });
      if (error) throw error;
      setMessage(authMessage, "If that invited account exists, a password reset email has been sent.", true);
      return;
    }
    const { data, error } = await client.auth.signInWithPassword({
      email: authEmail.value.trim(),
      password: authPassword.value
    });
    if (error) throw error;
    await activateSession(data.session);
  } catch (error) {
    setMessage(authMessage, error.message || "Sign-in failed.");
  } finally {
    button.disabled = false;
  }
});

unlockForm.addEventListener("submit", async event => {
  event.preventDefault();
  setMessage(lockMessage, "");
  unlockButton.disabled = true;
  unlockButton.textContent = "Unlocking…";
  try {
    await unlockSharedLedger(passphraseInput.value, unlockButton.dataset.setup === "true");
    passphraseInput.value = "";
    confirmInput.value = "";
  } catch (error) {
    sharedKey = null;
    sharedSalt = null;
    if (error.code === "40001" || /another user|already exists/i.test(error.message)) {
      try {
        sharedRecord = await loadSharedRecord();
        if (sharedRecord) {
          lockTitle.textContent = "Unlock your dashboard";
          lockDescription.textContent = "Another invited user created the shared ledger. Enter their shared passphrase to continue.";
          confirmField.hidden = true;
          confirmInput.required = false;
          unlockButton.dataset.setup = "false";
          unlockButton.textContent = "Unlock dashboard";
        }
      } catch (refreshError) {
        setMessage(lockMessage, `Could not refresh shared ledger: ${refreshError.message}`);
        return;
      }
    }
    setMessage(lockMessage, error.message || "Could not unlock the shared ledger.");
  } finally {
    unlockButton.disabled = false;
    if (!app.hidden) return;
    if (unlockButton.dataset.setup === "true") unlockButton.textContent = "Create shared ledger";
    else unlockButton.textContent = "Unlock dashboard";
  }
});

document.querySelectorAll(".tab").forEach(button => {
  button.addEventListener("click", () => setActiveView(button.dataset.view));
});

document.querySelectorAll("[data-open-view]").forEach(button => {
  button.addEventListener("click", () => setActiveView(button.dataset.openView));
});

document.querySelector("#loans-summary").addEventListener("click", () => setActiveView("loans"));
document.querySelector("#loans-summary").addEventListener("keydown", event => {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    setActiveView("loans");
  }
});
document.querySelector("#savings-summary").addEventListener("click", () => setActiveView("savings"));
document.querySelector("#savings-summary").addEventListener("keydown", event => {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    setActiveView("savings");
  }
});

document.querySelectorAll("[data-add-type]").forEach(button => {
  button.addEventListener("click", () => openEntry(button.dataset.addType));
});

monthFilter.addEventListener("change", render);

transactionForm.addEventListener("submit", async event => {
  event.preventDefault();
  setMessage(transactionMessage, "");
  const amount = Number(amountInput.value);
  if (!validMoney(amount) || !isValidDate(dateInput.value) || !descriptionInput.value.trim()) {
    setMessage(transactionMessage, "Enter a description, a positive amount, and a valid date.");
    return;
  }
  const id = transactionIdInput.value;
  const item = {
    id: id || newId(),
    type: transactionTypeInput.value,
    description: descriptionInput.value.trim(),
    amount: Math.round(amount * 100) / 100,
    date: dateInput.value,
    category: transactionCategory.value,
    note: noteInput.value.trim()
  };
  const index = ledger.transactions.findIndex(transaction => transaction.id === id);
  if (index >= 0) ledger.transactions[index] = item;
  else ledger.transactions.push(item);
  render();
  try {
    await persist();
    transactionDialog.close();
  } catch {
    setMessage(transactionMessage, "This change was not synced. Reload the latest shared ledger before trying again.");
  }
});

document.querySelector("#add-loan").addEventListener("click", () => {
  loanForm.reset();
  document.querySelector("#loan-id").value = "";
  document.querySelector("#loan-form-title").textContent = "Add a loan";
  document.querySelector("#loan-date").value = localDateString();
  setMessage(loanMessage, "");
  loanDialog.showModal();
});

loanForm.addEventListener("submit", async event => {
  event.preventDefault();
  const amount = Number(document.querySelector("#loan-amount").value);
  const date = document.querySelector("#loan-date").value;
  const dueDate = document.querySelector("#loan-due").value;
  const id = document.querySelector("#loan-id").value;
  if (!validMoney(amount) || !isValidDate(date) || (dueDate && !isValidDate(dueDate))) {
    setMessage(loanMessage, "Enter a valid loan amount and date.");
    return;
  }
  const existing = ledger.loans.find(loan => loan.id === id);
  const paid = existing?.payments.reduce((sum, payment) => sum + payment.amount, 0) || 0;
  if (amount < paid) {
    setMessage(loanMessage, "The original loan amount cannot be less than the repayments already recorded.");
    return;
  }
  const loan = {
    id: id || newId(),
    name: document.querySelector("#borrower-name").value.trim(),
    phone: document.querySelector("#borrower-phone").value.trim(),
    amount: Math.round(amount * 100) / 100,
    date,
    dueDate,
    note: document.querySelector("#loan-note").value.trim(),
    payments: existing?.payments || []
  };
  if (!loan.name) {
    setMessage(loanMessage, "Enter the person's name.");
    return;
  }
  if (existing) ledger.loans = ledger.loans.map(item => item.id === id ? loan : item);
  else ledger.loans.push(loan);
  render();
  try {
    await persist();
    loanDialog.close();
  } catch {
    setMessage(loanMessage, "This change was not synced. Reload the latest shared ledger before trying again.");
  }
});

function openLoanEditor(id) {
  const loan = ledger.loans.find(item => item.id === id);
  if (!loan) return;
  document.querySelector("#loan-id").value = loan.id;
  document.querySelector("#loan-form-title").textContent = "Edit loan";
  document.querySelector("#borrower-name").value = loan.name;
  document.querySelector("#borrower-phone").value = loan.phone;
  document.querySelector("#loan-amount").value = String(loan.amount);
  document.querySelector("#loan-date").value = loan.date;
  document.querySelector("#loan-due").value = loan.dueDate;
  document.querySelector("#loan-note").value = loan.note;
  setMessage(loanMessage, "");
  loanDialog.showModal();
}

function openRepaymentForm(id) {
  const loan = ledger.loans.find(item => item.id === id);
  if (!loan) return;
  const paid = loan.payments.reduce((sum, payment) => sum + payment.amount, 0);
  const due = Math.max(0, loan.amount - paid);
  document.querySelector("#repayment-loan-id").value = id;
  document.querySelector("#repayment-description").textContent = `${loan.name} still owes ${formatAmount(due)}.`;
  document.querySelector("#repayment-amount").value = "";
  document.querySelector("#repayment-amount").max = String(due);
  document.querySelector("#repayment-date").value = localDateString();
  setMessage(document.querySelector("#repayment-message"), "");
  document.querySelector("#repayment-dialog").showModal();
}

document.querySelector("#repayment-form").addEventListener("submit", async event => {
  event.preventDefault();
  const id = document.querySelector("#repayment-loan-id").value;
  const loan = ledger.loans.find(item => item.id === id);
  const amount = Number(document.querySelector("#repayment-amount").value);
  const date = document.querySelector("#repayment-date").value;
  if (!loan || !validMoney(amount) || !isValidDate(date)) {
    setMessage(document.querySelector("#repayment-message"), "Enter a valid repayment amount and date.");
    return;
  }
  const paid = loan.payments.reduce((sum, payment) => sum + payment.amount, 0);
  const remaining = loan.amount - paid;
  if (amount > remaining + 0.001) {
    setMessage(document.querySelector("#repayment-message"), `The amount cannot exceed the remaining ${formatAmount(remaining)}.`);
    return;
  }
  loan.payments.push({ id: newId(), amount: Math.round(amount * 100) / 100, date });
  render();
  try {
    await persist();
    document.querySelector("#repayment-dialog").close();
  } catch {
    setMessage(document.querySelector("#repayment-message"), "This repayment was not synced. Reload the latest shared ledger before trying again.");
  }
});

async function markLoanRepaid(id) {
  const loan = ledger.loans.find(item => item.id === id);
  if (!loan) return;
  const paid = loan.payments.reduce((sum, payment) => sum + payment.amount, 0);
  const remaining = Math.max(0, loan.amount - paid);
  if (!remaining || !confirm(`Mark ${loan.name}'s remaining ${formatAmount(remaining)} as repaid?`)) return;
  loan.payments.push({ id: newId(), amount: Math.round(remaining * 100) / 100, date: localDateString() });
  render();
  try {
    await persist();
  } catch {
    setSyncStatus("Repayment not synced. Reload the latest shared ledger before continuing.", true);
  }
}

document.querySelector("#loan-list").addEventListener("click", async event => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  const { action, id } = button.dataset;
  if (action === "repay-loan") return openRepaymentForm(id);
  if (action === "full-repay") return markLoanRepaid(id);
  if (action === "edit-loan") return openLoanEditor(id);
  const loan = ledger.loans.find(item => item.id === id);
  if (!loan || !confirm(`Delete the loan for ${loan.name} and its repayment history?`)) return;
  ledger.loans = ledger.loans.filter(item => item.id !== id);
  render();
  try {
    await persist();
  } catch {
    setSyncStatus("Loan deletion not synced. Reload the latest shared ledger before continuing.", true);
  }
});

document.querySelector("#add-savings").addEventListener("click", () => {
  savingsForm.reset();
  document.querySelector("#savings-id").value = "";
  document.querySelector("#savings-form-title").textContent = "Add a savings place";
  document.querySelector("#savings-balance").value = "0";
  setMessage(savingsMessage, "");
  savingsDialog.showModal();
});

savingsForm.addEventListener("submit", async event => {
  event.preventDefault();
  const id = document.querySelector("#savings-id").value;
  const name = document.querySelector("#savings-name").value.trim();
  const balance = Number(document.querySelector("#savings-balance").value);
  const goalValue = document.querySelector("#savings-goal").value;
  const goal = goalValue === "" ? null : Number(goalValue);
  if (!name || !validMoney(balance, true) || (goal !== null && !validMoney(goal, true))) {
    setMessage(savingsMessage, "Enter a name and valid non-negative amounts.");
    return;
  }
  const pot = { id: id || newId(), name, balance: Math.round(balance * 100) / 100, goal };
  if (id) ledger.savings = ledger.savings.map(item => item.id === id ? pot : item);
  else ledger.savings.push(pot);
  render();
  try {
    await persist();
    savingsDialog.close();
  } catch {
    setMessage(savingsMessage, "This change was not synced. Reload the latest shared ledger before trying again.");
  }
});

function openSavingsEditor(id) {
  const pot = ledger.savings.find(item => item.id === id);
  if (!pot) return;
  document.querySelector("#savings-id").value = pot.id;
  document.querySelector("#savings-form-title").textContent = "Edit savings place";
  document.querySelector("#savings-name").value = pot.name;
  document.querySelector("#savings-balance").value = String(pot.balance);
  document.querySelector("#savings-goal").value = pot.goal === null ? "" : String(pot.goal);
  setMessage(savingsMessage, "");
  savingsDialog.showModal();
}

function openSavingsAction(id, direction) {
  const pot = ledger.savings.find(item => item.id === id);
  if (!pot) return;
  document.querySelector("#savings-action-id").value = id;
  document.querySelector("#savings-action-type").value = direction;
  document.querySelector("#savings-action-title").textContent = direction === "deposit" ? "Add money to savings" : "Take money out";
  document.querySelector("#savings-action-description").textContent =
    direction === "deposit" ? pot.name : `${pot.name} has ${formatAmount(pot.balance)} available.`;
  document.querySelector("#savings-action-amount").value = "";
  setMessage(document.querySelector("#savings-action-message"), "");
  document.querySelector("#savings-action-dialog").showModal();
  document.querySelector("#savings-action-amount").focus();
}

document.querySelector("#savings-action-form").addEventListener("submit", async event => {
  event.preventDefault();
  const id = document.querySelector("#savings-action-id").value;
  const direction = document.querySelector("#savings-action-type").value;
  const pot = ledger.savings.find(item => item.id === id);
  const amount = Number(document.querySelector("#savings-action-amount").value);
  const message = document.querySelector("#savings-action-message");
  if (!pot || !["deposit", "withdraw"].includes(direction) || !validMoney(amount)) {
    setMessage(message, "Enter an amount greater than zero.");
    return;
  }
  if (direction === "withdraw" && amount > pot.balance) {
    setMessage(message, `You can take out no more than ${formatAmount(pot.balance)}.`);
    return;
  }
  pot.balance = Math.round((pot.balance + (direction === "deposit" ? amount : -amount)) * 100) / 100;
  render();
  try {
    await persist();
    document.querySelector("#savings-action-dialog").close();
  } catch {
    setMessage(message, "This change was not synced. Reload the latest shared ledger before trying again.");
  }
});

async function updateSavingsBalance(id, direction) {
  openSavingsAction(id, direction > 0 ? "deposit" : "withdraw");
}

document.querySelector("#savings-list").addEventListener("click", async event => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  const { action, id } = button.dataset;
  if (action === "deposit") return updateSavingsBalance(id, 1);
  if (action === "withdraw") return updateSavingsBalance(id, -1);
  if (action === "edit-savings") return openSavingsEditor(id);
  const pot = ledger.savings.find(item => item.id === id);
  if (!pot || !confirm(`Delete the "${pot.name}" savings place?`)) return;
  ledger.savings = ledger.savings.filter(item => item.id !== id);
  render();
  try {
    await persist();
  } catch {
    setSyncStatus("Savings deletion not synced. Reload the latest shared ledger before continuing.", true);
  }
});

document.querySelectorAll("#income-list, #costs-list, #latest-entries").forEach(target => {
  target.addEventListener("click", async event => {
    const button = event.target.closest("button[data-action]");
    if (!button) return;
    const transaction = ledger.transactions.find(item => item.id === button.dataset.id);
    if (!transaction) return;
    if (button.dataset.action === "edit-transaction") {
      return openTransactionForm(transaction.type, transaction);
    }
    if (!confirm(`Delete "${transaction.description}"?`)) return;
    ledger.transactions = ledger.transactions.filter(item => item.id !== transaction.id);
    render();
    try {
      await persist();
    } catch {
      setSyncStatus("Entry deletion not synced. Reload the latest shared ledger before continuing.", true);
    }
  });
});

currencyInput.addEventListener("change", async () => {
  ledger.currency = currencyInput.value;
  render();
  try {
    await persist();
  } catch {
    setSyncStatus("Currency change not synced. Reload the latest shared ledger before continuing.", true);
  }
});

const membersButton = document.querySelector("#members-button");
const membersDialog = document.querySelector("#members-dialog");
const membersList = document.querySelector("#members-list");
const membersMessage = document.querySelector("#members-message");

async function openMembersDialog() {
  membersDialog.showModal();
  setMessage(membersMessage, "Loading invited users…");
  try {
    const { data, error } = await client.rpc("ledger_member_directory");
    if (error) throw error;
    membersList.innerHTML = "";
    for (const member of data || []) {
      const row = document.createElement("div");
      row.className = "entry-row";
      row.innerHTML = `
        <div class="entry-main"><strong></strong><span></span></div>
        <select class="member-role" aria-label="Access level">
          <option value="owner">Owner - full access</option>
          <option value="no_loans">No Loans - can edit everything else</option>
        </select>`;
      row.querySelector("strong").textContent = member.email || "Unknown email";
      row.querySelector("span").textContent = member.user_id;
      const roleSelect = row.querySelector("select");
      roleSelect.value = member.role || "owner";
      roleSelect.addEventListener("change", async () => {
        roleSelect.disabled = true;
        setMessage(membersMessage, "Saving access level…");
        try {
          const { error: roleError } = await client.rpc("set_ledger_member_role", {
            p_user_id: member.user_id,
            p_role: roleSelect.value
          });
          if (roleError) throw roleError;
          setMessage(membersMessage, "Access level updated.", true);
        } catch (roleUpdateError) {
          roleSelect.value = member.role || "owner";
          setMessage(membersMessage, roleUpdateError.message || "Could not update access level.");
        } finally {
          roleSelect.disabled = false;
        }
      });
      membersList.appendChild(row);
    }
    setMessage(membersMessage, "Choose the access level for each invited user.", true);
  } catch (error) {
    setMessage(membersMessage, error.message || "Could not load members.");
  }
}

membersButton?.addEventListener("click", openMembersDialog);

document.querySelector("#logout-button").addEventListener("click", async () => {
  setSyncStatus("Signing out…");
  try {
    const { error } = await client.auth.signOut();
    if (error) throw error;
    showAuthScreen();
  } catch (error) {
    setSyncStatus(`Could not sign out: ${error.message}`, true);
  }
});

document.querySelector("#csv-button").addEventListener("click", () => {
  const transactions = activeTransactions();
  if (!transactions.length) {
    setSyncStatus("There are no transactions in this period to export.", true);
    return;
  }
  if (!confirm("CSV files are not encrypted. Anyone with access to the exported file can read it. Continue?")) return;
  const escape = value => {
    const text = String(value ?? "");
    const safeText = /^[=+\-@]/.test(text) ? `'${text}` : text;
    return `"${safeText.replace(/"/g, '""')}"`;
  };
  const rows = [
    ["Date", "Description", "Category", "Type", "Amount", "Note"],
    ...transactions.map(item => [item.date, item.description, item.category, item.type, item.amount.toFixed(2), item.note])
  ];
  downloadFile(`financial-ledger-${localDateString()}.csv`, `\uFEFF${rows.map(row => row.map(escape).join(",")).join("\r\n")}`, "text/csv;charset=utf-8");
  setSyncStatus("CSV exported. The file is not encrypted.");
});

function downloadFile(filename, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

document.querySelector("#backup-button").addEventListener("click", async () => {
  try {
    const payload = await encryptPayload(ledger, sharedKey, sharedSalt);
    const backup = { format: BACKUP_FORMAT, version: BACKUP_VERSION, ...payload };
    downloadFile(`financial-ledger-backup-${localDateString()}.json`, JSON.stringify(backup, null, 2), "application/json");
    setSyncStatus("Encrypted backup downloaded. Keep your passphrase safe.");
  } catch (error) {
    setSyncStatus(`Could not create backup: ${error.message}`, true);
  }
});

document.querySelector("#restore-button").addEventListener("click", () => restoreFileInput.click());

restoreFileInput.addEventListener("change", event => {
  restoreFile = event.target.files[0] || null;
  event.target.value = "";
  if (!restoreFile) return;
  setMessage(restoreMessage, "");
  document.querySelector("#restore-passphrase").value = "";
  restoreDialog.showModal();
  document.querySelector("#restore-passphrase").focus();
});

restoreForm.addEventListener("submit", async event => {
  event.preventDefault();
  if (!restoreFile) return;
  setMessage(restoreMessage, "");
  try {
    const backup = JSON.parse(await restoreFile.text());
    if (
      backup?.format !== BACKUP_FORMAT ||
      ![1, BACKUP_VERSION].includes(backup.version) ||
      typeof backup.salt !== "string" ||
      typeof backup.iv !== "string" ||
      typeof backup.ciphertext !== "string"
    ) {
      throw new Error("This is not a supported encrypted ledger backup.");
    }
    const backupSalt = decodeBase64(backup.salt);
    if (backupSalt.length !== 16) throw new Error("The backup encryption data is damaged.");
    const backupKey = await deriveKey(document.querySelector("#restore-passphrase").value, backupSalt);
    const decrypted = await decryptPayload(backup, backupKey);
    const imported = backup.version === 1
      ? validateLedger({ ...decrypted, loans: [], savings: [] })
      : validateLedger(decrypted);
    if (!confirm("Replace the shared ledger with this backup? This affects everyone with access.")) return;
    await saveQueue.catch(() => {});
    await saveSharedLedger(imported);
    ledger = imported;
    render();
    restoreDialog.close();
    restoreFile = null;
    setSyncStatus("Backup restored and re-encrypted with the current shared passphrase.");
  } catch (error) {
    if (error.code === "40001" || /another user updated/i.test(error.message)) {
      document.querySelector("#reload-button").hidden = false;
    }
    setMessage(restoreMessage, `Could not restore backup: ${error.message}`);
  }
});

document.querySelector("#reload-button").addEventListener("click", async () => {
  const button = document.querySelector("#reload-button");
  button.disabled = true;
  try {
    const row = await loadSharedRecord();
    if (!row) throw new Error("Shared ledger record was not found.");
    const payload = await decryptPayload(row, sharedKey);
    const latest = validateLedger(payload);
    sharedRecord = row;
    revision = Number(row.revision);
    remoteRevision = revision;
    ledger = latest;
    render();
    document.querySelector("#reload-button").hidden = true;
    setSyncStatus("Latest shared changes loaded.");
  } catch (error) {
    setSyncStatus(`Could not load shared changes: ${error.message}`, true);
  } finally {
    button.disabled = false;
  }
});

document.querySelectorAll("[data-close-dialog]").forEach(button => {
  button.addEventListener("click", () => button.closest("dialog").close());
});

restoreDialog.addEventListener("close", () => {
  document.querySelector("#restore-passphrase").value = "";
  restoreFile = null;
});

async function initialize() {
  if (!window.crypto?.subtle || !window.crypto?.getRandomValues) {
    setMessage(authMessage, "This browser does not support secure encryption. Please use an up-to-date browser.");
    document.querySelector("#auth-submit").disabled = true;
    return;
  }
  const config = window.LEDGER_SUPABASE_CONFIG;
  if (!config?.url || !config?.publishableKey || !window.supabase?.createClient) {
    setMessage(authMessage, "Supabase is not configured. Check supabase-config.js and your internet connection.");
    return;
  }
  try {
    client = window.supabase.createClient(config.url, config.publishableKey, {
      auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true }
    });
    const settingsResponse = await fetch(`${config.url.replace(/\/+$/, "")}/auth/v1/settings`, {
      headers: { apikey: config.publishableKey }
    });
    if (!settingsResponse.ok) {
      throw new Error(`Could not verify Supabase sign-up settings (HTTP ${settingsResponse.status}).`);
    }
    const authSettings = await settingsResponse.json();
    if (authSettings.disable_signup !== true) {
      throw new Error("Public sign-ups are currently enabled. Disable them in Supabase Authentication settings before using this shared ledger.");
    }
    inviteOnlyReady = true;
    client.auth.onAuthStateChange((event, nextSession) => {
      if (event === "SIGNED_OUT") {
        showAuthScreen();
      } else if (event === "SIGNED_IN" && nextSession && !session?.user) {
        queueMicrotask(() => activateSession(nextSession));
      }
    });
    const { data, error } = await client.auth.getSession();
    if (error) throw error;
    if (data.session) await activateSession(data.session);
  } catch (error) {
    setMessage(authMessage, `Could not initialize Supabase: ${error.message}`);
  }
}

initialize();
