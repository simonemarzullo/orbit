(() => {
  "use strict";

  const VAULT_KEY = "orbit.vault.v1";
  const KDF_ITERS = 210000;
  const FAIL_MAX = 6;
  const FAIL_MS = 30000;
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  const $ = (id) => document.getElementById(id);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  const state = {
    view: "boot",
    panel: "deck",
    master: null,
    wrap: null,
    recoveryWrap: null,
    username: "",
    modules: [],
    query: "",
    channel: "ALL",
    activeId: null,
    installEvent: null,
    pendingRecovery: null
  };

  let clockTimer = 0;
  let toastTimer = 0;
  let dialogResolver = null;
  let failCount = 0;
  let failUntil = 0;

  /* ── crypto ─────────────────────────────────────────────── */

  function bufToB64(buf) {
    const bytes = new Uint8Array(buf);
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s);
  }

  function b64ToBuf(b64) {
    const s = atob(b64);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }

  async function deriveKey(secret, salt, iters = KDF_ITERS) {
    const base = await crypto.subtle.importKey("raw", enc.encode(secret), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: iters, hash: "SHA-256" },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function encryptBytes(key, bytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes);
    return { iv: bufToB64(iv), data: bufToB64(data) };
  }

  async function decryptBytes(key, blob) {
    return crypto.subtle.decrypt({ name: "AES-GCM", iv: b64ToBuf(blob.iv) }, key, b64ToBuf(blob.data));
  }

  async function encryptPayload(key, data) {
    return encryptBytes(key, enc.encode(JSON.stringify(data)));
  }

  async function decryptPayload(key, payload) {
    return JSON.parse(dec.decode(await decryptBytes(key, payload)));
  }

  function readVault() {
    try {
      const raw = localStorage.getItem(VAULT_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  }

  function writeVault(vault) {
    localStorage.setItem(VAULT_KEY, JSON.stringify(vault));
  }

  function clearVault() {
    localStorage.removeItem(VAULT_KEY);
  }

  function makeRecoveryKey() {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase().match(/.{4}/g).join("-");
  }

  function normRecovery(s) {
    return String(s || "").replace(/[^a-fA-F0-9]/g, "").toUpperCase();
  }

  function normHandle(s) {
    return String(s || "").trim().toLowerCase();
  }

  async function importMaster(raw) {
    return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
  }

  async function wrapMaster(secret, raw) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(secret, salt);
    const blob = await encryptBytes(key, raw);
    return { salt: bufToB64(salt), ...blob };
  }

  async function unwrapMaster(secret, wrap) {
    const key = await deriveKey(secret, b64ToBuf(wrap.salt));
    return decryptBytes(key, wrap);
  }

  async function persist() {
    if (!state.master || !state.wrap) return;
    const payload = await encryptPayload(state.master, { modules: state.modules, username: state.username });
    writeVault({
      v: 2,
      handle: state.username,
      wrap: state.wrap,
      recovery: state.recoveryWrap || null,
      payload
    });
  }

  async function sessionFromRaw(raw, wrap, recoveryWrap, data) {
    state.master = await importMaster(raw);
    state.wrap = wrap;
    state.recoveryWrap = recoveryWrap || null;
    state.username = data.username || "";
    state.modules = Array.isArray(data.modules) ? data.modules : [];
  }

  async function createVault(user, pass) {
    const master = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", master));
    const recovery = makeRecoveryKey();
    state.master = master;
    state.username = String(user || "").trim();
    state.modules = [];
    state.wrap = await wrapMaster(pass, raw);
    state.recoveryWrap = await wrapMaster(normRecovery(recovery), raw);
    await persist();
    raw.fill(0);
    return recovery;
  }

  async function unlockWith(user, pass) {
    const vault = readVault();
    if (!vault) throw new Error("NO VAULT");
    if (vault.v === 2 && vault.wrap && vault.payload) {
      const raw = new Uint8Array(await unwrapMaster(pass, vault.wrap));
      const master = await importMaster(raw);
      const data = await decryptPayload(master, vault.payload);
      const stored = data.username || vault.handle || "";
      if (stored && normHandle(user) !== normHandle(stored)) {
        raw.fill(0);
        throw new Error("AUTH");
      }
      await sessionFromRaw(raw, vault.wrap, vault.recovery, { ...data, username: stored || String(user || "").trim() });
      raw.fill(0);
      if (!stored && state.username) await persist();
      if (!vault.recovery) return await issueRecovery();
      return null;
    }
    if (!vault.salt || !vault.data) throw new Error("AUTH");
    const oldKey = await deriveKey(pass, b64ToBuf(vault.salt), 120000);
    const data = await decryptPayload(oldKey, vault);
    const stored = data.username || vault.handle || "";
    if (stored && normHandle(user) !== normHandle(stored)) throw new Error("AUTH");
    const master = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", master));
    const recovery = makeRecoveryKey();
    state.master = master;
    state.username = stored || String(user || "").trim();
    state.modules = Array.isArray(data.modules) ? data.modules : [];
    state.wrap = await wrapMaster(pass, raw);
    state.recoveryWrap = await wrapMaster(normRecovery(recovery), raw);
    await persist();
    raw.fill(0);
    return recovery;
  }

  async function restoreWith(user, recoveryKey, newPass) {
    const vault = readVault();
    if (!vault || !vault.recovery || !vault.payload) throw new Error("AUTH");
    const stored = vault.handle || "";
    if (stored && normHandle(user) !== normHandle(stored)) throw new Error("AUTH");
    const raw = new Uint8Array(await unwrapMaster(normRecovery(recoveryKey), vault.recovery));
    const master = await importMaster(raw);
    const data = await decryptPayload(master, vault.payload);
    state.master = master;
    state.username = data.username || stored || String(user || "").trim();
    state.modules = Array.isArray(data.modules) ? data.modules : [];
    state.wrap = await wrapMaster(newPass, raw);
    state.recoveryWrap = vault.recovery;
    await persist();
    raw.fill(0);
  }

  async function issueRecovery() {
    if (!state.master) throw new Error("AUTH");
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", state.master));
    const recovery = makeRecoveryKey();
    state.recoveryWrap = await wrapMaster(normRecovery(recovery), raw);
    await persist();
    raw.fill(0);
    return recovery;
  }

  async function rewrapPassword(newPass) {
    if (!state.master) throw new Error("AUTH");
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", state.master));
    state.wrap = await wrapMaster(newPass, raw);
    await persist();
    raw.fill(0);
  }

  /* ── helpers ────────────────────────────────────────────── */

  function esc(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function uid() {
    if (crypto.randomUUID) return crypto.randomUUID();
    return "orb-" + Math.random().toString(16).slice(2) + Date.now().toString(16);
  }

  function serialFrom(id) {
    const compact = id.replace(/-/g, "").slice(0, 6).toUpperCase();
    return `ORB-${compact.slice(0, 3)}-${compact.slice(3)}`;
  }

  function hostOf(url) {
    try {
      return new URL(url).host.replace(/^www\./, "");
    } catch {
      return url;
    }
  }

  function normalizeUrl(raw) {
    const t = String(raw || "").trim();
    if (!t) return "";
    const candidate = /^[a-z][a-z0-9+.-]*:/i.test(t) ? t : "https://" + t;
    let parsed;
    try {
      parsed = new URL(candidate);
    } catch {
      return "";
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return "";
    return parsed.href;
  }

  function callsignFromUrl(url) {
    const host = hostOf(url);
    const base = host.split(".")[0] || host;
    return base.replace(/[-_]/g, " ").toUpperCase();
  }

  function fmtTime(ts) {
    if (!ts) return "—";
    const d = new Date(ts);
    const p = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
  }

  function channels() {
    const set = new Map();
    for (const m of state.modules) {
      const ch = (m.channel || "OPEN").trim().toUpperCase();
      set.set(ch, (set.get(ch) || 0) + 1);
    }
    return [...set.keys()].sort();
  }

  function filtered() {
    const q = state.query.trim().toLowerCase();
    return state.modules
      .filter((m) => {
        const ch = (m.channel || "OPEN").trim().toUpperCase();
        if (state.channel !== "ALL" && ch !== state.channel) return false;
        if (!q) return true;
        return [m.callsign, m.url, m.channel, m.notes, hostOf(m.url)]
          .join(" ")
          .toLowerCase()
          .includes(q);
      })
      .sort((a, b) => Number(b.pinned) - Number(a.pinned) || (b.openedAt || 0) - (a.openedAt || 0) || b.createdAt - a.createdAt);
  }

  function isStandalone() {
    return window.matchMedia("(display-mode: standalone)").matches || window.navigator.standalone === true;
  }

  /* ── views ──────────────────────────────────────────────── */

  function showView(name) {
    state.view = name;
    $$(".view").forEach((el) => el.classList.toggle("is-on", el.id === "view-" + name));
  }

  function go(panel, id) {
    if (panel === "new" && !id) resetForm();
    state.panel = panel;
    if (id) state.activeId = id;
    $$(".panel").forEach((el) => el.classList.toggle("is-on", el.id === "panel-" + panel));
    $$("[data-go]").forEach((el) => el.classList.toggle("is-on", el.getAttribute("data-go") === panel));
    const hash = panel === "module" && state.activeId ? `#/module/${state.activeId}` : `#/${panel}`;
    if (location.hash !== hash) history.replaceState(null, "", hash);
    $("stage").scrollTop = 0;
    window.scrollTo(0, 0);
    if (panel === "module") renderModule();
    if (panel === "deck") renderDeck();
    if (panel === "new") $("mod-callsign").focus();
  }

  function readHash() {
    const h = location.hash.replace(/^#\/?/, "");
    if (h.startsWith("module/")) {
      const id = h.slice(7);
      if (state.modules.some((m) => m.id === id)) go("module", id);
      else go("deck");
      return;
    }
    if (h === "new" || h === "systems" || h === "deck") go(h);
    else go("deck");
  }

  /* ── render ─────────────────────────────────────────────── */

  function renderDeck() {
    const list = filtered();
    const n = state.modules.length;
    $("rail-count").textContent = `// ${String(n).padStart(2, "0")} MODULE${n === 1 ? "" : "S"}`;
    $("rail-handle").textContent = state.username ? `*| ${state.username}` : "*| —";
    if ($("id-user") && !$("id-user").matches(":focus")) $("id-user").value = state.username;

    const chans = ["ALL", ...channels()];
    $("channels").innerHTML = chans
      .map(
        (ch) =>
          `<button type="button" class="chip${state.channel === ch ? " is-on" : ""}" data-channel="${esc(ch)}">// ${esc(ch)}</button>`
      )
      .join("");

    $("channel-list").innerHTML = channels()
      .map((ch) => `<option value="${esc(ch)}"></option>`)
      .join("");

    if (!list.length) {
      const emptyCopy = n
        ? "No plates match this scan."
        : "No modules on this orbit.";
      $("deck").innerHTML = `
        <div class="empty">
          <p class="kicker">*| EMPTY</p>
          <h2 class="headline">${emptyCopy}</h2>
          <button class="act primary" type="button" data-go="new">NEW MODULE</button>
        </div>`;
      return;
    }

    $("deck").innerHTML = list
      .map((m, i) => {
        const ch = (m.channel || "OPEN").toUpperCase();
        return `
        <article class="plate" data-id="${esc(m.id)}">
          <div class="rivet tl"></div>
          <div class="rivet br"></div>
          ${m.pinned ? `<span class="pin-mark">*|</span>` : ""}
          <a class="plate-open" href="${esc(m.url)}" target="_blank" rel="noopener noreferrer" data-open="${esc(m.id)}">
            <header class="plate-head">
              <span class="kicker">// ${esc(ch)}</span>
              <span class="idx">${String(i + 1).padStart(2, "0")}</span>
            </header>
            <h2 class="plate-title">${esc(m.callsign)}</h2>
            <p class="plate-host">${esc(hostOf(m.url))}</p>
            <footer class="plate-foot">
              <span class="serial">${esc(m.serial)}</span>
              <span class="open-lbl">OPEN →</span>
            </footer>
          </a>
          <button class="icon-btn plate-info" type="button" data-info="${esc(m.id)}" aria-label="Module ${esc(m.callsign)}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4">
              <circle cx="12" cy="12" r="9"/>
              <path d="M12 11v5M12 8h.01"/>
            </svg>
          </button>
        </article>`;
      })
      .join("");
  }

  function renderModule() {
    const m = state.modules.find((x) => x.id === state.activeId);
    if (!m) {
      go("deck");
      return;
    }
    $("mod-kicker").textContent = m.pinned ? "*| PINNED" : "*| MODULE";
    $("mod-title").textContent = m.callsign;
    $("mod-host").textContent = m.url;
    $("mod-serial").textContent = m.serial;
    $("mod-ch").textContent = (m.channel || "OPEN").toUpperCase();
    $("mod-opened").textContent = fmtTime(m.openedAt);
    $("mod-created").textContent = fmtTime(m.createdAt);
    $("mod-notes-view").textContent = m.notes || "";
    $("mod-open").href = m.url;
    $("mod-pin").textContent = m.pinned ? "UNPIN" : "PIN";
  }

  function resetForm() {
    $("mod-id").value = "";
    $("mod-callsign").value = "";
    $("mod-url").value = "";
    $("mod-channel").value = "";
    $("mod-notes").value = "";
    $("mod-error").textContent = "";
    $("panel-new").querySelector(".headline").textContent = "Assign a callsign";
    $("panel-new").querySelector(".kicker").textContent = "*| NEW MODULE";
  }

  function fillForm(m) {
    $("mod-id").value = m.id;
    $("mod-callsign").value = m.callsign;
    $("mod-url").value = m.url;
    $("mod-channel").value = m.channel || "";
    $("mod-notes").value = m.notes || "";
    $("mod-error").textContent = "";
    $("panel-new").querySelector(".headline").textContent = "Revise this module";
    $("panel-new").querySelector(".kicker").textContent = "*| REVISE";
  }

  function tickClock() {
    const d = new Date();
    const p = (n) => String(n).padStart(2, "0");
    $("clock").textContent = `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  }

  function toast(msg) {
    const el = $("toast");
    el.textContent = "> " + msg;
    el.classList.add("is-on");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove("is-on"), 2800);
  }

  function confirmDialog({ kicker, title, copy, ok, abort = "ABORT", danger = true }) {
    $("dialog-kicker").textContent = kicker;
    $("dialog-title").textContent = title;
    $("dialog-copy").textContent = copy;
    $("dialog-ok").textContent = ok;
    $("dialog-abort").textContent = abort;
    $("dialog-ok").className = "act " + (danger ? "abort" : "primary");
    $("dialog").classList.add("is-on");
    $("dialog-abort").focus();
    return new Promise((resolve) => {
      dialogResolver = resolve;
    });
  }

  function closeDialog(result) {
    $("dialog").classList.remove("is-on");
    if (dialogResolver) {
      const r = dialogResolver;
      dialogResolver = null;
      r(result);
    }
  }

  /* ── boot / gate ────────────────────────────────────────── */

  function boot() {
    const log = $("boot-log");
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const line1 = "CONNECTING TO ORBIT…";
    if (reduced) {
      log.textContent = "> " + line1 + "\n> LINK ESTABLISHED";
      setTimeout(afterBoot, 300);
      return;
    }
    let i = 0;
    log.innerHTML = "> <span class=\"cursor\">_</span>";
    const type = setInterval(() => {
      i += 1;
      log.innerHTML = "> " + esc(line1.slice(0, i)) + '<span class="cursor">_</span>';
      if (i >= line1.length) {
        clearInterval(type);
        setTimeout(() => {
          log.innerHTML = "> " + esc(line1) + "\n> LINK ESTABLISHED";
          setTimeout(afterBoot, 180);
        }, 240);
      }
    }, 22);
  }

  function afterBoot() {
    setupGate();
    showView("gate");
    $("gate-user").focus();
  }

  function setupGate() {
    $("gate-kicker").textContent = "*| LOGIN";
    $("gate-title").textContent = "Orbit";
    $("gate-error").textContent = "";
    $("restore-error").textContent = "";
    $("gate-form").hidden = false;
    $("restore-form").hidden = true;
    $("restore-open").hidden = false;
    const vault = readVault();
    $("gate-user").value = vault && vault.handle ? vault.handle : "";
    $("restore-user").value = $("gate-user").value;
  }

  function showRecovery(key) {
    state.pendingRecovery = null;
    $("recovery-key").textContent = key;
    showView("recovery");
  }

  async function enterShell() {
    document.documentElement.classList.toggle("standalone", isStandalone());
    showView("shell");
    tickClock();
    clearInterval(clockTimer);
    clockTimer = setInterval(tickClock, 1000);
    renderDeck();
    readHash();
    updateInstallUI();
  }

  function lock() {
    state.master = null;
    state.wrap = null;
    state.recoveryWrap = null;
    state.modules = [];
    state.query = "";
    state.channel = "ALL";
    state.activeId = null;
    $("scan").value = "";
    state.username = "";
    clearInterval(clockTimer);
    setupGate();
    showView("gate");
    $("gate-key").value = "";
    $("gate-user").focus();
    history.replaceState(null, "", "#/");
    toast("LOCKED");
  }

  function lockedOut() {
    const wait = failUntil - Date.now();
    if (wait > 0) {
      $("gate-error").textContent = "Wait " + Math.ceil(wait / 1000) + "s, then retry.";
      return true;
    }
    return false;
  }

  function noteFail() {
    failCount += 1;
    if (failCount >= FAIL_MAX) {
      failUntil = Date.now() + FAIL_MS;
      failCount = 0;
    }
  }

  /* ── install ────────────────────────────────────────────── */

  function updateInstallUI() {
    const standalone = isStandalone();
    $("note-standalone").hidden = !standalone;
    $("note-browser").hidden = standalone;
    $("install-btn").hidden = standalone || !state.installEvent;
  }

  /* ── events ─────────────────────────────────────────────── */

  $("gate-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (lockedOut()) return;
    const user = $("gate-user").value.trim();
    const pass = $("gate-key").value;
    $("gate-error").textContent = "";
    $("gate-submit").disabled = true;
    if (!user) {
      $("gate-error").textContent = "Username required.";
      $("gate-submit").disabled = false;
      return;
    }
    if (pass.length < 4) {
      $("gate-error").textContent = "Password too short — four characters minimum.";
      $("gate-submit").disabled = false;
      return;
    }
    try {
      const vault = readVault();
      const recovery = vault ? await unlockWith(user, pass) : await createVault(user, pass);
      failCount = 0;
      $("gate-key").value = "";
      if (recovery) showRecovery(recovery);
      else await enterShell();
    } catch {
      noteFail();
      $("gate-error").textContent = "Login rejected.";
    } finally {
      $("gate-submit").disabled = false;
    }
  });

  $("restore-open").addEventListener("click", () => {
    $("gate-form").hidden = true;
    $("restore-form").hidden = false;
    $("restore-open").hidden = true;
    $("restore-user").value = $("gate-user").value;
    $("restore-key").focus();
  });

  $("restore-abort").addEventListener("click", () => {
    $("restore-form").hidden = true;
    $("gate-form").hidden = false;
    $("restore-open").hidden = false;
    $("restore-key").value = "";
    $("restore-pass").value = "";
    $("restore-error").textContent = "";
  });

  $("restore-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (lockedOut()) {
      $("restore-error").textContent = $("gate-error").textContent;
      return;
    }
    const user = $("restore-user").value.trim();
    const rec = $("restore-key").value;
    const pass = $("restore-pass").value;
    $("restore-error").textContent = "";
    if (!user || normRecovery(rec).length !== 32 || pass.length < 4) {
      $("restore-error").textContent = "Username, restore key, and new password required.";
      return;
    }
    try {
      await restoreWith(user, rec, pass);
      failCount = 0;
      $("restore-key").value = "";
      $("restore-pass").value = "";
      toast("PASSWORD RESTORED");
      await enterShell();
    } catch {
      noteFail();
      $("restore-error").textContent = "Restore rejected.";
    }
  });

  $("recovery-copy").addEventListener("click", async () => {
    const key = $("recovery-key").textContent;
    try {
      await navigator.clipboard.writeText(key);
      toast("KEY COPIED");
    } catch {
      toast("COPY FAILED");
    }
  });

  $("recovery-done").addEventListener("click", () => enterShell());

  $("recovery-issue").addEventListener("click", async () => {
    const key = await issueRecovery();
    showRecovery(key);
  });

  document.addEventListener("click", async (e) => {
    const goBtn = e.target.closest("[data-go]");
    if (goBtn) {
      e.preventDefault();
      go(goBtn.getAttribute("data-go"));
      return;
    }
    const lockBtn = e.target.closest("[data-action='lock']");
    if (lockBtn) {
      e.preventDefault();
      lock();
      return;
    }
    const chip = e.target.closest("[data-channel]");
    if (chip) {
      state.channel = chip.getAttribute("data-channel");
      renderDeck();
      return;
    }
    const info = e.target.closest("[data-info]");
    if (info) {
      e.preventDefault();
      go("module", info.getAttribute("data-info"));
      return;
    }
  });

  $("deck").addEventListener("click", async (e) => {
    const open = e.target.closest("[data-open]");
    if (!open) return;
    const id = open.getAttribute("data-open");
    const m = state.modules.find((x) => x.id === id);
    if (!m) return;
    m.openedAt = Date.now();
    await persist();
  });

  $("scan").addEventListener("input", () => {
    state.query = $("scan").value;
    renderDeck();
  });

  $("mod-url").addEventListener("blur", () => {
    const url = normalizeUrl($("mod-url").value);
    if (url) $("mod-url").value = url;
    if (url && !$("mod-callsign").value) $("mod-callsign").value = callsignFromUrl(url);
  });

  $("module-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("mod-error").textContent = "";
    const callsign = $("mod-callsign").value.trim();
    const url = normalizeUrl($("mod-url").value);
    const channel = $("mod-channel").value.trim().toUpperCase();
    const notes = $("mod-notes").value.trim();
    if (!callsign) {
      $("mod-error").textContent = "Callsign required.";
      return;
    }
    try {
      new URL(url);
    } catch {
      $("mod-error").textContent = "URL rejected — add a host.";
      return;
    }
    const id = $("mod-id").value;
    if (id) {
      const m = state.modules.find((x) => x.id === id);
      if (!m) return;
      m.callsign = callsign;
      m.url = url;
      m.channel = channel;
      m.notes = notes;
      await persist();
      toast("MODULE REVISED");
      go("module", id);
    } else {
      const m = {
        id: uid(),
        callsign,
        url,
        channel,
        notes,
        serial: "",
        pinned: false,
        createdAt: Date.now(),
        openedAt: null
      };
      m.serial = serialFrom(m.id);
      state.modules.unshift(m);
      await persist();
      toast("MODULE COMMITTED");
      go("deck");
    }
  });

  $("mod-open").addEventListener("click", async () => {
    const m = state.modules.find((x) => x.id === state.activeId);
    if (!m) return;
    m.openedAt = Date.now();
    await persist();
    renderModule();
  });

  $("mod-pin").addEventListener("click", async () => {
    const m = state.modules.find((x) => x.id === state.activeId);
    if (!m) return;
    m.pinned = !m.pinned;
    await persist();
    renderModule();
    toast(m.pinned ? "PINNED" : "UNPINNED");
  });

  $("mod-edit").addEventListener("click", () => {
    const m = state.modules.find((x) => x.id === state.activeId);
    if (!m) return;
    fillForm(m);
    go("new");
  });

  $("mod-retire").addEventListener("click", async () => {
    const ok = await confirmDialog({
      kicker: "*| RETIRE",
      title: "Retire this module?",
      copy: "The plate is removed from this deck. The destination is unchanged.",
      ok: "RETIRE"
    });
    if (!ok) return;
    state.modules = state.modules.filter((m) => m.id !== state.activeId);
    await persist();
    toast("MODULE RETIRED");
    go("deck");
  });

  $("id-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("id-error").textContent = "";
    const user = $("id-user").value.trim();
    const a = $("id-pass").value;
    const b = $("id-confirm").value;
    if (!user) {
      $("id-error").textContent = "Username required.";
      return;
    }
    if (a || b) {
      if (a.length < 4) {
        $("id-error").textContent = "Password too short — four characters minimum.";
        return;
      }
      if (a !== b) {
        $("id-error").textContent = "Passwords do not match.";
        return;
      }
      await rewrapPassword(a);
      state.username = user;
      await persist();
      $("id-pass").value = "";
      $("id-confirm").value = "";
      toast("PASSWORD UPDATED");
    } else {
      state.username = user;
      await persist();
      toast("USERNAME UPDATED");
    }
    renderDeck();
  });

  $("export-btn").addEventListener("click", () => {
    const blob = new Blob(
      [JSON.stringify({ v: 1, exportedAt: Date.now(), modules: state.modules }, null, 2)],
      { type: "application/json" }
    );
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "orbit-deck.json";
    a.click();
    URL.revokeObjectURL(a.href);
    toast("DECK EXPORTED");
  });

  $("import-btn").addEventListener("click", () => $("import-file").click());

  $("import-file").addEventListener("change", async (e) => {
    const file = e.target.files && e.target.files[0];
    e.target.value = "";
    if (!file) return;
    try {
      const json = JSON.parse(await file.text());
      const incoming = Array.isArray(json) ? json : json.modules;
      if (!Array.isArray(incoming)) throw new Error("shape");
      let added = 0;
      const urls = new Set(state.modules.map((m) => m.url));
      for (const raw of incoming) {
        if (!raw || !raw.url) continue;
        const url = normalizeUrl(String(raw.url));
        try {
          new URL(url);
        } catch {
          continue;
        }
        if (urls.has(url)) continue;
        const m = {
          id: uid(),
          callsign: String(raw.callsign || callsignFromUrl(url)).slice(0, 80),
          url,
          channel: String(raw.channel || "").toUpperCase().slice(0, 32),
          notes: String(raw.notes || "").slice(0, 500),
          serial: "",
          pinned: Boolean(raw.pinned),
          createdAt: Number(raw.createdAt) || Date.now(),
          openedAt: Number(raw.openedAt) || null
        };
        m.serial = serialFrom(m.id);
        state.modules.unshift(m);
        urls.add(url);
        added += 1;
      }
      await persist();
      renderDeck();
      toast(`${String(added).padStart(2, "0")} MODULES IMPORTED`);
    } catch {
      toast("IMPORT REJECTED");
    }
  });

  $("wipe-btn").addEventListener("click", async () => {
    const ok = await confirmDialog({
      kicker: "*| ABORT",
      title: "Wipe this deck?",
      copy: "Every module and the access key on this device will be destroyed.",
      ok: "WIPE DECK"
    });
    if (!ok) return;
    clearVault();
    state.master = null;
    state.wrap = null;
    state.recoveryWrap = null;
    state.username = "";
    state.modules = [];
    toast("DECK WIPED");
    setupGate();
    showView("gate");
    $("gate-user").focus();
  });

  $("dialog-abort").addEventListener("click", () => closeDialog(false));
  $("dialog-ok").addEventListener("click", () => closeDialog(true));
  $("dialog").addEventListener("click", (e) => {
    if (e.target.id === "dialog") closeDialog(false);
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && $("dialog").classList.contains("is-on")) {
      closeDialog(false);
    }
  });

  $("install-btn").addEventListener("click", async () => {
    if (!state.installEvent) return;
    state.installEvent.prompt();
    await state.installEvent.userChoice;
    state.installEvent = null;
    updateInstallUI();
  });

  window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();
    state.installEvent = e;
    updateInstallUI();
  });

  window.addEventListener("hashchange", () => {
    if (state.view === "shell") readHash();
  });

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("./sw.js").catch(() => {});
  }

  boot();
})();
