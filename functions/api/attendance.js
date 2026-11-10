// Cloudflare Pages Function -> POST /api/attendance (needs a D1 binding named DB)
// Body: { action: "login" | "checkin", name, pin }
// First login with a new name creates the account and sets its PIN.
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });

// ---- Late check-in alert (after 9:00 AM Bangladesh time) ----
const CUTOFF_SECONDS = 9 * 3600; // 9:00:00 AM
const TZ_OFFSET_HOURS = 6;       // Bangladesh is UTC+6 with no daylight saving
const ALERT_TO = "hasib0642@gmail.com";

function secondsIntoDay(now) {
  const local = new Date(now.getTime() + TZ_OFFSET_HOURS * 3600 * 1000);
  return local.getUTCHours() * 3600 + local.getUTCMinutes() * 60 + local.getUTCSeconds();
}

async function sendLateEmail(env, name, now) {
  if (!env.RESEND_API_KEY) return; // alerts stay off until the key is added in Cloudflare
  try {
    const when = now.toLocaleString("en-GB", { timeZone: "Asia/Dhaka", dateStyle: "full", timeStyle: "medium" });
    const minsLate = Math.floor((secondsIntoDay(now) - CUTOFF_SECONDS) / 60);
    const time = now.toLocaleTimeString("en-US", { timeZone: "Asia/Dhaka" });
    await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: "Bearer " + env.RESEND_API_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: "Attendance <onboarding@resend.dev>",
        to: [env.ALERT_EMAIL || ALERT_TO],
        subject: "Late check-in: " + name + " at " + time,
        text: name + " checked in late.\n\nTime: " + when + " (Bangladesh time)\nLate by: about " + minsLate + " minutes after 9:00 AM",
      }),
    });
  } catch (e) { /* never block a check-in because of an email problem */ }
}

const enc = new TextEncoder();
const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const cleanName = (v) => String(v || "").trim().replace(/\s+/g, " ").slice(0, 60);

async function hashPin(pin, saltHex) {
  const salt = Uint8Array.from(saltHex.match(/../g).map((h) => parseInt(h, 16)));
  const key = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, key, 256);
  return toHex(bits);
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function handle({ request, env, waitUntil }) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid request." }, 400); }

  const action = body.action === "checkin" || body.action === "checkout" ? body.action : "login";
  const name = cleanName(body.name);
  const pin = String(body.pin || "");
  if (!name) return json({ error: "Enter your name." }, 400);
  if (!/^\d{4,8}$/.test(pin)) return json({ error: "PIN must be 4 to 8 digits." }, 400);

  const key = name.toLowerCase();
  const now = new Date();

  // Create missing tables by themselves, so a skipped setup step cannot break sign-in
  const hasAllowed = await env.DB.prepare("SELECT 1 AS x FROM sqlite_master WHERE type = 'table' AND name = 'allowed'").first();
  if (!hasAllowed) {
    await env.DB.batch([
      env.DB.prepare("CREATE TABLE IF NOT EXISTS allowed (name_key TEXT PRIMARY KEY, name TEXT NOT NULL)"),
      // everyone who already has an account stays approved
      env.DB.prepare("INSERT OR IGNORE INTO allowed (name_key, name) SELECT name_key, name FROM users"),
    ]);
  }
  // Check-outs live in their own table
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS checkouts (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, checked_out_at TEXT NOT NULL)"
  ).run();

  // Only names on the approved list may sign in or register
  const approved = await env.DB.prepare("SELECT 1 FROM allowed WHERE name_key = ?").bind(key).first();
  if (!approved) return json({ error: "This name is not on the approved list. Ask the administrator to add you." }, 403);
  let user = await env.DB.prepare("SELECT * FROM users WHERE name_key = ?").bind(key).first();
  let created = false;

  if (!user) {
    const salt = toHex(crypto.getRandomValues(new Uint8Array(16)));
    const pin_hash = await hashPin(pin, salt);
    await env.DB.prepare("INSERT INTO users (name_key, name, salt, pin_hash) VALUES (?, ?, ?, ?)")
      .bind(key, name, salt, pin_hash).run();
    user = { name, failed: 0 };
    created = true;
  } else {
    if (user.locked_until && user.locked_until > now.toISOString()) {
      return json({ error: "Too many wrong PINs. Try again in 10 minutes." }, 429);
    }
    const ok = safeEqual(await hashPin(pin, user.salt), user.pin_hash);
    if (!ok) {
      const failed = user.failed + 1;
      if (failed >= 5) {
        const until = new Date(now.getTime() + 10 * 60 * 1000).toISOString();
        await env.DB.prepare("UPDATE users SET failed = 0, locked_until = ? WHERE name_key = ?").bind(until, key).run();
        return json({ error: "Too many wrong PINs. Try again in 10 minutes." }, 429);
      }
      await env.DB.prepare("UPDATE users SET failed = ? WHERE name_key = ?").bind(failed, key).run();
      return json({ error: "Wrong PIN." }, 401);
    }
    if (user.failed || user.locked_until) {
      await env.DB.prepare("UPDATE users SET failed = 0, locked_until = NULL WHERE name_key = ?").bind(key).run();
    }
  }

  let checkedInAt = null;
  let checkedOutAt = null;
  if (action === "checkin") {
    checkedInAt = now.toISOString(); // server time, so it can't be edited in the browser
    await env.DB.prepare("INSERT INTO attendance (name, checked_in_at) VALUES (?, ?)")
      .bind(user.name, checkedInAt).run();
    if (secondsIntoDay(now) > CUTOFF_SECONDS) waitUntil(sendLateEmail(env, user.name, now));
  }
  if (action === "checkout") {
    checkedOutAt = now.toISOString(); // server time, so it can't be edited in the browser
    await env.DB.prepare("INSERT INTO checkouts (name, checked_out_at) VALUES (?, ?)")
      .bind(user.name, checkedOutAt).run();
  }

  const { results } = await env.DB.prepare(
    "SELECT checked_in_at FROM attendance WHERE name = ? COLLATE NOCASE ORDER BY checked_in_at DESC LIMIT 1000"
  ).bind(user.name).all();

  const outs = await env.DB.prepare(
    "SELECT checked_out_at FROM checkouts WHERE name = ? COLLATE NOCASE ORDER BY checked_out_at DESC LIMIT 1000"
  ).bind(user.name).all();

  return json({
    name: user.name, created,
    checked_in_at: checkedInAt, checked_out_at: checkedOutAt,
    records: results.map((r) => r.checked_in_at),
    checkouts: outs.results.map((r) => r.checked_out_at),
  });
}

export async function onRequestPost(ctx) {
  try {
    return await handle(ctx);
  } catch (e) {
    // Show a readable reason instead of a blank "Request failed."
    return json({ error: "Server error: " + String((e && e.message) || e).slice(0, 160) }, 500);
  }
}
