// Cloudflare Pages Function -> POST /api/attendance (needs a D1 binding named DB)
// Body: { action: "login" | "checkin", name, pin }
// First login with a new name creates the account and sets its PIN.
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });

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

export async function onRequestPost({ request, env }) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid request." }, 400); }

  const action = body.action === "checkin" ? "checkin" : "login";
  const name = cleanName(body.name);
  const pin = String(body.pin || "");
  if (!name) return json({ error: "Enter your name." }, 400);
  if (!/^\d{4,8}$/.test(pin)) return json({ error: "PIN must be 4 to 8 digits." }, 400);

  const key = name.toLowerCase();
  const now = new Date();
  let user = await env.DB.prepare("SELECT * FROM users WHERE name_key = ?").bind(key).first();
  let created = false;

  if (!user) {
    if (action !== "login") return json({ error: "Sign in first." }, 401);
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
  if (action === "checkin") {
    checkedInAt = now.toISOString(); // server time, so it can't be edited in the browser
    await env.DB.prepare("INSERT INTO attendance (name, checked_in_at) VALUES (?, ?)")
      .bind(user.name, checkedInAt).run();
  }

  const { results } = await env.DB.prepare(
    "SELECT checked_in_at FROM attendance WHERE name = ? COLLATE NOCASE ORDER BY checked_in_at DESC LIMIT 1000"
  ).bind(user.name).all();

  return json({ name: user.name, created, checked_in_at: checkedInAt, records: results.map((r) => r.checked_in_at) });
}
