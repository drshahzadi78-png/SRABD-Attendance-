// Cloudflare Pages Function -> POST /api/admin
// Needs: D1 binding named DB, and a secret named ADMIN_PASSWORD
// Body: { password, action: "list" | "add" | "remove" | "reset" | "unlock", name?, names? }
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });

const enc = new TextEncoder();
const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const digest = async (v) => toHex(await crypto.subtle.digest("SHA-256", enc.encode(String(v))));
const cleanName = (v) => String(v || "").trim().replace(/\s+/g, " ").slice(0, 60);

async function ensureTables(env) {
  await env.DB.batch([
    env.DB.prepare("CREATE TABLE IF NOT EXISTS allowed (name_key TEXT PRIMARY KEY, name TEXT NOT NULL)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS admin_lock (id INTEGER PRIMARY KEY, failed INTEGER NOT NULL DEFAULT 0, locked_until TEXT)"),
    env.DB.prepare("INSERT OR IGNORE INTO admin_lock (id, failed) VALUES (1, 0)"),
  ]);
}

// Returns an error Response, or null when the password is correct
async function authorize(env, password) {
  if (!env.ADMIN_PASSWORD) return json({ error: "The admin password is not set yet. Add the ADMIN_PASSWORD secret in Cloudflare." }, 503);
  const lock = await env.DB.prepare("SELECT failed, locked_until FROM admin_lock WHERE id = 1").first();
  const now = new Date();
  if (lock && lock.locked_until && lock.locked_until > now.toISOString()) {
    return json({ error: "Too many wrong passwords. Try again in 15 minutes." }, 429);
  }
  const ok = (await digest(password)) === (await digest(env.ADMIN_PASSWORD));
  if (ok) {
    if (lock && (lock.failed || lock.locked_until)) {
      await env.DB.prepare("UPDATE admin_lock SET failed = 0, locked_until = NULL WHERE id = 1").run();
    }
    return null;
  }
  const failed = (lock ? lock.failed : 0) + 1;
  if (failed >= 5) {
    const until = new Date(now.getTime() + 15 * 60 * 1000).toISOString();
    await env.DB.prepare("UPDATE admin_lock SET failed = 0, locked_until = ? WHERE id = 1").bind(until).run();
    return json({ error: "Too many wrong passwords. Try again in 15 minutes." }, 429);
  }
  await env.DB.prepare("UPDATE admin_lock SET failed = ? WHERE id = 1").bind(failed).run();
  return json({ error: "Wrong password." }, 401);
}

async function listNames(env) {
  const now = new Date().toISOString();
  const { results } = await env.DB.prepare(
    `SELECT a.name AS name, u.name_key AS reg, u.locked_until AS locked_until
     FROM allowed a LEFT JOIN users u ON u.name_key = a.name_key
     ORDER BY a.name COLLATE NOCASE`
  ).all();
  return results.map((r) => ({
    name: r.name,
    status: !r.reg ? "waiting" : r.locked_until && r.locked_until > now ? "locked" : "active",
  }));
}

export async function onRequestPost({ request, env }) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid request." }, 400); }

  await ensureTables(env);
  const denied = await authorize(env, body.password);
  if (denied) return denied;

  const action = String(body.action || "list");
  const key = cleanName(body.name).toLowerCase();

  if (action === "add") {
    const names = (Array.isArray(body.names) ? body.names : []).map(cleanName).filter(Boolean).slice(0, 200);
    if (!names.length) return json({ error: "Enter at least one name." }, 400);
    await env.DB.batch(names.map((n) =>
      env.DB.prepare("INSERT OR IGNORE INTO allowed (name_key, name) VALUES (?, ?)").bind(n.toLowerCase(), n)));
  } else if (action === "remove" && key) {
    await env.DB.prepare("DELETE FROM allowed WHERE name_key = ?").bind(key).run();
  } else if (action === "reset" && key) {
    await env.DB.prepare("DELETE FROM users WHERE name_key = ?").bind(key).run();
  } else if (action === "unlock" && key) {
    await env.DB.prepare("UPDATE users SET failed = 0, locked_until = NULL WHERE name_key = ?").bind(key).run();
  } else if (action !== "list") {
    return json({ error: "Unknown action." }, 400);
  }

  return json({ names: await listNames(env) });
}
