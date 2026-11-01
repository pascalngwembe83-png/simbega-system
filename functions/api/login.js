const encoder = new TextEncoder();

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fromBase64Url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function hashPassword(password, salt, iterations) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256"
    },
    key,
    256
  );

  return new Uint8Array(bits);
}

async function createPasswordHash(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iterations = 210000;
  const hash = await hashPassword(password, salt, iterations);

  return `pbkdf2$${iterations}$${toBase64Url(salt)}$${toBase64Url(hash)}`;
}

async function verifyPassword(password, stored) {
  const parts = stored.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;

  const iterations = Number(parts[1]);
  if (!Number.isInteger(iterations) || iterations < 100000 || iterations > 500000) {
    return false;
  }

  const salt = fromBase64Url(parts[2]);
  const expected = fromBase64Url(parts[3]);
  const actual = await hashPassword(password, salt, iterations);

  if (actual.length !== expected.length) return false;

  let difference = 0;
  for (let i = 0; i < actual.length; i++) {
    difference |= actual[i] ^ expected[i];
  }

  return difference === 0;
}

async function createToken(user, secret) {
  const header = toBase64Url(
    encoder.encode(JSON.stringify({ alg: "HS256", typ: "JWT" }))
  );

  const payload = toBase64Url(
    encoder.encode(JSON.stringify({
      id: user.id,
      username: user.username,
      role: user.role,
      exp: Math.floor(Date.now() / 1000) + 28800
    }))
  );

  const message = `${header}.${payload}`;

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(message)
  );

  return `${message}.${toBase64Url(new Uint8Array(signature))}`;
}

export async function onRequestPost({ request, env }) {
  try {
    if (!env.DB) {
      return Response.json({ success: false, message: "Database haijaunganishwa." }, { status: 500 });
    }

    const body = await request.json();
    const action = body.action;

    if (action === "setup_admin") {
      if (!env.ADMIN_SETUP_KEY || body.setupKey !== env.ADMIN_SETUP_KEY) {
        return Response.json({ success: false, message: "Ruhusa haijathibitishwa." }, { status: 403 });
      }

      const username = String(body.username || "").trim();
      const password = String(body.password || "");

      if (!username || password.length < 12) {
        return Response.json({ success: false, message: "Jina linahitajika na nywila iwe na angalau herufi 12." }, { status: 400 });
      }

      const existing = await env.DB.prepare(
        "SELECT id FROM user_accounts WHERE role = 'admin' LIMIT 1"
      ).first();

      if (existing) {
        return Response.json({ success: false, message: "Akaunti ya Mkuu wa Shule tayari ipo." }, { status: 409 });
      }

      const passwordHash = await createPasswordHash(password);

      await env.DB.prepare(
        "INSERT INTO user_accounts (username, password_hash, role) VALUES (?, ?, 'admin')"
      ).bind(username, passwordHash).run();

      return Response.json({ success: true, message: "Akaunti ya Mkuu wa Shule imetengenezwa." });
    }

    if (action === "login") {
      const username = String(body.username || "").trim();
      const password = String(body.password || "");

      const user = await env.DB.prepare(
        "SELECT id, username, password_hash, role, is_active FROM user_accounts WHERE username = ? LIMIT 1"
      ).bind(username).first();

      if (!user || user.is_active === 0 || !(await verifyPassword(password, user.password_hash))) {
        return Response.json({ success: false, message: "Jina au nywila si sahihi." }, { status: 401 });
      }

      if (!env.SESSION_SECRET) {
        return Response.json({ success: false, message: "Mipangilio ya usalama haijakamilika." }, { status: 500 });
      }

      const token = await createToken(user, env.SESSION_SECRET);

      return Response.json({
        success: true,
        message: "Umeingia kikamilifu.",
        token,
        user: { id: user.id, username: user.username, role: user.role }
      });
    }

    return Response.json({ success: false, message: "Ombi halitambuliki." }, { status: 400 });

  } catch (error) {
    return Response.json({ success: false, message: "Hitilafu imetokea kwenye seva." }, { status: 500 });
  }
}
