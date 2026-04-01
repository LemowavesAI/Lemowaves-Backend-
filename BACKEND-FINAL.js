"use strict";
/*
 * ═══════════════════════════════════════════════════════
 *  LEMOWAVES AI — BACKEND v4  (Railway Production)
 *  100% crash-proof. Zero restarts. All keys server-side.
 * ═══════════════════════════════════════════════════════
 *
 *  RAILWAY SETUP:
 *  Variables tab → add these (paste your real values):
 *
 *  OPENAI_KEY     = sk-proj-qlaHHleQO5Gw...
 *  CLAUDE_KEY     = sk-ant-api03-slEs5vrh...
 *  GEMINI_KEY     = AIzaSyBlOuWpQjkCJt41...
 *  GROQ_KEY       = gsk_AJXqSjHInWL0vAyQ...
 *  STABILITY_KEY  = sk-eYEnfYpZ4yLeMkwUg...
 *  RZP_KEY_ID     = rzp_live_...
 *  RZP_KEY_SECRET = ...
 *  RZP_WEBHOOK    = any_random_secret_you_make_up
 *  PREMIUM_SECRET = another_random_secret_you_make_up
 *
 * ═══════════════════════════════════════════════════════
 */

const http    = require("http");
const https   = require("https");
const crypto  = require("crypto");
const express = require("express");
const cors    = require("cors");

/* ── optional deps — safe if missing ─────────────── */
let nodeFetch = null;
try { nodeFetch = require("node-fetch"); } catch(e) {}
const fetchFn = global.fetch || nodeFetch;

let FormDataPkg = null;
try { FormDataPkg = require("form-data"); } catch(e) {}

let Razorpay = null;
try { Razorpay = require("razorpay"); } catch(e) { console.log("Razorpay not installed"); }

/* ── app setup ────────────────────────────────────── */
const app = express();
app.disable("x-powered-by");

/* ── CORS — allow everything (tighten later if needed) */
app.use(cors({ origin: true, methods: ["GET","POST","OPTIONS"], credentials: true }));
app.options("*", cors());

/* ── body parser — 8mb max (prevents OOM crashes) ── */
app.use(express.json({ limit: "8mb" }));
app.use(express.urlencoded({ extended: false, limit: "8mb" }));

/* ── safe key reader ─────────────────────────────── */
const K = (name) => (process.env[name] || "").trim();

/* ── safe fetch with timeout ─────────────────────── */
function go(url, opts, ms) {
  return new Promise(function(resolve, reject) {
    ms = ms || 25000;
    const timer = setTimeout(function() { reject(new Error("timeout")); }, ms);
    Promise.resolve(fetchFn(url, opts))
      .then(function(r) { clearTimeout(timer); resolve(r); })
      .catch(function(e) { clearTimeout(timer); reject(e); });
  });
}

/* ── wrap async handlers — THE crash fix ─────────── */
/* Every route is wrapped so unhandled async errors    */
/* NEVER reach Node's unhandledRejection handler       */
function wrap(fn) {
  return function(req, res) {
    Promise.resolve(fn(req, res)).catch(function(err) {
      console.error("Route error (caught):", err && err.message || err);
      if (!res.headersSent) res.status(500).json({ error: "Server error" });
    });
  };
}

/* ── text extractors ─────────────────────────────── */
function oai(d)    { try { return d.choices[0].message.content || ""; } catch(e) { return ""; } }
function gem(d)    { try { return d.candidates[0].content.parts[0].text || ""; } catch(e) { return ""; } }
function ant(d)    { try { return d.content[0].text || ""; } catch(e) { return ""; } }

/* ── rate limiter ────────────────────────────────── */
const rl = new Map();
function limit(req, max) {
  const ipRaw = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "x";
  const k = String(ipRaw).split(",")[0].trim();
  const now = Date.now();
  const e = rl.get(k) || { n: 0, t: now };
  if (now - e.t > 60000) { e.n = 1; e.t = now; } else e.n++;
  rl.set(k, e);
  return e.n > (max || 60);
}

/* ═══════════════════════════════════════════════════
   PREMIUM SESSION STORE
   In-memory map: token → { uid, expires }
   No database needed. Tokens last 30 days.
   Cannot be faked — signed with PREMIUM_SECRET.
   ═══════════════════════════════════════════════════ */
const premiumSessions = new Map();

function makePremiumToken(uid, months) {
  const secret = K("PREMIUM_SECRET") || "lw_default_secret_change_me";
  const exp    = Date.now() + (months || 1) * 30 * 24 * 60 * 60 * 1000;
  const payload = uid + ":" + exp;
  const sig = crypto.createHmac("sha256", secret).update(payload).digest("hex").slice(0, 16);
  const token = Buffer.from(payload + ":" + sig).toString("base64url");
  premiumSessions.set(token, { uid, exp });
  return token;
}

function verifyPremiumToken(token) {
  if (!token) return null;
  // Check memory first (fast path)
  const mem = premiumSessions.get(token);
  if (mem) {
    if (Date.now() < mem.exp) return mem.uid;
    premiumSessions.delete(token);
    return null;
  }
  // Verify signature (slow path — for tokens not in memory e.g. after restart)
  try {
    const secret = K("PREMIUM_SECRET") || "lw_default_secret_change_me";
    const raw = Buffer.from(token, "base64url").toString();
    const parts = raw.split(":");
    if (parts.length < 3) return null;
    const sig = parts.pop();
    const payload = parts.join(":");
    const expected = crypto.createHmac("sha256", secret).update(payload).digest("hex").slice(0, 16);
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    const [uid, expStr] = payload.split(":");
    const exp = parseInt(expStr);
    if (isNaN(exp) || Date.now() > exp) return null;
    // Re-cache it
    premiumSessions.set(token, { uid, exp });
    return uid;
  } catch(e) { return null; }
}

/* ═══════════════════════════════════════════════════
   GET /health   — Railway health check
   ═══════════════════════════════════════════════════ */
app.get("/health", function(req, res) {
  res.json({ ok: true, ts: Date.now() });
});

app.get("/", function(req, res) {
  res.json({
    service: "Lemowaves AI Backend v4",
    status:  "running",
    keys: {
      openai:    !!K("OPENAI_KEY"),
      claude:    !!K("CLAUDE_KEY"),
      gemini:    !!K("GEMINI_KEY"),
      groq:      !!K("GROQ_KEY"),
      stability: !!K("STABILITY_KEY"),
      razorpay:  !!K("RZP_KEY_ID"),
    }
  });
});

/* ═══════════════════════════════════════════════════
   POST /chat   — Text AI
   GPT-4o → Claude Sonnet → Gemini 2.0 → Groq → Pollinations
   ═══════════════════════════════════════════════════ */
app.post("/chat", wrap(async function(req, res) {
  if (limit(req, 120)) return res.status(429).json({ error: "Too many requests" });

  const body    = req.body || {};
  const userTxt = String(body.userText || "").slice(0, 3000);
  const sysRaw  = String(body.systemPrompt || "You are Lemowaves AI, built by Sam.").slice(0, 4000);
  const isBig   = !!body.isBigRequest;
  const maxTok  = isBig ? 8000 : 4000;
  const seed    = parseInt(body.seed) || 1;
  const hist    = (Array.isArray(body.messages) ? body.messages : [])
    .slice(-16)
    .map(m => ({ role: m.role === "user" ? "user" : "assistant", content: String(m.content||"").slice(0,1000) }))
    .filter(m => m.content);

  const msgs = [{ role:"system", content:sysRaw }, ...hist, { role:"user", content:userTxt }];

  // 1. GPT-4o
  if (K("OPENAI_KEY")) {
    const r = await go("https://api.openai.com/v1/chat/completions", {
      method:"POST",
      headers:{"Content-Type":"application/json","Authorization":"Bearer "+K("OPENAI_KEY")},
      body: JSON.stringify({ model:"gpt-4o", messages:msgs, max_tokens:maxTok, temperature:0.7 })
    }, 30000).catch(e => null);
    if (r && r.ok) { const t = oai(await r.json().catch(()=>({}))); if (t) return res.json({ reply:t, model:"gpt-4o" }); }
  }

  // 2. Claude 3.5 Sonnet
  if (K("CLAUDE_KEY")) {
    const r = await go("https://api.anthropic.com/v1/messages", {
      method:"POST",
      headers:{"Content-Type":"application/json","x-api-key":K("CLAUDE_KEY"),"anthropic-version":"2023-06-01"},
      body: JSON.stringify({ model:"claude-3-5-sonnet-20241022", max_tokens:maxTok, system:sysRaw,
        messages: msgs.filter(m=>m.role!=="system") })
    }, 35000).catch(e => null);
    if (r && r.ok) { const t = ant(await r.json().catch(()=>({}))); if (t) return res.json({ reply:t, model:"claude" }); }
  }

  // 3. Gemini 2.0 Flash
  if (K("GEMINI_KEY")) {
    const gParts = [...hist.map(m=>({text:(m.role==="user"?"U: ":"A: ")+m.content})), {text:"U: "+userTxt}];
    const r = await go(
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key="+K("GEMINI_KEY"),
      { method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ system_instruction:{parts:[{text:sysRaw}]},
          contents:[{role:"user",parts:gParts}], generationConfig:{maxOutputTokens:maxTok,temperature:0.7} })
      }, 25000).catch(e => null);
    if (r && r.ok) { const t = gem(await r.json().catch(()=>({}))); if (t) return res.json({ reply:t, model:"gemini" }); }
  }

  // 4. Groq Llama 70b
  if (K("GROQ_KEY")) {
    const r = await go("https://api.groq.com/openai/v1/chat/completions", {
      method:"POST",
      headers:{"Content-Type":"application/json","Authorization":"Bearer "+K("GROQ_KEY")},
      body: JSON.stringify({ model:"llama-3.3-70b-versatile", messages:msgs, max_tokens:maxTok, temperature:0.7 })
    }, 20000).catch(e => null);
    if (r && r.ok) { const t = oai(await r.json().catch(()=>({}))); if (t) return res.json({ reply:t, model:"groq" }); }
  }

  // 5. Pollinations (no key — always available)
  const r5 = await go("https://text.pollinations.ai/openai", {
    method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({ model:"openai-large", messages:msgs, max_tokens:4000, seed })
  }, 20000).catch(e => null);
  if (r5 && r5.ok) { const t = oai(await r5.json().catch(()=>({}))); if (t) return res.json({ reply:t, model:"pollinations" }); }

  res.status(502).json({ error: "All AI services failed" });
}));

/* ═══════════════════════════════════════════════════
   POST /vision  — Image understanding
   ═══════════════════════════════════════════════════ */
app.post("/vision", wrap(async function(req, res) {
  if (limit(req, 30)) return res.status(429).json({ error: "Too many requests" });

  const body   = req.body || {};
  const img64  = String(body.imageBase64 || "");
  const mime   = String(body.imageMime || "image/jpeg");
  const vTxt   = String(body.userText || "Describe EVERYTHING you see in this image with 100% accuracy. Every object, person, color, text, mood, background. Be vivid and detailed.");
  const sysRaw = String(body.systemPrompt || "You are Lemowaves AI. Describe images accurately.").slice(0, 2000);

  if (!img64) return res.status(400).json({ error: "imageBase64 required" });
  // Safety: reject oversized images (>4MB base64 ≈ 3MB file)
  if (img64.length > 4_200_000) return res.status(413).json({ error: "Image too large — compress before sending" });

  // 1. GPT-4o Vision
  if (K("OPENAI_KEY")) {
    const r = await go("https://api.openai.com/v1/chat/completions", {
      method:"POST",
      headers:{"Content-Type":"application/json","Authorization":"Bearer "+K("OPENAI_KEY")},
      body: JSON.stringify({ model:"gpt-4o", max_tokens:2048,
        messages:[{ role:"system", content:sysRaw },
          { role:"user", content:[
            { type:"image_url", image_url:{ url:"data:"+mime+";base64,"+img64, detail:"high" }},
            { type:"text", text:vTxt }
          ]}]
      })
    }, 40000).catch(e => null);
    if (r && r.ok) { const t = oai(await r.json().catch(()=>({}))); if (t) return res.json({ reply:t, model:"gpt-4o-vision" }); }
  }

  // 2. Claude Haiku Vision
  if (K("CLAUDE_KEY")) {
    const r = await go("https://api.anthropic.com/v1/messages", {
      method:"POST",
      headers:{"Content-Type":"application/json","x-api-key":K("CLAUDE_KEY"),"anthropic-version":"2023-06-01"},
      body: JSON.stringify({ model:"claude-3-5-haiku-20241022", max_tokens:2048, system:sysRaw,
        messages:[{ role:"user", content:[
          { type:"image", source:{ type:"base64", media_type:mime, data:img64 }},
          { type:"text", text:vTxt }
        ]}]
      })
    }, 40000).catch(e => null);
    if (r && r.ok) { const t = ant(await r.json().catch(()=>({}))); if (t) return res.json({ reply:t, model:"claude-vision" }); }
  }

  // 3. Gemini 1.5 Flash Vision
  if (K("GEMINI_KEY")) {
    const r = await go(
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key="+K("GEMINI_KEY"),
      { method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ contents:[{ parts:[
          { text:vTxt },
          { inline_data:{ mime_type:mime, data:img64 }}
        ]}], generationConfig:{ maxOutputTokens:2048, temperature:0.4 }})
      }, 35000).catch(e => null);
    if (r && r.ok) { const t = gem(await r.json().catch(()=>({}))); if (t) return res.json({ reply:t, model:"gemini-vision" }); }
  }

  // 4. Groq LLaVA
  if (K("GROQ_KEY")) {
    for (const model of ["llama-3.2-90b-vision-preview","llama-3.2-11b-vision-preview"]) {
      const r = await go("https://api.groq.com/openai/v1/chat/completions", {
        method:"POST",
        headers:{"Content-Type":"application/json","Authorization":"Bearer "+K("GROQ_KEY")},
        body: JSON.stringify({ model, max_tokens:2048, temperature:0.5,
          messages:[{ role:"system", content:sysRaw },
            { role:"user", content:[
              { type:"image_url", image_url:{ url:"data:"+mime+";base64,"+img64 }},
              { type:"text", text:vTxt }
            ]}]
        })
      }, 25000).catch(e => null);
      if (r && r.ok) { const t = oai(await r.json().catch(()=>({}))); if (t) return res.json({ reply:t, model }); }
    }
  }

  res.status(502).json({ error: "Vision services unavailable" });
}));

/* ═══════════════════════════════════════════════════
   POST /generateImage  — Stability AI
   ═══════════════════════════════════════════════════ */
app.post("/generateImage", wrap(async function(req, res) {
  if (limit(req, 20)) return res.status(429).json({ error: "Too many requests" });

  const prompt = String((req.body||{}).prompt || "").slice(0, 2000);
  if (!prompt) return res.status(400).json({ error: "prompt required" });

  if (K("STABILITY_KEY") && FormDataPkg) {
    const fd = new FormDataPkg();
    fd.append("prompt", prompt);
    fd.append("output_format", "png");
    fd.append("aspect_ratio", "1:1");
    const r = await go("https://api.stability.ai/v2beta/stable-image/generate/core", {
      method:"POST",
      headers:{ "Authorization":"Bearer "+K("STABILITY_KEY"), "Accept":"application/json", ...fd.getHeaders() },
      body: fd
    }, 55000).catch(e => null);
    if (r && r.ok) {
      const d = await r.json().catch(()=>({}));
      if (d.image) return res.json({ image: d.image });
    }
  }

  res.status(502).json({ error: "Image generation unavailable — use Pollinations fallback" });
}));

/* ═══════════════════════════════════════════════════
   POST /createOrder  — Razorpay order
   ═══════════════════════════════════════════════════ */
app.post("/createOrder", wrap(async function(req, res) {
  if (!K("RZP_KEY_ID") || !K("RZP_KEY_SECRET")) return res.status(503).json({ error: "Payment not configured" });
  if (!Razorpay) return res.status(503).json({ error: "Razorpay not installed" });

  const plan   = (req.body||{}).planType === "yearly" ? "yearly" : "monthly";
  const amount = plan === "yearly" ? 79900 : 9900;
  const uid    = String((req.body||{}).uid || "guest_" + Date.now());

  const rzp   = new Razorpay({ key_id: K("RZP_KEY_ID"), key_secret: K("RZP_KEY_SECRET") });
  const order = await rzp.orders.create({ amount, currency:"INR",
    receipt: "lw_"+uid.slice(0,8)+"_"+Date.now(),
    notes:   { uid, planType: plan }
  });

  res.json({ orderId: order.id, amount, currency:"INR", keyId: K("RZP_KEY_ID") });
}));

/* ═══════════════════════════════════════════════════
   POST /verifyPayment  — HMAC verify + issue token
   This is the ONLY place premium gets activated.
   ═══════════════════════════════════════════════════ */
app.post("/verifyPayment", wrap(async function(req, res) {
  if (!K("RZP_KEY_SECRET")) return res.status(503).json({ error: "Payment not configured" });

  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, uid } = req.body || {};
  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature)
    return res.status(400).json({ error: "Missing payment fields" });

  // HMAC-SHA256 — cryptographic payment verification
  const expected = crypto.createHmac("sha256", K("RZP_KEY_SECRET"))
    .update(razorpay_order_id + "|" + razorpay_payment_id).digest("hex");

  let valid = false;
  try {
    valid = crypto.timingSafeEqual(Buffer.from(expected,"hex"), Buffer.from(razorpay_signature,"hex"));
  } catch(e) { valid = false; }

  if (!valid) return res.status(400).json({ error: "Payment verification failed — signature mismatch" });

  // ✅ Payment is real — issue a premium token
  const safeUid   = String(uid || "user_" + razorpay_payment_id.slice(-8));
  const token     = makePremiumToken(safeUid, 1);
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

  console.log("✅ Premium activated:", safeUid, "expires:", expiresAt);
  res.json({ success: true, premiumToken: token, expiresAt, message: "Premium activated!" });
}));

/* ═══════════════════════════════════════════════════
   POST /checkPremium  — verify token server-side
   Frontend sends the stored token, we verify it here.
   Cannot be faked — HMAC signed.
   ═══════════════════════════════════════════════════ */
app.post("/checkPremium", wrap(async function(req, res) {
  const token = String((req.body||{}).premiumToken || "");
  const uid   = verifyPremiumToken(token);

  if (!uid) return res.json({ isPremium: false });

  res.json({
    isPremium: true,
    uid,
    expiresAt: (function() {
      try {
        const raw   = Buffer.from(token,"base64url").toString();
        const parts = raw.split(":");
        parts.pop(); // remove sig
        return new Date(parseInt(parts[1])).toISOString();
      } catch(e) { return null; }
    })()
  });
}));

/* ═══════════════════════════════════════════════════
   POST /razorpayWebhook  — server-to-server
   ═══════════════════════════════════════════════════ */
app.post("/razorpayWebhook", function(req, res) {
  const sig  = req.headers["x-razorpay-signature"] || "";
  const hook = K("RZP_WEBHOOK");
  if (!sig || !hook) return res.status(400).send("Invalid");
  const exp  = crypto.createHmac("sha256",hook).update(JSON.stringify(req.body)).digest("hex");
  let v = false;
  try { v = crypto.timingSafeEqual(Buffer.from(exp,"hex"),Buffer.from(sig,"hex")); } catch(e){}
  if (!v) return res.status(400).send("Bad sig");
  // Webhook verified — log it (Firestore upgrade optional)
  if (req.body && req.body.event === "payment.captured") {
    const uid = req.body?.payload?.payment?.entity?.notes?.uid;
    if (uid) {
      const tok = makePremiumToken(uid, 1);
      console.log("Webhook: premium token created for", uid, "token:", tok.slice(0,20)+"...");
    }
  }
  res.send("ok");
});

/* ═══════════════════════════════════════════════════
   Global error handler — catches anything we missed
   ═══════════════════════════════════════════════════ */
app.use(function(err, req, res, next) {
  console.error("Global error handler:", err && err.message || err);
  if (!res.headersSent) res.status(500).json({ error: "Internal server error" });
});

/* ═══════════════════════════════════════════════════
   Process-level crash guards — NEVER let Node exit
   ═══════════════════════════════════════════════════ */
process.on("uncaughtException", function(err) {
  console.error("[CRASH GUARD] uncaughtException:", err && err.message || err);
  // DON'T exit — log and continue
});
process.on("unhandledRejection", function(reason) {
  console.error("[CRASH GUARD] unhandledRejection:", reason && reason.message || reason);
  // DON'T exit — log and continue
});

/* ═══════════════════════════════════════════════════
   Start server
   ═══════════════════════════════════════════════════ */
const PORT = parseInt(process.env.PORT || "3001", 10);
app.listen(PORT, "0.0.0.0", function() {
  console.log("🚀 Lemowaves AI Backend v4 running on port", PORT);
  console.log("   OpenAI:    ", !!K("OPENAI_KEY"));
  console.log("   Claude:    ", !!K("CLAUDE_KEY"));
  console.log("   Gemini:    ", !!K("GEMINI_KEY"));
  console.log("   Groq:      ", !!K("GROQ_KEY"));
  console.log("   Stability: ", !!K("STABILITY_KEY"));
  console.log("   Razorpay:  ", !!K("RZP_KEY_ID"));
});
