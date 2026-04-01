"use strict";
/**
 * ══════════════════════════════════════════════════════════════════
 *  LEMOWAVES AI — BACKEND (Railway / Firebase Functions)
 *
 *  ALL API KEYS live here in environment variables ONLY.
 *  The frontend has zero keys — it just calls this backend.
 *
 *  Endpoints:
 *    POST /chat            → text AI (GPT-4o → Claude → Gemini → Groq)
 *    POST /vision          → image understanding (GPT-4o → Claude → Gemini → Groq LLaVA)
 *    POST /generateImage   → Stability AI image generation
 *    POST /createOrder     → Razorpay order creation
 *    POST /verifyPayment   → Razorpay HMAC-SHA256 verification
 *    POST /razorpayWebhook → Webhook handler (payment.captured)
 *    GET  /checkPremium    → Firestore premium status check
 *    GET  /health          → Health check
 *
 *  ── RAILWAY SETUP ─────────────────────────────────────────────
 *  In Railway dashboard → your project → Variables tab, add:
 *
 *    OPENAI_KEY       = sk-proj-qlaHHleQ...
 *    CLAUDE_KEY       = sk-ant-api03-slEs5vrh...
 *    GEMINI_KEY       = AIzaSyBlOuWpQjk...
 *    GROQ_KEY         = gsk_AJXqSjHInWL0...
 *    OR_KEY           = sk-or-v1-77c546...
 *    TOGETHER_KEY     = e0c952c3-2585-4674...
 *    STABILITY_KEY    = sk-eYEnfYpZ4yLeM...
 *    RAZORPAY_KEY_ID  = rzp_live_...
 *    RAZORPAY_KEY_SECRET = ...
 *    RAZORPAY_WEBHOOK_SECRET = (random string you make up)
 *    ALLOWED_ORIGINS  = https://lemowavesai.github.io,https://lemowaves.netlify.app
 *
 *  ── FRONTEND SIDE ─────────────────────────────────────────────
 *  In the HTML file, set RAILWAY_BACKEND to your Railway URL:
 *    var RAILWAY_BACKEND = 'https://your-app.up.railway.app';
 * ══════════════════════════════════════════════════════════════════
 */

const express  = require("express");
const cors     = require("cors");
const fetch    = require("node-fetch");
const FormData = require("form-data");
const crypto   = require("crypto");

// Firebase Admin — optional, only needed for Firestore premium sync
let admin, db;
try {
  admin = require("firebase-admin");
  if (!admin.apps.length) admin.initializeApp();
  db = admin.firestore();
  console.log("Firebase Admin initialized ✅");
} catch (e) {
  console.warn("Firebase Admin not available (Firestore disabled):", e.message);
}

const app = express();

// ── CORS ─────────────────────────────────────────────────────────
const ALLOWED = (process.env.ALLOWED_ORIGINS || "")
  .split(",").map(s => s.trim()).filter(Boolean)
  .concat([
    "https://lemowavesai.github.io",
    "https://lemowaves.netlify.app",
    "http://localhost:3000",
    "http://127.0.0.1:5500",
    "http://127.0.0.1:8080",
  ]);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED.includes(origin)) return cb(null, true);
    console.warn("CORS blocked:", origin);
    cb(new Error("CORS: not allowed — " + origin));
  },
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
}));
app.options("*", cors());
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true, limit: "20mb" }));

// ── Read API keys from env vars (NEVER hardcode here) ─────────────
const K = {
  OPENAI:    () => process.env.OPENAI_KEY,
  CLAUDE:    () => process.env.CLAUDE_KEY,
  GEMINI:    () => process.env.GEMINI_KEY,
  GROQ:      () => process.env.GROQ_KEY,
  OR:        () => process.env.OR_KEY,
  TOGETHER:  () => process.env.TOGETHER_KEY,
  STABILITY: () => process.env.STABILITY_KEY,
  RZP_ID:    () => process.env.RAZORPAY_KEY_ID,
  RZP_SEC:   () => process.env.RAZORPAY_KEY_SECRET,
  RZP_HOOK:  () => process.env.RAZORPAY_WEBHOOK_SECRET,
};

// ── In-memory rate limiter ────────────────────────────────────────
const _rl = new Map();
function rateLimit(ip, maxPerMin = 60) {
  const now = Date.now(), win = 60_000;
  const e = _rl.get(ip) || { n: 0, t: now };
  if (now - e.t > win) { e.n = 1; e.t = now; } else e.n++;
  _rl.set(ip, e);
  return e.n > maxPerMin;
}
function getIP(req) {
  return (req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown").split(",")[0].trim();
}

// ── Response extractors ───────────────────────────────────────────
const oaiText    = d => d?.choices?.[0]?.message?.content || "";
const gemText    = d => d?.candidates?.[0]?.content?.parts?.[0]?.text || "";
const claudeText = d => d?.content?.[0]?.text || "";

// ── Firebase token verify ─────────────────────────────────────────
async function verifyToken(req) {
  if (!admin) return null;
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) return null;
  try { return await admin.auth().verifyIdToken(h.slice(7)); }
  catch { return null; }
}

// ── Fetch with timeout helper ─────────────────────────────────────
async function timedFetch(url, opts, ms = 30000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

// ══════════════════════════════════════════════════════════════════
//  POST /chat  ─  Text AI proxy
//  Priority: GPT-4o → Claude 3.5 Sonnet → Gemini 2.0 Flash →
//            Groq Llama 3.3 70b → Pollinations (no key fallback)
// ══════════════════════════════════════════════════════════════════
app.post("/chat", async (req, res) => {
  if (rateLimit(getIP(req), 80)) return res.status(429).json({ error: "Rate limit exceeded" });

  const { messages = [], userText = "", systemPrompt = "", seed = 0, isBigRequest = false } = req.body;
  const maxTok = isBigRequest ? 8000 : 4000;
  const temp   = 0.7;
  const sys    = (systemPrompt || "You are Lemowaves AI, a smart helpful assistant.").slice(0, 4000);

  // Build messages array
  const hist = (Array.isArray(messages) ? messages : []).slice(-20).map(m => ({
    role: m.role === "user" ? "user" : "assistant",
    content: String(m.content || "").slice(0, 1200),
  })).filter(m => m.content);

  const msgs      = [{ role: "system", content: sys }, ...hist, { role: "user", content: userText }];
  const msgsNoSys = msgs.filter(m => m.role !== "system");

  // ── 1. GPT-4o ──
  if (K.OPENAI()) {
    try {
      const r = await timedFetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${K.OPENAI()}` },
        body: JSON.stringify({ model: "gpt-4o", messages: msgs, max_tokens: maxTok, temperature: temp }),
      }, 35000);
      if (r.ok) { const txt = oaiText(await r.json()); if (txt) return res.json({ reply: txt, model: "gpt-4o" }); }
    } catch (e) { console.warn("GPT-4o:", e.message); }
  }

  // ── 2. Claude 3.5 Sonnet ──
  if (K.CLAUDE()) {
    try {
      const r = await timedFetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-api-key": K.CLAUDE(), "anthropic-version": "2023-06-01" },
        body: JSON.stringify({ model: "claude-3-5-sonnet-20241022", max_tokens: maxTok, system: sys, messages: msgsNoSys }),
      }, 40000);
      if (r.ok) { const txt = claudeText(await r.json()); if (txt) return res.json({ reply: txt, model: "claude-sonnet" }); }
    } catch (e) { console.warn("Claude:", e.message); }
  }

  // ── 3. Gemini 2.0 Flash ──
  if (K.GEMINI()) {
    try {
      const gParts = [...hist.map(m => ({ text: (m.role === "user" ? "User: " : "AI: ") + m.content })),
        { text: "User: " + userText }];
      const r = await timedFetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${K.GEMINI()}`,
        { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ system_instruction: { parts: [{ text: sys }] },
            contents: [{ role: "user", parts: gParts }], generationConfig: { maxOutputTokens: maxTok, temperature: temp } }) },
        30000);
      if (r.ok) { const txt = gemText(await r.json()); if (txt) return res.json({ reply: txt, model: "gemini-2.0-flash" }); }
    } catch (e) { console.warn("Gemini:", e.message); }
  }

  // ── 4. Groq Llama 3.3 70b ──
  if (K.GROQ()) {
    try {
      const r = await timedFetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${K.GROQ()}` },
        body: JSON.stringify({ model: "llama-3.3-70b-versatile", messages: msgs, max_tokens: maxTok, temperature: temp }),
      }, 25000);
      if (r.ok) { const txt = oaiText(await r.json()); if (txt) return res.json({ reply: txt, model: "groq-70b" }); }
    } catch (e) { console.warn("Groq:", e.message); }
  }

  // ── 5. Pollinations (no key, public fallback) ──
  try {
    const r = await timedFetch("https://text.pollinations.ai/openai", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model: "openai-large", messages: msgs, max_tokens: 4000, seed }),
    }, 20000);
    if (r.ok) { const txt = oaiText(await r.json()); if (txt) return res.json({ reply: txt, model: "pollinations" }); }
  } catch (e) { console.warn("Pollinations:", e.message); }

  res.status(502).json({ error: "All AI services unavailable. Try again shortly." });
});

// ══════════════════════════════════════════════════════════════════
//  POST /vision  ─  Image understanding proxy
//  Priority: GPT-4o Vision → Claude 3.5 Haiku → Gemini 1.5 Flash → Groq LLaVA
// ══════════════════════════════════════════════════════════════════
app.post("/vision", async (req, res) => {
  if (rateLimit(getIP(req), 30)) return res.status(429).json({ error: "Rate limit exceeded" });

  const { userText = "", imageBase64 = "", imageMime = "image/jpeg", systemPrompt = "" } = req.body;
  if (!imageBase64) return res.status(400).json({ error: "imageBase64 required" });

  const sys  = (systemPrompt || "You are Lemowaves AI. Describe images in vivid, accurate detail.").slice(0, 2000);
  const vTxt = userText || "Describe EVERYTHING in this image with 100% accuracy. Every object, person, color, text, mood, lighting, style. Be specific and thorough.";

  // ── 1. GPT-4o Vision (most accurate) ──
  if (K.OPENAI()) {
    try {
      const r = await timedFetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${K.OPENAI()}` },
        body: JSON.stringify({ model: "gpt-4o", max_tokens: 2048,
          messages: [
            { role: "system", content: sys },
            { role: "user", content: [
              { type: "image_url", image_url: { url: `data:${imageMime};base64,${imageBase64}`, detail: "high" } },
              { type: "text", text: vTxt },
            ]},
          ],
        }),
      }, 45000);
      if (r.ok) { const txt = oaiText(await r.json()); if (txt) return res.json({ reply: txt, model: "gpt-4o-vision" }); }
    } catch (e) { console.warn("GPT-4o vision:", e.message); }
  }

  // ── 2. Claude 3.5 Haiku Vision ──
  if (K.CLAUDE()) {
    try {
      const r = await timedFetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-api-key": K.CLAUDE(), "anthropic-version": "2023-06-01" },
        body: JSON.stringify({ model: "claude-3-5-haiku-20241022", max_tokens: 2048, system: sys,
          messages: [{ role: "user", content: [
            { type: "image", source: { type: "base64", media_type: imageMime, data: imageBase64 } },
            { type: "text", text: vTxt },
          ]}],
        }),
      }, 45000);
      if (r.ok) { const txt = claudeText(await r.json()); if (txt) return res.json({ reply: txt, model: "claude-haiku-vision" }); }
    } catch (e) { console.warn("Claude vision:", e.message); }
  }

  // ── 3. Gemini 1.5 Flash Vision ──
  if (K.GEMINI()) {
    try {
      const r = await timedFetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${K.GEMINI()}`,
        { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ contents: [{ parts: [
            { text: vTxt },
            { inline_data: { mime_type: imageMime, data: imageBase64 } },
          ]}], generationConfig: { maxOutputTokens: 2048, temperature: 0.4 } }) },
        40000);
      if (r.ok) { const txt = gemText(await r.json()); if (txt) return res.json({ reply: txt, model: "gemini-flash-vision" }); }
    } catch (e) { console.warn("Gemini vision:", e.message); }
  }

  // ── 4. Groq LLaVA 90b → 11b ──
  if (K.GROQ()) {
    for (const model of ["llama-3.2-90b-vision-preview", "llama-3.2-11b-vision-preview"]) {
      try {
        const r = await timedFetch("https://api.groq.com/openai/v1/chat/completions", {
          method: "POST",
          headers: { "Content-Type": "application/json", "Authorization": `Bearer ${K.GROQ()}` },
          body: JSON.stringify({ model, max_tokens: 2048, temperature: 0.5,
            messages: [
              { role: "system", content: sys },
              { role: "user", content: [
                { type: "image_url", image_url: { url: `data:${imageMime};base64,${imageBase64}` } },
                { type: "text", text: vTxt },
              ]},
            ],
          }),
        }, 30000);
        if (r.ok) { const txt = oaiText(await r.json()); if (txt) return res.json({ reply: txt, model }); }
      } catch (e) { console.warn(`Groq ${model}:`, e.message); }
    }
  }

  res.status(502).json({ error: "Vision services unavailable. Try again." });
});

// ══════════════════════════════════════════════════════════════════
//  POST /generateImage  ─  Stability AI image gen
//  Returns base64 PNG. Key never leaves this file.
// ══════════════════════════════════════════════════════════════════
app.post("/generateImage", async (req, res) => {
  if (rateLimit(getIP(req), 20)) return res.status(429).json({ error: "Rate limit exceeded" });

  const { prompt = "", isPremium = false } = req.body;
  if (!prompt) return res.status(400).json({ error: "prompt required" });

  if (K.STABILITY()) {
    try {
      const form = new FormData();
      form.append("prompt", prompt.slice(0, 2000));
      form.append("output_format", "png");
      form.append("aspect_ratio", "1:1");
      if (isPremium) form.append("style_preset", "photographic");

      const r = await timedFetch("https://api.stability.ai/v2beta/stable-image/generate/core", {
        method: "POST",
        headers: { "Authorization": `Bearer ${K.STABILITY()}`, "Accept": "application/json", ...form.getHeaders() },
        body: form,
      }, 60000);

      if (r.ok) {
        const d = await r.json();
        if (d?.image) return res.json({ image: d.image, model: "stability-core" });
      } else {
        const t = await r.text();
        console.warn("Stability AI error:", r.status, t.slice(0, 200));
      }
    } catch (e) { console.warn("Stability AI:", e.message); }
  }

  res.status(502).json({ error: "Image generation unavailable" });
});

// ══════════════════════════════════════════════════════════════════
//  POST /createOrder  ─  Razorpay order (key server-side only)
// ══════════════════════════════════════════════════════════════════
app.post("/createOrder", async (req, res) => {
  if (rateLimit(getIP(req), 10)) return res.status(429).json({ error: "Too many requests" });
  if (!K.RZP_ID() || !K.RZP_SEC()) return res.status(503).json({ error: "Payment not configured" });

  try {
    const { planType = "monthly" } = req.body;
    const PLANS  = { monthly: 9900, yearly: 79900 };
    const amount = PLANS[planType] || PLANS.monthly;

    const Razorpay = require("razorpay");
    const rzp      = new Razorpay({ key_id: K.RZP_ID(), key_secret: K.RZP_SEC() });
    const fbUser   = await verifyToken(req);
    const uid      = fbUser?.uid || "guest_" + Date.now();

    const order = await rzp.orders.create({
      amount, currency: "INR",
      receipt: `lw_${uid.slice(0, 10)}_${Date.now()}`,
      notes: { uid, planType },
    });

    if (db) {
      await db.collection("orders").doc(order.id).set({
        uid, orderId: order.id, amount, planType, status: "created",
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    }

    return res.json({ orderId: order.id, amount, currency: "INR", keyId: K.RZP_ID() });
  } catch (e) {
    console.error("createOrder:", e);
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════════
//  POST /verifyPayment  ─  HMAC-SHA256 Razorpay verification
// ══════════════════════════════════════════════════════════════════
app.post("/verifyPayment", async (req, res) => {
  if (!K.RZP_SEC()) return res.status(503).json({ error: "Payment not configured" });

  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature)
    return res.status(400).json({ error: "Missing payment fields" });

  const expected = crypto.createHmac("sha256", K.RZP_SEC())
    .update(`${razorpay_order_id}|${razorpay_payment_id}`).digest("hex");

  let valid = false;
  try { valid = crypto.timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(razorpay_signature, "hex")); }
  catch { valid = false; }

  if (!valid) return res.status(400).json({ error: "Signature mismatch — payment rejected" });

  if (db) {
    try {
      const fbUser = await verifyToken(req);
      if (fbUser?.uid) {
        const expiry = new Date(); expiry.setMonth(expiry.getMonth() + 1);
        await db.collection("users").doc(fbUser.uid).set({
          premium: true, planType: "monthly",
          premiumExpiry: admin.firestore.Timestamp.fromDate(expiry),
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        }, { merge: true });
        await db.collection("orders").doc(razorpay_order_id).update({
          status: "paid", paymentId: razorpay_payment_id,
          paidAt: admin.firestore.FieldValue.serverTimestamp(),
        }).catch(() => {});
      }
    } catch (e) { console.warn("verifyPayment Firestore:", e.message); }
  }

  res.json({ success: true, message: "Payment verified ✅" });
});

// ══════════════════════════════════════════════════════════════════
//  POST /razorpayWebhook  ─  Server-to-server from Razorpay
// ══════════════════════════════════════════════════════════════════
app.post("/razorpayWebhook", async (req, res) => {
  const sig = req.headers["x-razorpay-signature"];
  if (!sig || !K.RZP_HOOK()) return res.status(400).send("Invalid");

  const expected = crypto.createHmac("sha256", K.RZP_HOOK())
    .update(JSON.stringify(req.body)).digest("hex");

  let valid = false;
  try { valid = crypto.timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(sig, "hex")); }
  catch { valid = false; }

  if (!valid) return res.status(400).send("Invalid signature");

  if (req.body?.event === "payment.captured" && db) {
    const uid = req.body?.payload?.payment?.entity?.notes?.uid;
    if (uid) {
      const expiry = new Date(); expiry.setMonth(expiry.getMonth() + 1);
      await db.collection("users").doc(uid).set({
        premium: true, planType: "monthly",
        premiumExpiry: admin.firestore.Timestamp.fromDate(expiry),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }, { merge: true }).catch(e => console.warn("Webhook Firestore:", e.message));
    }
  }
  res.status(200).send("ok");
});

// ══════════════════════════════════════════════════════════════════
//  GET /checkPremium  ─  Read premium status from Firestore
// ══════════════════════════════════════════════════════════════════
app.get("/checkPremium", async (req, res) => {
  if (!db) return res.json({ isPremium: false, planType: "free" });
  const user = await verifyToken(req);
  if (!user) return res.status(401).json({ error: "Unauthorized" });
  try {
    const doc = await db.collection("users").doc(user.uid).get();
    if (!doc.exists) return res.json({ isPremium: false, planType: "free" });
    const d = doc.data();
    if (d.premiumExpiry && d.premiumExpiry.toDate() < new Date()) {
      await db.collection("users").doc(user.uid).update({ premium: false });
      return res.json({ isPremium: false, planType: "free" });
    }
    return res.json({
      isPremium: d.premium === true,
      planType: d.planType || "free",
      expiry: d.premiumExpiry ? d.premiumExpiry.toDate().toISOString() : null,
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Health & root ──────────────────────────────────────────────────
app.get("/", (req, res) => res.json({ status: "ok", service: "Lemowaves AI Backend", version: "2.0" }));
app.get("/health", (req, res) => res.json({ status: "ok" }));

// ── Start server ───────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT || "3001", 10);
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Lemowaves AI backend running on port ${PORT}`);
  console.log(`   Keys loaded: OpenAI=${!!K.OPENAI()} Claude=${!!K.CLAUDE()} Gemini=${!!K.GEMINI()} Groq=${!!K.GROQ()} Stability=${!!K.STABILITY()}`);
});

// Firebase Functions compatibility export (if deployed there instead)
try {
  const functions = require("firebase-functions");
  exports.api = functions.runWith({ timeoutSeconds: 120, memory: "512MB" }).https.onRequest(app);
} catch (_) { /* Railway mode — no Firebase Functions needed */ }
