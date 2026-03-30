/**
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 *  LEMOWAVES AI â€” FIREBASE CLOUD FUNCTIONS BACKEND
 *  Production-Grade | Secure | Anti-Bypass
 *
 *  Endpoints:
 *    POST /createOrder        â†’ Razorpay order creation
 *    POST /verifyPayment      â†’ Razorpay signature verification
 *    POST /razorpayWebhook    â†’ Webhook (payment.captured)
 *    GET  /checkPremium       â†’ Read premium status
 *    POST /generateResponse   â†’ AI proxy (premium-gated)
 *
 *  Security Model:
 *    â€¢ All secrets live in Firebase environment variables ONLY
 *    â€¢ Every protected endpoint verifies a Firebase ID token
 *    â€¢ Premium is read from Firestore â€” client localStorage is ignored
 *    â€¢ Razorpay signature verified with HMAC-SHA256 before any DB write
 *    â€¢ Webhook verified with Razorpay webhook secret independently
 *    â€¢ Rate-limiting per UID to prevent abuse
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 */

"use strict";

const functions      = require("firebase-functions");
const admin          = require("firebase-admin");
const Razorpay       = require("razorpay");
const crypto         = require("crypto");
const fetch          = require("node-fetch");
const cors           = require("cors");

// â”€â”€ Init Firebase Admin (uses FIREBASE_ADMIN_KEY env var automatically) â”€â”€
admin.initializeApp();
const db = admin.firestore();

// â”€â”€ CORS â€” only allow your domain in production â”€â”€
const corsHandler = cors({
  origin: [
    "https://lemowavesai.github.io",
    "https://lemowaves.netlify.app",
    // Add your custom domain here
    // "https://yourdomain.com"
  ],
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
});

// â”€â”€ Read secrets from Firebase environment variables â”€â”€
// Set them with: firebase functions:config:set razorpay.key_id="..." etc.
function getConfig() {
  const cfg = functions.config();
  return {
    RAZORPAY_KEY_ID:      cfg.razorpay?.key_id      || process.env.RAZORPAY_KEY_ID,
    RAZORPAY_KEY_SECRET:  cfg.razorpay?.key_secret   || process.env.RAZORPAY_KEY_SECRET,
    RAZORPAY_WEBHOOK_SEC: cfg.razorpay?.webhook_sec  || process.env.RAZORPAY_WEBHOOK_SECRET,
    AI_API_KEY:           cfg.ai?.api_key            || process.env.AI_API_KEY,
    GROQ_KEY:             cfg.ai?.groq_key           || process.env.GROQ_KEY,
  };
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  MIDDLEWARE HELPERS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/**
 * verifyAuth â€” extracts and validates Firebase ID token from header.
 * Returns decoded token (contains uid, email) or throws 401.
 *
 * SECURITY: The ID token is a short-lived JWT signed by Firebase.
 * It cannot be forged by the client. We verify it with the Admin SDK
 * which checks Firebase's public keys. Only real logged-in users pass.
 */
async function verifyAuth(req) {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) {
    const err = new Error("Missing Authorization header");
    err.code = 401;
    throw err;
  }
  const idToken = authHeader.slice(7);
  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    return decoded; // { uid, email, name, ... }
  } catch (e) {
    const err = new Error("Invalid or expired ID token");
    err.code = 401;
    throw err;
  }
}

/**
 * checkPremiumStatus â€” reads Firestore (NOT localStorage, NOT client input).
 * Returns { isPremium, planType, expiry }.
 *
 * SECURITY: Only the server can write to Firestore premium fields via
 * Admin SDK with security rules blocking client writes to premium/*.
 */
async function checkPremiumStatus(uid) {
  const userDoc = await db.collection("users").doc(uid).get();
  if (!userDoc.exists) {
    return { isPremium: false, planType: "free", expiry: null };
  }
  const data = userDoc.data();

  // Check expiry server-side â€” client cannot fake this
  if (data.premiumExpiry && data.premiumExpiry.toDate() < new Date()) {
    // Subscription lapsed â€” auto-downgrade in Firestore
    await db.collection("users").doc(uid).update({
      premium: false,
      planType: "free",
    });
    return { isPremium: false, planType: "free", expiry: null };
  }

  return {
    isPremium: data.premium === true,
    planType: data.planType || "free",
    expiry: data.premiumExpiry ? data.premiumExpiry.toDate().toISOString() : null,
  };
}

// Simple in-memory rate limiter (resets on cold start â€” good enough for abuse prevention)
const rateLimitMap = new Map();
function rateLimit(uid, maxPerMinute = 20) {
  const now = Date.now();
  const window = 60_000;
  const entry = rateLimitMap.get(uid) || { count: 0, start: now };
  if (now - entry.start > window) {
    entry.count = 1;
    entry.start = now;
  } else {
    entry.count++;
  }
  rateLimitMap.set(uid, entry);
  return entry.count > maxPerMinute;
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  ENDPOINT 1: /createOrder
//  Creates a Razorpay order on the backend.
//  SECRET KEY never leaves the server.
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
exports.createOrder = functions.https.onRequest((req, res) => {
  corsHandler(req, res, async () => {
    if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

    try {
      // Step 1: Authenticate the request
      const user = await verifyAuth(req);

      // Step 2: Rate limit
      if (rateLimit(user.uid, 5)) {
        return res.status(429).json({ error: "Too many requests. Slow down." });
      }

      // Step 3: Get plan details from request body
      const { planType = "monthly" } = req.body || {};

      // Step 4: Determine amount from server-side config (never trust client amount)
      const PLANS = {
        monthly: 9900,  // â‚¹99 in paise
        yearly:  79900, // â‚¹799 in paise
      };
      const amount = PLANS[planType] || PLANS.monthly;

      // Step 5: Create order using SECRET KEY from env â€” never exposed to client
      const cfg = getConfig();
      const razorpay = new Razorpay({
        key_id:     cfg.RAZORPAY_KEY_ID,
        key_secret: cfg.RAZORPAY_KEY_SECRET,
      });

      const order = await razorpay.orders.create({
        amount,
        currency: "INR",
        receipt:  `lw_${user.uid.slice(0, 10)}_${Date.now()}`,
        notes: {
          uid:      user.uid,
          email:    user.email || "",
          planType,
        },
      });

      // Step 6: Store pending order in Firestore for verification later
      await db.collection("orders").doc(order.id).set({
        uid:       user.uid,
        orderId:   order.id,
        amount,
        planType,
        status:    "created",
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      // Step 7: Return order ID + public key only (NOT secret key)
      return res.json({
        orderId:  order.id,
        amount,
        currency: "INR",
        keyId:    cfg.RAZORPAY_KEY_ID, // Public key is safe to send
      });

    } catch (err) {
      console.error("createOrder error:", err);
      return res.status(err.code || 500).json({ error: err.message || "Server error" });
    }
  });
});

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  ENDPOINT 2: /verifyPayment
//  Verifies Razorpay HMAC signature.
//  Only marks user as premium AFTER cryptographic verification.
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
exports.verifyPayment = functions.https.onRequest((req, res) => {
  corsHandler(req, res, async () => {
    if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

    try {
      // Step 1: Authenticate
      const user = await verifyAuth(req);

      const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body || {};

      if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
        return res.status(400).json({ error: "Missing payment fields" });
      }

      // Step 2: Verify the order belongs to this user (anti-hijacking)
      const orderDoc = await db.collection("orders").doc(razorpay_order_id).get();
      if (!orderDoc.exists) {
        return res.status(404).json({ error: "Order not found" });
      }
      const orderData = orderDoc.data();
      if (orderData.uid !== user.uid) {
        // SECURITY: Someone tried to verify another user's payment
        console.error(`SECURITY: UID mismatch! Order UID: ${orderData.uid}, Request UID: ${user.uid}`);
        return res.status(403).json({ error: "Forbidden" });
      }
      if (orderData.status === "paid") {
        return res.status(409).json({ error: "Order already processed" });
      }

      // Step 3: HMAC-SHA256 signature verification
      // SECURITY: This is the critical anti-bypass step.
      // A fake payment_id will produce a wrong signature and be rejected.
      const cfg = getConfig();
      const expectedSignature = crypto
        .createHmac("sha256", cfg.RAZORPAY_KEY_SECRET)
        .update(`${razorpay_order_id}|${razorpay_payment_id}`)
        .digest("hex");

      const signaturesMatch = crypto.timingSafeEqual(
        Buffer.from(expectedSignature, "hex"),
        Buffer.from(razorpay_signature, "hex")
      );

      if (!signaturesMatch) {
        console.error(`SECURITY: Invalid payment signature for order ${razorpay_order_id}`);
        return res.status(400).json({ error: "Payment verification failed. Signature mismatch." });
      }

      // Step 4: Signature valid â€” upgrade user in Firestore
      const months = orderData.planType === "yearly" ? 12 : 1;
      const expiry = new Date();
      expiry.setMonth(expiry.getMonth() + months);

      // Batch write for atomicity
      const batch = db.batch();

      batch.set(db.collection("users").doc(user.uid), {
        premium:       true,
        planType:      orderData.planType || "monthly",
        premiumExpiry: admin.firestore.Timestamp.fromDate(expiry),
        email:         user.email || "",
        displayName:   user.name || "",
        uid:           user.uid,
        updatedAt:     admin.firestore.FieldValue.serverTimestamp(),
        createdAt:     admin.firestore.FieldValue.serverTimestamp(),
      }, { merge: true });

      batch.update(db.collection("orders").doc(razorpay_order_id), {
        status:    "paid",
        paymentId: razorpay_payment_id,
        paidAt:    admin.firestore.FieldValue.serverTimestamp(),
      });

      await batch.commit();

      console.log(`âœ… Payment verified. User ${user.uid} upgraded to premium until ${expiry.toISOString()}`);

      return res.json({
        success: true,
        premium: true,
        expiry:  expiry.toISOString(),
        message: "Payment verified. Premium activated!",
      });

    } catch (err) {
      console.error("verifyPayment error:", err);
      return res.status(err.code || 500).json({ error: err.message || "Server error" });
    }
  });
});

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  ENDPOINT 3: /razorpayWebhook
//  Handles Razorpay server-to-server payment.captured event.
//  SECURITY: Uses a SEPARATE webhook secret, not the API secret.
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
exports.razorpayWebhook = functions.https.onRequest(async (req, res) => {
  // No CORS needed â€” this is server-to-server from Razorpay
  if (req.method !== "POST") return res.status(405).end();

  try {
    const cfg = getConfig();
    const webhookSecret = cfg.RAZORPAY_WEBHOOK_SEC;

    // Step 1: Verify webhook signature using raw body
    const razorpaySignature = req.headers["x-razorpay-signature"];
    if (!razorpaySignature) {
      return res.status(400).send("Missing webhook signature");
    }

    // The raw body is needed for HMAC â€” use express raw middleware
    const rawBody = JSON.stringify(req.body);
    const expectedSig = crypto
      .createHmac("sha256", webhookSecret)
      .update(rawBody)
      .digest("hex");

    const isValid = crypto.timingSafeEqual(
      Buffer.from(expectedSig, "hex"),
      Buffer.from(razorpaySignature, "hex")
    );

    if (!isValid) {
      console.error("SECURITY: Invalid webhook signature");
      return res.status(400).send("Invalid signature");
    }

    // Step 2: Process the event
    const event = req.body;
    console.log(`Webhook received: ${event.event}`);

    if (event.event === "payment.captured") {
      const payment  = event.payload.payment.entity;
      const orderId  = payment.order_id;
      const paymentId = payment.id;
      const uid      = payment.notes?.uid;

      if (!uid) {
        console.error("Webhook: no UID in payment notes for order", orderId);
        return res.status(200).send("ok"); // Acknowledge to Razorpay
      }

      // Check if already processed (idempotency)
      const orderDoc = await db.collection("orders").doc(orderId).get();
      if (orderDoc.exists && orderDoc.data().status === "paid") {
        console.log(`Webhook: order ${orderId} already processed, skipping.`);
        return res.status(200).send("ok");
      }

      // Upgrade user
      const planType = payment.notes?.planType || "monthly";
      const months   = planType === "yearly" ? 12 : 1;
      const expiry   = new Date();
      expiry.setMonth(expiry.getMonth() + months);

      const batch = db.batch();
      batch.set(db.collection("users").doc(uid), {
        premium:       true,
        planType,
        premiumExpiry: admin.firestore.Timestamp.fromDate(expiry),
        updatedAt:     admin.firestore.FieldValue.serverTimestamp(),
      }, { merge: true });

      if (orderDoc.exists) {
        batch.update(db.collection("orders").doc(orderId), {
          status:    "paid",
          paymentId,
          paidAt:    admin.firestore.FieldValue.serverTimestamp(),
        });
      }

      await batch.commit();
      console.log(`âœ… Webhook: User ${uid} upgraded via webhook`);
    }

    // Always return 200 to acknowledge receipt
    return res.status(200).send("ok");

  } catch (err) {
    console.error("Webhook error:", err);
    // Still return 200 to prevent Razorpay from retrying indefinitely
    return res.status(200).send("ok");
  }
});

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  ENDPOINT 4: /checkPremium
//  Returns real premium status from Firestore.
//  SECURITY: Client localStorage is completely bypassed.
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
exports.checkPremium = functions.https.onRequest((req, res) => {
  corsHandler(req, res, async () => {
    if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

    try {
      const user   = await verifyAuth(req);
      const status = await checkPremiumStatus(user.uid);

      return res.json({
        uid:       user.uid,
        isPremium: status.isPremium,
        planType:  status.planType,
        expiry:    status.expiry,
        // SECURITY: Never include API keys or secrets in this response
      });

    } catch (err) {
      return res.status(err.code || 500).json({ error: err.message });
    }
  });
});

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  ENDPOINT 5: /generateResponse
//  AI API proxy â€” only accessible to premium users.
//  The AI API key NEVER leaves the server.
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
exports.generateResponse = functions
  .runWith({ timeoutSeconds: 120, memory: "512MB" })
  .https.onRequest((req, res) => {
  corsHandler(req, res, async () => {
    if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

    try {
      // Step 1: Authenticate
      const user = await verifyAuth(req);

      // Step 2: Rate limit (max 30 AI calls/min per user)
      if (rateLimit(user.uid, 30)) {
        return res.status(429).json({ error: "Rate limit exceeded. Try again shortly." });
      }

      // Step 3: Check premium from Firestore (not client localStorage!)
      const status = await checkPremiumStatus(user.uid);
      if (!status.isPremium) {
        return res.status(403).json({
          error: "Premium required",
          code:  "NOT_PREMIUM",
          message: "This feature requires a Lemowaves Premium subscription.",
        });
      }

      // Step 4: Validate request body
      const { messages, model, systemPrompt, maxTokens } = req.body || {};
      if (!messages || !Array.isArray(messages) || messages.length === 0) {
        return res.status(400).json({ error: "messages array is required" });
      }

      // Step 5: Sanitize messages (strip any attempts to inject system override)
      const sanitized = messages
        .filter(m => m && m.role && m.content)
        .map(m => ({
          role:    m.role === "user" ? "user" : "assistant",
          content: typeof m.content === "string"
            ? m.content.slice(0, 8000)
            : m.content, // Allow multipart for vision
        }))
        .slice(-20); // Max 20 messages context

      // Step 6: Build request using backend API key
      const cfg = getConfig();
      const safeModel = "llama-3.3-70b-versatile"; // Override any client-provided model
      const body = {
        model:      safeModel,
        messages:   [
          { role: "system", content: systemPrompt || "You are Lemowaves AI, a helpful assistant." },
          ...sanitized,
        ],
        max_tokens: Math.min(maxTokens || 4000, 8000),
        temperature: 0.7,
      };

      // Step 7: Call AI API â€” key stays on server
      const aiRes = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method:  "POST",
        headers: {
          "Content-Type":  "application/json",
          "Authorization": `Bearer ${cfg.GROQ_KEY}`,
        },
        body: JSON.stringify(body),
      });

      if (!aiRes.ok) {
        const errText = await aiRes.text();
        console.error("AI API error:", errText);
        return res.status(502).json({ error: "AI service error. Try again." });
      }

      const aiData = await aiRes.json();
      const reply  = aiData?.choices?.[0]?.message?.content || "";

      if (!reply) {
        return res.status(502).json({ error: "Empty response from AI" });
      }

      // Log usage (for billing/monitoring â€” never log API key)
      await db.collection("usage").add({
        uid:       user.uid,
        model:     safeModel,
        tokens:    aiData?.usage?.total_tokens || 0,
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
      });

      return res.json({ reply, model: safeModel });

    } catch (err) {
      console.error("generateResponse error:", err);
      return res.status(err.code || 500).json({ error: err.message || "Server error" });
    }
  });
});

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  FIRESTORE SECURITY â€” Scheduled cleanup
//  Runs daily to purge expired orders older than 90 days
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
exports.cleanupExpiredOrders = functions.pubsub
  .schedule("every 24 hours")
  .onRun(async () => {
    const cutoff  = new Date();
    cutoff.setDate(cutoff.getDate() - 90);
    const snap = await db.collection("orders")
      .where("createdAt", "<", admin.firestore.Timestamp.fromDate(cutoff))
      .where("status", "!=", "paid")
      .limit(100)
      .get();

    const batch = db.batch();
    snap.docs.forEach(doc => batch.delete(doc.ref));
    await batch.commit();
    console.log(`Cleaned up ${snap.size} expired orders`);
    return null;
  });
