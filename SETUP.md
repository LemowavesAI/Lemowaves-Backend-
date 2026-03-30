## ══════════════════════════════════════════════════════════════
##  LEMOWAVES AI — ENVIRONMENT VARIABLES SETUP
##  Run these commands in your terminal to set all secrets.
##  NEVER commit actual keys to Git. Use .gitignore on .env files.
## ══════════════════════════════════════════════════════════════

## ── STEP 1: Install Firebase CLI ──────────────────────────────
npm install -g firebase-tools

## ── STEP 2: Login & select project ───────────────────────────
firebase login
firebase use --add
# → Select your Firebase project (lemowaves-d5e8e)

## ── STEP 3: Set all secrets via Firebase config ───────────────
## Replace the placeholder values with your real keys.
## These are stored encrypted in Firebase — not in your code.

firebase functions:config:set \
  razorpay.key_id="rzp_live_REPLACE_WITH_YOUR_KEY_ID" \
  razorpay.key_secret="REPLACE_WITH_YOUR_RAZORPAY_SECRET" \
  razorpay.webhook_sec="REPLACE_WITH_YOUR_WEBHOOK_SECRET" \
  ai.groq_key="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" \
  ai.gemini_key="AIzaSyBtL-rOYderQ3mryHHvOe-t5L7ZMqrFVvg" \
  ai.stability_key="sk-eYEnfYpZ4yLeMkwUgTZOIwU9tg2sD1i2gKZ4WFXpG25vE4ub"

## ── STEP 4: Verify config was saved ──────────────────────────
firebase functions:config:get

## ── STEP 5: Deploy functions ──────────────────────────────────
cd functions
npm install
cd ..
firebase deploy --only functions

## ── STEP 6: Deploy Firestore rules ───────────────────────────
firebase deploy --only firestore:rules

## ── STEP 7: Set up Razorpay Webhook ──────────────────────────
## In your Razorpay Dashboard → Settings → Webhooks → Add New
##
## Webhook URL:
##   https://us-central1-YOUR_PROJECT_ID.cloudfunctions.net/razorpayWebhook
##   (Replace YOUR_PROJECT_ID with your Firebase project ID)
##
## Events to select:
##   ✅ payment.captured
##
## Secret: Use the SAME value as razorpay.webhook_sec above
## (Generate a random 32-char string: openssl rand -hex 16)

## ── STEP 8: Get your function URLs ───────────────────────────
## After deploy, your endpoints will be:
## https://us-central1-YOUR_PROJECT_ID.cloudfunctions.net/createOrder
## https://us-central1-YOUR_PROJECT_ID.cloudfunctions.net/verifyPayment
## https://us-central1-YOUR_PROJECT_ID.cloudfunctions.net/razorpayWebhook
## https://us-central1-YOUR_PROJECT_ID.cloudfunctions.net/checkPremium
## https://us-central1-YOUR_PROJECT_ID.cloudfunctions.net/generateResponse

## ── LOCAL TESTING ─────────────────────────────────────────────
## To test locally with the emulator:
firebase functions:config:get > functions/.runtimeconfig.json
firebase emulators:start --only functions,firestore

## ── .gitignore additions ──────────────────────────────────────
## Add these to your .gitignore:
## functions/.runtimeconfig.json
## .env
## *.env
## service-account-key.json
