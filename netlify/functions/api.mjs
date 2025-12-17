// netlify/functions/api.mjs
import serverless from "serverless-http";
import express from "express";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import speakeasy from "speakeasy";
import session from "express-session";
import QRCode from "qrcode";
import { getStore } from "@netlify/blobs";

// Donnees par defaut
const DEFAULT_DATA = {
  skills: [
    "Anglais (LV)",
    "Certification Pix (3e)",
    "Renovation d'ordinateurs",
    "Diagnostics materiels",
    "Bases reseaux",
    "Sens du service"
  ],
  interests: [
    "Sport - Ultimate, tennis, natation",
    "Gaming en reseau",
    "Reseaux sociaux - TikTok, Instagram, YouTube"
  ],
  experiences: [],
  contact: {
    email: "viktormorel@mailo.com",
    phone: "06.14.09.93.55",
    linkedin: "viktormorel"
  }
};

// Stockage en memoire (fallback si Blobs echoue)
let inMemoryData = null;
let inMemoryLogins = [];
let inMemoryStats = { visits: 0, lastVisits: [] };

// Helper pour obtenir le store Netlify Blobs
function getBlobStore() {
  // Utiliser directement getStore avec le nom - Netlify injecte le contexte automatiquement
  // Cela fonctionne si le site a Blobs active
  return getStore("cv-data");
}

// Netlify Blobs pour persistance (avec fallback memoire)
async function loadSiteData() {
  // D'abord essayer la memoire
  if (inMemoryData) {
    console.log("[Data] Returning from memory");
    return inMemoryData;
  }

  // Ensuite essayer Blobs
  try {
    const store = getBlobStore();
    const data = await store.get("site-data", { type: "json" });
    if (data) {
      console.log("[Data] Loaded from Blobs");
      inMemoryData = data;
      return data;
    }
  } catch (err) {
    console.error("[Data] Blobs read error:", err.message);
  }

  // Fallback aux donnees par defaut
  console.log("[Data] Using defaults");
  inMemoryData = { ...DEFAULT_DATA };
  return inMemoryData;
}

async function saveSiteData(data) {
  // Toujours sauvegarder en memoire d'abord
  inMemoryData = data;
  console.log("[Save] Saved to memory");

  // Essayer de sauvegarder dans Blobs
  try {
    const store = getBlobStore();
    await store.setJSON("site-data", data);
    console.log("[Save] Saved to Blobs successfully");
  } catch (err) {
    console.error("[Save] Blobs write error:", err.message);
    // Ne pas throw - on a sauvegarde en memoire au moins
    // Les donnees persisteront pendant la session
  }
}

// Gestion des connexions avec Netlify Blobs (avec fallback memoire)
async function loadLogins() {
  // D'abord essayer Blobs
  try {
    const store = getBlobStore();
    const logins = await store.get("logins", { type: "json" });
    if (logins) {
      inMemoryLogins = logins;
      return logins;
    }
  } catch (err) {
    console.error("[Logins] Blobs read error:", err.message);
  }
  return inMemoryLogins;
}

async function saveLogin(user) {
  try {
    let logins = await loadLogins();
    const userEmail = user.emails?.[0]?.value || "";
    const now = Date.now();

    // Eviter les doublons : ne pas enregistrer si meme email dans les 5 dernieres minutes
    const fiveMinutesAgo = now - (5 * 60 * 1000);
    const recentLogin = logins.find(login =>
      login.email === userEmail &&
      login.date &&
      new Date(login.date).getTime() > fiveMinutesAgo
    );

    if (recentLogin) {
      console.log("[Logins] Already recorded recently for:", userEmail);
      return;
    }

    // Ajouter la nouvelle connexion
    logins.unshift({
      name: user.displayName || "",
      email: userEmail,
      photo: user.photos?.[0]?.value || "",
      date: new Date().toISOString()
    });

    // Garder uniquement les connexions des 15 derniers jours
    const fifteenDaysAgo = now - (15 * 24 * 60 * 60 * 1000);
    logins = logins.filter(login => {
      if (!login.date) return false;
      return new Date(login.date).getTime() > fifteenDaysAgo;
    });

    // Sauvegarder en memoire
    inMemoryLogins = logins;

    // Essayer de sauvegarder dans Blobs
    try {
      const store = getBlobStore();
      await store.setJSON("logins", logins);
      console.log("[Logins] Saved to Blobs for:", user.displayName);
    } catch (blobErr) {
      console.error("[Logins] Blobs write error:", blobErr.message);
    }
  } catch (err) {
    console.error("[Logins] Error:", err.message);
  }
}

// Compteur de visites (avec fallback memoire)
async function incrementVisits() {
  // Charger les stats existantes
  let stats = inMemoryStats;

  try {
    const store = getBlobStore();
    const blobStats = await store.get("stats", { type: "json" });
    if (blobStats) stats = blobStats;
  } catch (e) {
    console.log("[Stats] Blobs read error, using memory");
  }

  if (!stats) stats = { visits: 0, lastVisits: [] };

  const now = new Date();
  const today = now.toISOString().split('T')[0];

  // Incrementer le compteur total
  stats.visits = (stats.visits || 0) + 1;

  // Garder l'historique des 30 derniers jours
  if (!stats.lastVisits) stats.lastVisits = [];
  const todayEntry = stats.lastVisits.find(v => v.date === today);
  if (todayEntry) {
    todayEntry.count++;
  } else {
    stats.lastVisits.unshift({ date: today, count: 1 });
    stats.lastVisits = stats.lastVisits.slice(0, 30);
  }

  // Sauvegarder en memoire
  inMemoryStats = stats;

  // Essayer de sauvegarder dans Blobs
  try {
    const store = getBlobStore();
    await store.setJSON("stats", stats);
    console.log("[Stats] Saved to Blobs:", stats.visits);
  } catch (err) {
    console.error("[Stats] Blobs write error:", err.message);
  }

  return stats;
}

async function getStats() {
  // D'abord essayer Blobs
  try {
    const store = getBlobStore();
    const stats = await store.get("stats", { type: "json" });
    if (stats) {
      inMemoryStats = stats;
      return stats;
    }
  } catch (err) {
    console.error("[Stats] Blobs read error:", err.message);
  }
  return inMemoryStats;
}

function isAdmin(req) {
  if (!req.user || !req.user.emails || req.user.emails.length === 0) return false;
  const userEmail = req.user.emails[0].value;
  const adminEmail = process.env.ADMIN_EMAIL || "vikvahe@gmail.com";
  return userEmail === adminEmail;
}

function ensureAdmin(req, res, next) {
  if (req.isAuthenticated() && req.session.twoFA === true && isAdmin(req)) return next();
  res.status(403).json({ error: "Acces refuse - Admin uniquement" });
}

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated() && req.session.twoFA === true) return next();
  res.status(401).json({ error: "Non authentifie" });
}

// Notification Discord lors d'une connexion
async function notifyDiscord(user) {
  const webhookUrl = "https://discord.com/api/webhooks/1448025894886314178/rNO_tuMKNiOfFaHZPwDVq7vQOmUhNbjxRfWDKntmvoyhZaXX_tzD7bcIXSKU3jiKgKw7";

  try {
    const payload = {
      embeds: [{
        title: "Nouvelle connexion sur le CV",
        color: 0x6a11cb,
        fields: [
          { name: "Nom", value: user.displayName || "Inconnu", inline: true },
          { name: "Email", value: user.emails?.[0]?.value || "Inconnu", inline: true }
        ],
        thumbnail: { url: user.photos?.[0]?.value || "" },
        timestamp: new Date().toISOString()
      }]
    };

    await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
  } catch (err) {
    console.error("Erreur notification Discord:", err);
  }
}

// App
const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");

// Rate limiting simple en memoire (protection brute-force)
const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX = 10; // 10 requetes par minute pour les routes sensibles

function rateLimit(key, max = RATE_LIMIT_MAX) {
  const now = Date.now();
  const record = rateLimitStore.get(key) || { count: 0, resetAt: now + RATE_LIMIT_WINDOW };

  if (now > record.resetAt) {
    record.count = 1;
    record.resetAt = now + RATE_LIMIT_WINDOW;
  } else {
    record.count++;
  }

  rateLimitStore.set(key, record);

  // Nettoyer les anciennes entrees toutes les 100 requetes
  if (rateLimitStore.size > 1000) {
    for (const [k, v] of rateLimitStore) {
      if (now > v.resetAt) rateLimitStore.delete(k);
    }
  }

  return record.count <= max;
}

// Middleware rate limiting pour routes sensibles
function rateLimitMiddleware(max = RATE_LIMIT_MAX) {
  return (req, res, next) => {
    const ip = req.ip || req.headers["x-forwarded-for"] || "unknown";
    const key = `${ip}:${req.path}`;

    if (!rateLimit(key, max)) {
      return res.status(429).json({ error: "Trop de requetes. Reessayez dans 1 minute." });
    }
    next();
  };
}

// Body parsing avec limite de taille
app.use(express.urlencoded({ extended: true, limit: "10kb" }));
app.use(express.json({ limit: "10kb" }));

// Sessions (securisees)
app.use(
  session({
    secret: process.env.SESSION_SECRET || "secret-key-change-me-in-prod",
    name: "__Host-session", // Prefixe securise
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true, // Toujours HTTPS
      sameSite: "strict", // Protection CSRF renforcee
      httpOnly: true, // Pas accessible via JS
      maxAge: 30 * 60 * 1000, // 30 minutes
      path: "/"
    }
  })
);

// Headers de securite (avant toute route)
app.use((_req, res, next) => {
  // HSTS - Force HTTPS pendant 1 an
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");

  // Empeche le clickjacking
  res.setHeader("X-Frame-Options", "DENY");

  // Bloque le MIME sniffing
  res.setHeader("X-Content-Type-Options", "nosniff");

  // Protection XSS navigateur
  res.setHeader("X-XSS-Protection", "1; mode=block");

  // Referrer Policy - ne pas fuiter les URLs
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

  // Permissions Policy - desactiver les features non utilisees
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()");

  // Content Security Policy restrictive
  res.setHeader("Content-Security-Policy", [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'", // inline necessaire pour le HTML injecte
    "style-src 'self' 'unsafe-inline' fonts.googleapis.com",
    "font-src 'self' fonts.gstatic.com",
    "img-src 'self' data: https:",
    "connect-src 'self' https://discord.com",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self' https://accounts.google.com"
  ].join("; "));

  next();
});

// CORS restrictif (pas de wildcard en prod)
app.use((req, res, next) => {
  console.log(`[API] ${req.method} ${req.path} (originalUrl: ${req.originalUrl})`);

  const allowedOrigins = [
    "https://viktor-morel.netlify.app",
    "https://cv-viktor-morel.netlify.app",
    "https://viktormorel.com" // Si tu as un domaine custom
  ];
  const origin = req.headers.origin;

  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }

  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Credentials", "true");

  if (req.method === "OPTIONS") return res.status(204).end();
  next();
});

// Google OAuth - initialisation différée
// IMPORTANT: L'URL doit correspondre EXACTEMENT à celle dans Google Cloud Console
const CALLBACK_URL = "https://viktor-morel.netlify.app/.netlify/functions/api/auth/google/callback";

app.use(passport.initialize());
app.use(passport.session());

// Initialiser Google Strategy seulement si les credentials sont présentes
let googleStrategyInitialized = false;
function initGoogleStrategy() {
  if (googleStrategyInitialized) return;
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
    console.error("GOOGLE_CLIENT_ID ou GOOGLE_CLIENT_SECRET manquant!");
    return;
  }
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: CALLBACK_URL
      },
      (accessToken, refreshToken, profile, done) => done(null, profile)
    )
  );
  googleStrategyInitialized = true;
}

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// Health
app.get("/health", (req, res) => res.json({ status: "ok" }));

// Auth start - Rate limited (10 tentatives/min)
app.get("/auth/google", rateLimitMiddleware(10), (req, res, next) => {
  initGoogleStrategy();
  passport.authenticate("google", { scope: ["profile", "email"] })(req, res, next);
});

// Auth callback (double chemin pour compat)
app.get(["/auth/google/callback", "/.netlify/functions/api/auth/google/callback"], (req, res, next) => {
  initGoogleStrategy();
  passport.authenticate("google", async (err, user) => {
    if (err) {
      console.error("OAuth error:", err);
      return res.status(500).send("Erreur OAuth");
    }
    if (!user) return res.redirect("/");
    req.logIn(user, async (loginErr) => {
      if (loginErr) {
        console.error("Erreur de connexion:", loginErr);
        return res.status(500).send("Erreur de connexion.");
      }
      // Enregistrer la connexion et notifier Discord
      await saveLogin(user);
      notifyDiscord(user);

      // Tout le monde passe par la 2FA (admin inclus)
      res.redirect("/login-2fa.html");
    });
  })(req, res, next);
});

// 2FA: formulaire
app.post("/verify-2fa", (req, res) => {
  const secret = req.session.twoFASecret || process.env.TWOFA_SECRET;
  if (!secret) return res.status(400).send("<h2>Erreur serveur : secret 2FA manquant.</h2>");
  const verified = speakeasy.totp.verify({
    secret,
    encoding: "base32",
    token: String(req.body.token || "").trim(),
    window: 1
  });
  if (verified) {
    req.session.twoFA = true;
    return res.redirect("/download.html");
  }
  res.send("<h2>Code invalide, réessaie.</h2><a href='/login-2fa.html'>Retour</a>");
});

// 2FA: API generate
app.post(["/api/2fa/generate", "/2fa/generate", "/.netlify/functions/api/2fa/generate"], async (req, res) => {
  try {
    const secret = speakeasy.generateSecret({ length: 20, name: "ViktorMorel" });
    req.session.twoFASecret = secret.base32;
    const dataUrl = await QRCode.toDataURL(secret.otpauth_url);
    res.json({ secret: secret.base32, qrCode: dataUrl });
  } catch (err) {
    console.error("2FA generate error:", err);
    res.status(500).json({ error: "2FA generate failed" });
  }
});

// 2FA: API verify (supporte email et qrcode) - Rate limited (5 essais/min)
app.post(["/api/2fa/verify", "/2fa/verify", "/.netlify/functions/api/2fa/verify"], rateLimitMiddleware(5), (req, res) => {
  const token = String(req.body.token || "").trim();
  const method = req.body.method || "qrcode";

  if (!token) return res.status(400).json({ valid: false, error: "token missing" });

  let verified = false;

  if (method === "email") {
    // Verification du code email
    const emailCode = req.session.emailCode;
    const emailCodeExpiry = req.session.emailCodeExpiry;

    if (!emailCode) {
      return res.json({ valid: false, error: "Aucun code envoye. Cliquez sur 'Envoyer le code'." });
    }
    if (Date.now() > emailCodeExpiry) {
      return res.json({ valid: false, error: "Code expire. Renvoyez un nouveau code." });
    }
    verified = (token === emailCode);
  } else {
    // Verification QR code (TOTP)
    const secret = req.session.twoFASecret || process.env.TWOFA_SECRET;
    if (!secret) return res.status(400).json({ valid: false, error: "secret missing" });
    verified = speakeasy.totp.verify({ secret, encoding: "base32", token, window: 1 });
  }

  if (verified) {
    req.session.twoFA = true;
    // Nettoyer le code email utilise
    delete req.session.emailCode;
    delete req.session.emailCodeExpiry;
    return res.json({ valid: true, message: "Code valide", redirect: "/.netlify/functions/api/download-cv" });
  }
  return res.json({ valid: false, error: "Code invalide" });
});

// 2FA: Generer et envoyer code par email via Brevo - Rate limited (3 demandes/min)
app.post(["/api/2fa/send-email", "/2fa/send-email", "/.netlify/functions/api/2fa/send-email"], rateLimitMiddleware(3), async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ success: false, error: "Non authentifie" });
  }

  const userEmail = req.user?.emails?.[0]?.value;
  const userName = req.user?.displayName || "Utilisateur";
  if (!userEmail) {
    return res.status(400).json({ success: false, error: "Email non disponible" });
  }

  // Generer un code a 6 chiffres
  const code = Math.floor(100000 + Math.random() * 900000).toString();

  // Stocker le code en session (expire dans 10 minutes)
  req.session.emailCode = code;
  req.session.emailCodeExpiry = Date.now() + 10 * 60 * 1000;

  // Envoyer l'email via Mailjet API
  const mjApiKey = process.env.MAILJET_API_KEY;
  const mjSecretKey = process.env.MAILJET_SECRET_KEY;
  if (!mjApiKey || !mjSecretKey) {
    console.error("MAILJET keys non configurees");
    return res.status(500).json({ success: false, error: "Service email non configure" });
  }

  try {
    const emailResponse = await fetch("https://api.mailjet.com/v3.1/send", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Basic " + Buffer.from(`${mjApiKey}:${mjSecretKey}`).toString("base64")
      },
      body: JSON.stringify({
        Messages: [{
          From: { Email: "vikvahe@gmail.com", Name: "Viktor Morel - CV" },
          To: [{ Email: userEmail, Name: userName }],
          Subject: "Votre code de verification - CV Viktor Morel",
          HTMLPart: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
              <div style="background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%); padding: 30px; border-radius: 12px; text-align: center;">
                <h1 style="color: white; margin: 0 0 10px;">Code de verification</h1>
                <p style="color: rgba(255,255,255,0.9); margin: 0;">Pour acceder au CV de Viktor Morel</p>
              </div>
              <div style="padding: 30px; background: #f8f9fa; border-radius: 0 0 12px 12px;">
                <p style="color: #333; font-size: 16px;">Bonjour ${userName},</p>
                <p style="color: #666; font-size: 14px;">Voici votre code de verification :</p>
                <div style="background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%); padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
                  <span style="font-size: 32px; font-weight: bold; color: white; letter-spacing: 8px;">${code}</span>
                </div>
                <p style="color: #999; font-size: 12px; text-align: center;">Ce code expire dans 10 minutes.</p>
              </div>
            </div>
          `
        }]
      })
    });

    if (!emailResponse.ok) {
      const errorData = await emailResponse.text();
      console.error("Erreur Mailjet:", errorData);
      return res.status(500).json({ success: false, error: "Erreur envoi email" });
    }

    res.json({
      success: true,
      message: "Code envoye par email ! Verifie ta boite de reception (et les spams)."
    });
  } catch (err) {
    console.error("Erreur envoi email:", err);
    res.status(500).json({ success: false, error: "Erreur serveur" });
  }
});

// Info utilisateur (pour afficher l'email + isAdmin)
app.get(["/api/user-info", "/user-info", "/.netlify/functions/api/user-info"], (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Non authentifie" });
  }
  res.json({
    email: req.user?.emails?.[0]?.value || "",
    name: req.user?.displayName || "",
    isAdmin: isAdmin(req)
  });
});

// Admin: voir le code 2FA actuel (pour admin uniquement)
app.get(["/api/admin/2fa-code", "/admin/2fa-code", "/.netlify/functions/api/admin/2fa-code"], (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Non authentifie" });
  }
  if (!isAdmin(req)) {
    return res.status(403).json({ error: "Admin uniquement" });
  }

  // Generer un code admin (ou utiliser le code email existant)
  let code = req.session.emailCode;

  // Si pas de code ou expire, en generer un nouveau
  if (!code || Date.now() > (req.session.emailCodeExpiry || 0)) {
    code = Math.floor(100000 + Math.random() * 900000).toString();
    req.session.emailCode = code;
    req.session.emailCodeExpiry = Date.now() + 10 * 60 * 1000;
  }

  res.json({ code });
});

// Admin
app.get(["/api/admin/check", "/admin/check", "/.netlify/functions/api/admin/check"], ensureAuthenticated, (req, res) => res.json({ isAdmin: isAdmin(req) }));
app.get(["/api/admin/check-login", "/admin/check-login", "/.netlify/functions/api/admin/check-login"], (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ isAdmin: false });
  res.json({ isAdmin: isAdmin(req) });
});
app.get(["/api/admin/data", "/admin/data", "/.netlify/functions/api/admin/data"], ensureAdmin, async (req, res) => {
  const data = await loadSiteData();
  res.json(data);
});
app.post(["/api/admin/save", "/admin/save", "/.netlify/functions/api/admin/save"], ensureAdmin, async (req, res) => {
  try {
    console.log("[Save] Donnees recues:", JSON.stringify(req.body).slice(0, 200));
    await saveSiteData(req.body);
    console.log("[Save] Sauvegarde reussie");
    res.json({ success: true });
  } catch (err) {
    console.error("[Save] Erreur sauvegarde:", err.message, err.stack);
    res.status(500).json({ error: "Erreur sauvegarde: " + err.message });
  }
});

// Admin: historique des connexions
app.get(["/api/admin/logins", "/admin/logins", "/.netlify/functions/api/admin/logins"], ensureAdmin, async (req, res) => {
  const logins = await loadLogins();
  res.json(logins);
});

// Statistiques de visites (public - pas de données sensibles)
app.get(["/api/admin/stats", "/admin/stats", "/.netlify/functions/api/admin/stats"], async (req, res) => {
  const stats = await getStats();
  res.json(stats);
});

// Tracking: incrementer le compteur de visites (appele depuis le frontend)
app.post(["/api/track-visit", "/track-visit", "/.netlify/functions/api/track-visit"], async (req, res) => {
  const stats = await incrementVisits();
  res.json({ success: true, visits: stats.visits });
});

// Auth check
app.get(["/auth-check", "/api/auth-check", "/.netlify/functions/api/auth-check"], (req, res) => {
  if (req.isAuthenticated() && req.session.twoFA === true) return res.json({ authenticated: true });
  res.json({ authenticated: false });
});

// Page download securisee - HTML servi uniquement si authentifie
app.get(["/download-cv", "/secure/download", "/.netlify/functions/api/download-cv"], (req, res) => {
  if (!req.isAuthenticated() || req.session.twoFA !== true) {
    return res.redirect("/");
  }
  const isAdminUser = isAdmin(req);
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Telechargement - CV Viktor Morel</title><link rel="stylesheet" href="/styles.css"><style>body{-webkit-user-select:none;user-select:none}.download-hero{padding:80px 20px;text-align:center}.download-card{max-width:760px;margin:20px auto;padding:28px;border-radius:16px}.download-title{font-size:1.6rem;margin:0 0 12px}.download-sub{color:var(--muted);margin-bottom:18px}.big-download{font-size:1.05rem;padding:14px 20px;border-radius:12px}.btn-admin{background:linear-gradient(135deg,#ff6b6b,#ee5a24);margin-top:12px}</style></head><body class="centered-layout" oncontextmenu="return false"><main class="download-hero"><div class="download-card glass gradient-border"><h1 class="download-title">Acces securise</h1><p class="download-sub">Bravo - tu t'es authentifie avec succes via Google et valide la 2FA.</p><div style="display:flex;gap:16px;flex-wrap:wrap;justify-content:center;margin-top:18px"><a class="btn primary big-download" href="/.netlify/functions/api/download-cv/file">Telecharger le CV (DOCX)</a></div>${isAdminUser ? '<div style="margin-top:20px"><a class="btn btn-admin big-download" href="/.netlify/functions/api/admin-console">Console Administration</a></div>' : ''}<p style="margin-top:6px;color:var(--muted)">Contact: <a href="mailto:viktormorel@mailo.com">viktormorel@mailo.com</a></p></div></main><script>document.addEventListener("keydown",e=>{if(e.key==="F12"||(e.ctrlKey&&e.shiftKey)||(e.ctrlKey&&e.key==="u"))e.preventDefault()});</script></body></html>`);
});

// Route pour telecharger le fichier CV (protegee par auth)
// Utilise une page HTML intermediaire pour maintenir la session
app.get(["/download-cv/file", "/.netlify/functions/api/download-cv/file"], (req, res) => {
  if (!req.isAuthenticated() || req.session.twoFA !== true) {
    return res.status(401).json({ error: "Non autorise" });
  }
  // Page HTML qui telecharge automatiquement le fichier
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>Telechargement en cours...</title>
  <style>
    body{font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:linear-gradient(135deg,#667eea,#764ba2)}
    .card{background:white;padding:40px;border-radius:20px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.3)}
    h1{color:#1f2937;margin-bottom:12px}
    p{color:#6b7280}
    .spinner{width:50px;height:50px;border:4px solid #e5e7eb;border-top-color:#667eea;border-radius:50%;animation:spin 1s linear infinite;margin:20px auto}
    @keyframes spin{to{transform:rotate(360deg)}}
  </style>
</head>
<body>
  <div class="card">
    <div class="spinner"></div>
    <h1>Telechargement en cours</h1>
    <p>Le CV va se telecharger automatiquement...</p>
  </div>
  <script>
    // Telecharger via un lien invisible
    const link = document.createElement('a');
    link.href = '/cv-viktor-morel.docx';
    link.download = 'CV-Viktor-Morel.docx';
    document.body.appendChild(link);
    link.click();
    // Rediriger vers la page de download apres 2 secondes
    setTimeout(() => {
      window.location.href = '/.netlify/functions/api/download-cv';
    }, 2000);
  </script>
</body>
</html>`);
});

// Console admin securisee - Design premium avec animations
app.get(["/admin-console", "/secure/admin", "/.netlify/functions/api/admin-console"], (req, res) => {
  if (!req.isAuthenticated() || req.session.twoFA !== true || !isAdmin(req)) {
    return res.redirect("/");
  }
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Console Admin - CV Viktor Morel</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:'Inter',system-ui,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 50%,#f093fb 100%);min-height:100vh;-webkit-user-select:none;user-select:none}

    /* Animated background */
    .bg-animation{position:fixed;top:0;left:0;right:0;bottom:0;z-index:0;overflow:hidden}
    .bg-animation::before,.bg-animation::after{content:'';position:absolute;width:600px;height:600px;border-radius:50%;background:rgba(255,255,255,0.1);animation:float 20s infinite}
    .bg-animation::before{top:-200px;left:-200px}
    .bg-animation::after{bottom:-200px;right:-200px;animation-delay:-10s}
    @keyframes float{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(50px,50px) scale(1.1)}}

    /* Glass navbar */
    .navbar{position:fixed;top:0;left:0;right:0;height:70px;background:rgba(255,255,255,0.1);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border-bottom:1px solid rgba(255,255,255,0.2);z-index:1000;display:flex;justify-content:space-between;align-items:center;padding:0 30px}
    .navbar-brand{display:flex;align-items:center;gap:12px}
    .navbar-brand .logo{width:40px;height:40px;background:linear-gradient(135deg,#fff,#f0f0f0);border-radius:12px;display:flex;align-items:center;justify-content:center;font-weight:700;color:#764ba2;font-size:1.2rem;box-shadow:0 4px 15px rgba(0,0,0,0.1)}
    .navbar-brand span{color:white;font-weight:600;font-size:1.1rem}
    .navbar-links{display:flex;gap:8px}
    .navbar-links a{color:rgba(255,255,255,0.9);text-decoration:none;padding:10px 18px;border-radius:10px;font-weight:500;font-size:0.9rem;transition:all 0.3s;display:flex;align-items:center;gap:8px}
    .navbar-links a:hover{background:rgba(255,255,255,0.15);transform:translateY(-2px)}
    .navbar-links a svg{width:18px;height:18px}

    /* Main layout */
    .admin-layout{display:flex;min-height:100vh;padding-top:70px;position:relative;z-index:1}

    /* Premium Sidebar */
    .sidebar{width:300px;background:rgba(255,255,255,0.95);backdrop-filter:blur(20px);position:fixed;left:0;top:70px;bottom:0;padding:30px 20px;overflow-y:auto;box-shadow:4px 0 30px rgba(0,0,0,0.1)}
    .sidebar::-webkit-scrollbar{width:6px}
    .sidebar::-webkit-scrollbar-thumb{background:linear-gradient(135deg,#667eea,#764ba2);border-radius:3px}

    .user-card{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);border-radius:20px;padding:24px;margin-bottom:30px;text-align:center;position:relative;overflow:hidden}
    .user-card::before{content:'';position:absolute;top:-50%;left:-50%;width:200%;height:200%;background:radial-gradient(circle,rgba(255,255,255,0.1) 0%,transparent 60%);animation:shimmer 3s infinite}
    @keyframes shimmer{0%,100%{transform:rotate(0deg)}50%{transform:rotate(180deg)}}
    .user-avatar{width:70px;height:70px;background:rgba(255,255,255,0.2);border-radius:50%;margin:0 auto 12px;display:flex;align-items:center;justify-content:center;font-size:1.8rem;color:white;border:3px solid rgba(255,255,255,0.3)}
    .user-card h3{color:white;font-size:1.1rem;margin-bottom:4px;position:relative}
    .user-card p{color:rgba(255,255,255,0.8);font-size:0.85rem;position:relative}

    .menu-group{margin-bottom:28px}
    .menu-label{font-size:0.7rem;font-weight:600;color:#9ca3af;text-transform:uppercase;letter-spacing:1.5px;padding:0 16px;margin-bottom:12px}

    .menu-item{display:flex;align-items:center;gap:14px;padding:14px 16px;border-radius:14px;cursor:pointer;transition:all 0.3s cubic-bezier(0.4,0,0.2,1);color:#4b5563;font-weight:500;font-size:0.95rem;border:none;background:transparent;width:100%;text-align:left;margin-bottom:4px;position:relative;overflow:hidden}
    .menu-item::before{content:'';position:absolute;left:0;top:0;bottom:0;width:4px;background:linear-gradient(135deg,#667eea,#764ba2);border-radius:0 4px 4px 0;transform:scaleY(0);transition:transform 0.3s}
    .menu-item:hover{background:linear-gradient(135deg,#f3f4f6,#e5e7eb);color:#667eea;transform:translateX(4px)}
    .menu-item:hover::before{transform:scaleY(1)}
    .menu-item.active{background:linear-gradient(135deg,#667eea,#764ba2);color:white;box-shadow:0 8px 25px rgba(102,126,234,0.4)}
    .menu-item.active::before{display:none}
    .menu-item svg{width:22px;height:22px;flex-shrink:0;transition:transform 0.3s}
    .menu-item:hover svg{transform:scale(1.1)}
    .menu-item .badge{margin-left:auto;background:linear-gradient(135deg,#f59e0b,#ef4444);color:white;font-size:0.7rem;font-weight:600;padding:4px 10px;border-radius:20px;min-width:28px;text-align:center}
    .menu-item.active .badge{background:rgba(255,255,255,0.25)}

    /* Main content */
    .main-content{flex:1;margin-left:300px;padding:30px 40px}

    /* Section cards */
    .section-card{background:rgba(255,255,255,0.95);backdrop-filter:blur(20px);border-radius:24px;padding:32px;margin-bottom:24px;box-shadow:0 10px 40px rgba(0,0,0,0.1);border:1px solid rgba(255,255,255,0.5);animation:fadeIn 0.5s ease}
    @keyframes fadeIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
    .section-card h2{font-size:1.5rem;color:#1f2937;margin-bottom:24px;display:flex;align-items:center;gap:12px}
    .section-card h2 svg{width:28px;height:28px;color:#667eea}

    /* Form elements */
    .form-group{margin-bottom:20px}
    .form-group label{display:block;color:#4b5563;margin-bottom:8px;font-weight:600;font-size:0.9rem}
    .form-group input,.form-group textarea{width:100%;padding:14px 18px;border:2px solid #e5e7eb;border-radius:14px;font-size:1rem;color:#1f2937;transition:all 0.3s;background:white}
    .form-group input:focus,.form-group textarea:focus{outline:none;border-color:#667eea;box-shadow:0 0 0 4px rgba(102,126,234,0.15)}
    .form-group textarea{min-height:120px;resize:vertical}

    /* Item list */
    .item-list{list-style:none}
    .item-list li{display:flex;align-items:center;justify-content:space-between;padding:16px 20px;background:linear-gradient(135deg,#f9fafb,#f3f4f6);border-radius:14px;margin-bottom:12px;border:1px solid #e5e7eb;transition:all 0.3s}
    .item-list li:hover{transform:translateX(8px);box-shadow:0 4px 20px rgba(0,0,0,0.08);border-color:#667eea}
    .item-list li span{color:#1f2937;font-weight:500}
    .item-actions{display:flex;gap:8px}

    /* Buttons */
    .btn{padding:12px 24px;border-radius:12px;border:none;cursor:pointer;font-size:0.95rem;font-weight:600;transition:all 0.3s cubic-bezier(0.4,0,0.2,1);display:inline-flex;align-items:center;justify-content:center;gap:8px}
    .btn:hover{transform:translateY(-3px)}
    .btn-primary{background:linear-gradient(135deg,#667eea,#764ba2);color:white;box-shadow:0 4px 15px rgba(102,126,234,0.4)}
    .btn-primary:hover{box-shadow:0 8px 30px rgba(102,126,234,0.5)}
    .btn-success{background:linear-gradient(135deg,#10b981,#059669);color:white;box-shadow:0 4px 15px rgba(16,185,129,0.4)}
    .btn-success:hover{box-shadow:0 8px 30px rgba(16,185,129,0.5)}
    .btn-danger{background:linear-gradient(135deg,#ef4444,#dc2626);color:white}
    .btn-sm{padding:8px 16px;font-size:0.85rem;border-radius:10px}
    .btn-block{width:100%}

    /* Stats cards */
    .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin-bottom:24px}
    .stat-card{background:linear-gradient(135deg,#667eea,#764ba2);border-radius:20px;padding:28px;color:white;position:relative;overflow:hidden}
    .stat-card::before{content:'';position:absolute;top:0;right:0;width:100px;height:100px;background:rgba(255,255,255,0.1);border-radius:50%;transform:translate(30%,-30%)}
    .stat-card.alt{background:linear-gradient(135deg,#f59e0b,#ef4444)}
    .stat-card.green{background:linear-gradient(135deg,#10b981,#059669)}
    .stat-value{font-size:2.8rem;font-weight:700;margin-bottom:4px}
    .stat-label{font-size:0.9rem;opacity:0.9}

    /* Tab content */
    .tab-content{display:none}
    .tab-content.active{display:block}

    /* Message toast */
    .toast{position:fixed;bottom:30px;right:30px;padding:16px 24px;border-radius:14px;color:white;font-weight:500;transform:translateY(100px);opacity:0;transition:all 0.4s cubic-bezier(0.4,0,0.2,1);z-index:2000;display:flex;align-items:center;gap:12px}
    .toast.show{transform:translateY(0);opacity:1}
    .toast.success{background:linear-gradient(135deg,#10b981,#059669);box-shadow:0 10px 40px rgba(16,185,129,0.4)}
    .toast.error{background:linear-gradient(135deg,#ef4444,#dc2626);box-shadow:0 10px 40px rgba(239,68,68,0.4)}
    .toast svg{width:24px;height:24px}

    /* Modal */
    .modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.5);backdrop-filter:blur(8px);display:none;justify-content:center;align-items:center;z-index:2000;padding:20px}
    .modal-overlay.active{display:flex}
    .modal{background:white;border-radius:24px;padding:32px;max-width:500px;width:100%;max-height:85vh;overflow-y:auto;box-shadow:0 25px 80px rgba(0,0,0,0.3);animation:modalIn 0.3s ease}
    @keyframes modalIn{from{opacity:0;transform:scale(0.9)}to{opacity:1;transform:scale(1)}}
    .modal h3{font-size:1.4rem;color:#1f2937;margin-bottom:24px}
    .modal-actions{display:flex;gap:12px;margin-top:24px}
    .modal-actions .btn{flex:1}

    /* Responsive */
    @media(max-width:1024px){.sidebar{width:260px}.main-content{margin-left:260px;padding:20px}}
    @media(max-width:768px){.sidebar{transform:translateX(-100%);z-index:100}.sidebar.open{transform:translateX(0)}.main-content{margin-left:0;padding:20px}.navbar-brand span{display:none}}
  </style>
</head>
<body oncontextmenu="return false">
  <div class="bg-animation"></div>

  <nav class="navbar">
    <div class="navbar-brand">
      <div class="logo">VM</div>
      <span>Admin Console</span>
    </div>
    <div class="navbar-links">
      <a href="/"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>CV</a>
      <a href="/.netlify/functions/api/download-cv"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>Download</a>
    </div>
  </nav>

  <div class="admin-layout">
    <aside class="sidebar">
      <div class="user-card">
        <div class="user-avatar">V</div>
        <h3>Viktor Morel</h3>
        <p>Administrateur</p>
      </div>

      <div class="menu-group">
        <div class="menu-label">Gestion du contenu</div>
        <button class="menu-item active" onclick="showTab('skills')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
          Competences
        </button>
        <button class="menu-item" onclick="showTab('interests')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>
          Centres d'interet
        </button>
        <button class="menu-item" onclick="showTab('experience')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/></svg>
          Experiences
        </button>
        <button class="menu-item" onclick="showTab('contact')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z"/></svg>
          Contact
        </button>
      </div>

      <div class="menu-group">
        <div class="menu-label">Analytiques</div>
        <button class="menu-item" onclick="showTab('stats')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
          Statistiques
          <span class="badge" id="visits-badge">-</span>
        </button>
        <button class="menu-item" onclick="showTab('logins')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg>
          Connexions
          <span class="badge" id="logins-badge">-</span>
        </button>
      </div>
    </aside>

    <main class="main-content">
      <div id="tab-skills" class="tab-content active">
        <div class="section-card">
          <h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>Gerer les Competences</h2>
          <ul class="item-list" id="skills-list"></ul>
          <div class="form-group"><label>Nouvelle competence</label><input type="text" id="new-skill" placeholder="Ex: Python, Docker, React..."></div>
          <button class="btn btn-primary btn-block" onclick="addSkill()"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>Ajouter</button>
        </div>
      </div>

      <div id="tab-interests" class="tab-content">
        <div class="section-card">
          <h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>Centres d'interet</h2>
          <ul class="item-list" id="interests-list"></ul>
          <div class="form-group"><label>Nouveau centre d'interet</label><input type="text" id="new-interest" placeholder="Ex: Sport, Musique, Gaming..."></div>
          <button class="btn btn-primary btn-block" onclick="addInterest()"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>Ajouter</button>
        </div>
      </div>

      <div id="tab-experience" class="tab-content">
        <div class="section-card">
          <h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/></svg>Experiences professionnelles</h2>
          <ul class="item-list" id="experience-list"></ul>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
            <div class="form-group"><label>Titre</label><input type="text" id="exp-title" placeholder="Stage developpeur"></div>
            <div class="form-group"><label>Entreprise</label><input type="text" id="exp-company" placeholder="Nom de l'entreprise"></div>
            <div class="form-group"><label>Categorie</label><input type="text" id="exp-tag" placeholder="IT, Design..."></div>
            <div class="form-group"><label>Date</label><input type="text" id="exp-date" placeholder="Janvier 2025"></div>
          </div>
          <div class="form-group"><label>Description</label><textarea id="exp-description" placeholder="Decrivez votre experience..."></textarea></div>
          <button class="btn btn-primary btn-block" onclick="addExperience()"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>Ajouter l'experience</button>
        </div>
      </div>

      <div id="tab-contact" class="tab-content">
        <div class="section-card">
          <h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z"/></svg>Informations de contact</h2>
          <div class="form-group"><label>Email</label><input type="email" id="contact-email" placeholder="votre@email.com"></div>
          <div class="form-group"><label>Telephone</label><input type="tel" id="contact-phone" placeholder="06 XX XX XX XX"></div>
          <div class="form-group"><label>LinkedIn</label><input type="text" id="contact-linkedin" placeholder="linkedin.com/in/votreprofil"></div>
        </div>
      </div>

      <div id="tab-stats" class="tab-content">
        <div class="section-card">
          <h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>Statistiques</h2>
          <div class="stats-grid">
            <div class="stat-card"><div class="stat-value" id="total-visits">-</div><div class="stat-label">Visites totales</div></div>
            <div class="stat-card alt"><div class="stat-value" id="today-visits">-</div><div class="stat-label">Aujourd'hui</div></div>
          </div>
          <button class="btn btn-primary" onclick="loadStats()"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>Actualiser</button>
        </div>
      </div>

      <div id="tab-logins" class="tab-content">
        <div class="section-card">
          <h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/></svg>Historique des connexions</h2>
          <div id="logins-list" style="max-height:400px;overflow-y:auto"><p style="color:#9ca3af">Chargement...</p></div>
          <button class="btn btn-primary" onclick="loadLogins()" style="margin-top:20px"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>Actualiser</button>
        </div>
      </div>

      <button class="btn btn-success btn-block" onclick="saveAll()" style="margin-top:24px;padding:18px 32px;font-size:1.1rem">
        <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
        Sauvegarder toutes les modifications
      </button>
    </main>
  </div>

  <div class="toast" id="toast"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg><span id="toast-msg"></span></div>

  <div class="modal-overlay" id="editModal">
    <div class="modal">
      <h3 id="modalTitle">Modifier</h3>
      <div id="modalContent"></div>
      <div class="modal-actions">
        <button class="btn" style="background:#e5e7eb;color:#374151" onclick="closeModal()">Annuler</button>
        <button class="btn btn-primary" onclick="confirmEdit()">Enregistrer</button>
      </div>
    </div>
  </div>

  <script>
    let siteData={skills:[],interests:[],experiences:[],contact:{email:'',phone:'',linkedin:''}};

    function showToast(msg,type='success'){const t=document.getElementById('toast'),m=document.getElementById('toast-msg');m.textContent=msg;t.className='toast '+type+' show';setTimeout(()=>t.classList.remove('show'),4000);}

    async function loadData(){try{const r=await fetch('/.netlify/functions/api/admin/data',{credentials:'include'});if(r.ok){siteData=await r.json();renderAll();}}catch(e){console.error(e);}}
    function renderAll(){renderSkills();renderInterests();renderExperiences();renderContact();}
    function renderSkills(){const l=document.getElementById('skills-list');l.innerHTML=siteData.skills.map((s,i)=>'<li><span>'+s+'</span><div class="item-actions"><button class="btn btn-primary btn-sm" onclick="editSkill('+i+')">Modifier</button><button class="btn btn-danger btn-sm" onclick="deleteSkill('+i+')">Supprimer</button></div></li>').join('');}
    function renderInterests(){const l=document.getElementById('interests-list');l.innerHTML=siteData.interests.map((s,i)=>'<li><span>'+s+'</span><div class="item-actions"><button class="btn btn-primary btn-sm" onclick="editInterest('+i+')">Modifier</button><button class="btn btn-danger btn-sm" onclick="deleteInterest('+i+')">Supprimer</button></div></li>').join('');}
    function renderExperiences(){const l=document.getElementById('experience-list');l.innerHTML=siteData.experiences.map((e,i)=>'<li><span><strong>'+e.title+'</strong> - '+e.company+'</span><div class="item-actions"><button class="btn btn-primary btn-sm" onclick="editExperience('+i+')">Modifier</button><button class="btn btn-danger btn-sm" onclick="deleteExperience('+i+')">Supprimer</button></div></li>').join('');}
    function renderContact(){document.getElementById('contact-email').value=siteData.contact.email||'';document.getElementById('contact-phone').value=siteData.contact.phone||'';document.getElementById('contact-linkedin').value=siteData.contact.linkedin||'';}

    function addSkill(){const i=document.getElementById('new-skill');if(i.value.trim()){siteData.skills.push(i.value.trim());i.value='';renderSkills();showToast('Competence ajoutee');}}
    function addInterest(){const i=document.getElementById('new-interest');if(i.value.trim()){siteData.interests.push(i.value.trim());i.value='';renderInterests();showToast('Centre d\\'interet ajoute');}}
    function addExperience(){const t=document.getElementById('exp-title').value.trim(),c=document.getElementById('exp-company').value.trim(),g=document.getElementById('exp-tag').value.trim(),d=document.getElementById('exp-date').value.trim(),desc=document.getElementById('exp-description').value.trim();if(t&&c){siteData.experiences.push({title:t,company:c,tag:g,date:d,description:desc});['exp-title','exp-company','exp-tag','exp-date','exp-description'].forEach(id=>document.getElementById(id).value='');renderExperiences();showToast('Experience ajoutee');}}

    function deleteSkill(i){siteData.skills.splice(i,1);renderSkills();showToast('Competence supprimee');}
    function deleteInterest(i){siteData.interests.splice(i,1);renderInterests();showToast('Centre d\\'interet supprime');}
    function deleteExperience(i){siteData.experiences.splice(i,1);renderExperiences();showToast('Experience supprimee');}

    let currentEditType=null,currentEditIndex=null;
    function openModal(t,c){document.getElementById('modalTitle').textContent=t;document.getElementById('modalContent').innerHTML=c;document.getElementById('editModal').classList.add('active');}
    function closeModal(){document.getElementById('editModal').classList.remove('active');currentEditType=null;currentEditIndex=null;}
    function editSkill(i){currentEditType='skill';currentEditIndex=i;openModal('Modifier la competence','<div class="form-group"><label>Competence</label><input type="text" id="edit-value" value="'+siteData.skills[i]+'"></div>');}
    function editInterest(i){currentEditType='interest';currentEditIndex=i;openModal("Modifier le centre d'interet",'<div class="form-group"><label>Centre d\\'interet</label><input type="text" id="edit-value" value="'+siteData.interests[i]+'"></div>');}
    function editExperience(i){currentEditType='experience';currentEditIndex=i;const e=siteData.experiences[i];openModal("Modifier l'experience",'<div class="form-group"><label>Titre</label><input type="text" id="edit-title" value="'+(e.title||'')+'"></div><div class="form-group"><label>Entreprise</label><input type="text" id="edit-company" value="'+(e.company||'')+'"></div><div class="form-group"><label>Tag</label><input type="text" id="edit-tag" value="'+(e.tag||'')+'"></div><div class="form-group"><label>Date</label><input type="text" id="edit-date" value="'+(e.date||'')+'"></div><div class="form-group"><label>Description</label><textarea id="edit-desc">'+(e.description||'')+'</textarea></div>');}
    function confirmEdit(){if(currentEditType==='skill'){const v=document.getElementById('edit-value').value.trim();if(v){siteData.skills[currentEditIndex]=v;renderSkills();showToast('Modifie !');}}else if(currentEditType==='interest'){const v=document.getElementById('edit-value').value.trim();if(v){siteData.interests[currentEditIndex]=v;renderInterests();showToast('Modifie !');}}else if(currentEditType==='experience'){const t=document.getElementById('edit-title').value.trim(),c=document.getElementById('edit-company').value.trim();if(t&&c){siteData.experiences[currentEditIndex]={title:t,company:c,tag:document.getElementById('edit-tag').value.trim(),date:document.getElementById('edit-date').value.trim(),description:document.getElementById('edit-desc').value.trim()};renderExperiences();showToast('Modifie !');}}closeModal();}
    document.getElementById('editModal').addEventListener('click',function(e){if(e.target===this)closeModal();});

    async function saveAll(){
      siteData.contact.email=document.getElementById('contact-email').value.trim();
      siteData.contact.phone=document.getElementById('contact-phone').value.trim();
      siteData.contact.linkedin=document.getElementById('contact-linkedin').value.trim();
      try{
        const r=await fetch('/.netlify/functions/api/admin/save',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify(siteData)});
        if(r.ok){showToast('Modifications sauvegardees avec succes !','success');}
        else{const err=await r.text();console.error('Save error:',err);showToast('Erreur: '+r.status,'error');}
      }catch(e){console.error(e);showToast('Erreur reseau','error');}
    }

    function showTab(t){document.querySelectorAll('.tab-content').forEach(e=>e.classList.remove('active'));document.querySelectorAll('.menu-item').forEach(e=>e.classList.remove('active'));document.getElementById('tab-'+t).classList.add('active');if(event&&event.target)event.target.closest('.menu-item').classList.add('active');}

    async function loadStats(){try{const r=await fetch('/.netlify/functions/api/admin/stats',{credentials:'include'});if(r.ok){const s=await r.json();document.getElementById('total-visits').textContent=s.visits||0;document.getElementById('visits-badge').textContent=s.visits||0;const today=new Date().toISOString().split('T')[0];const td=s.lastVisits?.find(v=>v.date===today);document.getElementById('today-visits').textContent=td?.count||0;}}catch(e){console.error(e);}}

    async function loadLogins(){const c=document.getElementById('logins-list');c.innerHTML='<p style="color:#9ca3af">Chargement...</p>';try{const r=await fetch('/.netlify/functions/api/admin/logins',{credentials:'include'});if(r.ok){const l=await r.json();document.getElementById('logins-badge').textContent=l.length;if(l.length===0){c.innerHTML='<p style="color:#9ca3af">Aucune connexion enregistree.</p>';}else{c.innerHTML='<ul class="item-list">'+l.map(x=>'<li style="flex-direction:column;align-items:flex-start;gap:8px"><div style="display:flex;align-items:center;gap:12px;width:100%">'+(x.photo?'<img src="'+x.photo+'" style="width:40px;height:40px;border-radius:50%;border:2px solid #e5e7eb">':'<div style="width:40px;height:40px;border-radius:50%;background:#e5e7eb;display:flex;align-items:center;justify-content:center;color:#9ca3af;font-size:1.2rem">?</div>')+'<div style="flex:1"><strong style="color:#1f2937">'+(x.name||'Utilisateur')+'</strong><div style="color:#6b7280;font-size:0.85rem">'+(x.email||'')+'</div></div><small style="color:#9ca3af">'+(x.date?new Date(x.date).toLocaleString('fr-FR'):'')+'</small></div></li>').join('')+'</ul>';}}}catch(e){console.error(e);c.innerHTML='<p style="color:#ef4444">Erreur reseau</p>';}}

    loadData();loadStats();loadLogins();
  </script>
</body>
</html>`);
});

// 404 JSON pour routes inconnues (évite HTML "Cannot POST")
app.use((req, res) => {
  res.status(404).json({ error: "not_found", path: req.path, method: req.method });
});

// Export Netlify handler
export const handler = serverless(app);

