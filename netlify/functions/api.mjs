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

// Helper pour obtenir le store Netlify Blobs
function getBlobStore() {
  // En production sur Netlify, utiliser les variables d'environnement injectées
  const siteID = process.env.SITE_ID;
  const token = process.env.NETLIFY_ACCESS_TOKEN;

  if (siteID && token) {
    return getStore({ name: "cv-data", siteID, token });
  }
  // Fallback pour le contexte de fonction native (si disponible)
  return getStore("cv-data");
}

// Netlify Blobs pour persistance
async function loadSiteData() {
  try {
    const store = getBlobStore();
    let data;
    try {
      data = await store.get("site-data", { type: "json" });
    } catch (e) {
      data = null;
    }
    return data || DEFAULT_DATA;
  } catch (err) {
    console.error("Erreur lecture site-data:", err.message);
    return DEFAULT_DATA;
  }
}

async function saveSiteData(data) {
  try {
    const store = getBlobStore();
    await store.setJSON("site-data", data);
  } catch (err) {
    console.error("Erreur ecriture site-data:", err.message);
    throw err;
  }
}

// Gestion des connexions avec Netlify Blobs
async function loadLogins() {
  try {
    const store = getBlobStore();
    let logins;
    try {
      logins = await store.get("logins", { type: "json" });
    } catch (e) {
      logins = null;
    }
    return logins || [];
  } catch (err) {
    console.error("Erreur lecture logins:", err.message);
    return [];
  }
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
      console.log("Login already recorded recently for:", userEmail);
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

    const store = getBlobStore();
    await store.setJSON("logins", logins);
    console.log("Login saved for:", user.displayName);
  } catch (err) {
    console.error("Erreur sauvegarde login:", err.message);
  }
}

// Compteur de visites
async function incrementVisits() {
  try {
    const store = getBlobStore();
    let stats;
    try {
      stats = await store.get("stats", { type: "json" });
    } catch (e) {
      console.log("Stats not found, creating new");
      stats = null;
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

    await store.setJSON("stats", stats);
    console.log("Stats saved:", stats);
    return stats;
  } catch (err) {
    console.error("Erreur compteur visites:", err.message, err.stack);
    return { visits: 0, lastVisits: [] };
  }
}

async function getStats() {
  try {
    const store = getBlobStore();
    let stats;
    try {
      stats = await store.get("stats", { type: "json" });
    } catch (e) {
      stats = null;
    }
    return stats || { visits: 0, lastVisits: [] };
  } catch (err) {
    console.error("Erreur lecture stats:", err.message);
    return { visits: 0, lastVisits: [] };
  }
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
    await saveSiteData(req.body);
    res.json({ success: true });
  } catch (err) {
    console.error("Erreur sauvegarde:", err);
    res.status(500).json({ error: "Erreur sauvegarde" });
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

// Console admin securisee - HTML complet avec menu sidebar
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
  <link rel="stylesheet" href="/styles.css">
  <style>
    body{-webkit-user-select:none;user-select:none}
    .navbar{position:fixed;top:0;left:0;right:0;background:linear-gradient(135deg,#6a11cb 0%,#2575fc 100%);z-index:999;display:flex;justify-content:space-between;align-items:center;padding:0 20px;box-shadow:0 4px 20px rgba(0,0,0,0.2);height:60px}
    .navbar ul{margin:0;padding:0;list-style:none;display:flex;gap:12px}
    .navbar a{color:#fff;text-decoration:none;padding:8px 12px;border-radius:8px;font-size:0.9rem}
    .navbar a:hover{background:rgba(255,255,255,0.15)}
    .admin-layout{display:flex;min-height:100vh;padding-top:60px}
    .sidebar{width:280px;background:rgba(255,255,255,0.98);border-radius:0 24px 24px 0;padding:24px 16px;box-shadow:4px 0 30px rgba(0,0,0,0.1);position:fixed;left:0;top:60px;bottom:0;overflow-y:auto;z-index:100}
    .sidebar-header{text-align:center;padding-bottom:20px;border-bottom:2px solid #eef2ff;margin-bottom:20px}
    .sidebar-header h2{color:#1f2430;font-size:1.3rem;margin:0 0 4px}
    .sidebar-header p{color:#5a6376;font-size:0.85rem;margin:0}
    .menu-section{margin-bottom:24px}
    .menu-section-title{color:#5a6376;font-size:0.75rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;padding-left:12px}
    .menu-item{display:flex;align-items:center;gap:12px;padding:14px 16px;border-radius:12px;cursor:pointer;transition:all 0.25s;margin-bottom:6px;color:#5a6376;font-weight:500;border:none;background:transparent;width:100%;text-align:left;font-size:0.95rem;text-decoration:none}
    .menu-item:hover{background:linear-gradient(135deg,#f8f9fc 0%,#eef2ff 100%);color:#6a11cb;transform:translateX(4px)}
    .menu-item.active{background:linear-gradient(135deg,#6a11cb 0%,#2575fc 100%);color:white;box-shadow:0 4px 15px rgba(106,17,203,0.3)}
    .menu-item svg{width:20px;height:20px;flex-shrink:0}
    .menu-item .badge{margin-left:auto;background:#ff4757;color:white;font-size:0.7rem;padding:2px 8px;border-radius:10px}
    .menu-item.active .badge{background:rgba(255,255,255,0.3)}
    .main-content{flex:1;margin-left:280px;padding:30px}
    .admin-container{padding-top:20px;max-width:100%}
    .admin-section{background:rgba(255,255,255,0.98);border-radius:20px;padding:28px;margin-bottom:24px;box-shadow:0 10px 40px rgba(0,0,0,0.12);border:1px solid rgba(255,255,255,0.5)}
    .admin-section h2{color:#1f2430;margin:0 0 24px;font-size:1.4rem;border-bottom:3px solid transparent;border-image:linear-gradient(90deg,#6a11cb,#2575fc) 1;padding-bottom:12px}
    .form-group{margin-bottom:16px}
    .form-group label{display:block;color:#5a6376;margin-bottom:6px;font-weight:600}
    .form-group input,.form-group textarea{width:100%;padding:12px;border:1px solid #dfe3eb;border-radius:8px;font-size:1rem;color:#1f2430;box-sizing:border-box}
    .form-group textarea{min-height:100px;resize:vertical}
    .form-group input:focus,.form-group textarea:focus{outline:none;border-color:#6a11cb;box-shadow:0 0 0 3px rgba(106,17,203,0.2)}
    .item-list{list-style:none;padding:0;margin:0 0 20px}
    .item-list li{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;background:linear-gradient(135deg,#f8f9fc 0%,#eef2ff 100%);border-radius:12px;margin-bottom:10px;border:1px solid rgba(106,17,203,0.1);transition:all 0.25s}
    .item-list li:hover{transform:translateX(4px);box-shadow:0 4px 15px rgba(106,17,203,0.1)}
    .item-list li span{color:#1f2430;font-weight:500}
    .btn-small{padding:8px 14px;border-radius:8px;border:none;cursor:pointer;font-size:0.85rem;transition:all 0.25s;font-weight:500}
    .btn-small:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,0.15)}
    .btn-edit{background:linear-gradient(135deg,#2575fc,#6a11cb);color:white}
    .btn-delete{background:linear-gradient(135deg,#ff4757,#ff6b81);color:white;margin-left:8px}
    .btn-add{background:linear-gradient(135deg,#6a11cb,#2575fc);color:white;padding:14px 24px;border:none;border-radius:12px;cursor:pointer;font-size:1rem;font-weight:600;width:100%;transition:all 0.3s;display:flex;align-items:center;justify-content:center;gap:8px}
    .btn-add:hover{transform:translateY(-3px);box-shadow:0 8px 25px rgba(106,17,203,0.4)}
    .btn-save{background:linear-gradient(135deg,#3ddc97,#00b894);color:white;padding:16px 32px;border:none;border-radius:14px;cursor:pointer;font-size:1.15rem;font-weight:700;width:100%;margin-top:24px;transition:all 0.3s;display:flex;align-items:center;justify-content:center;gap:10px;text-transform:uppercase}
    .btn-save:hover{transform:translateY(-3px);box-shadow:0 10px 30px rgba(61,220,151,0.4)}
    .message{padding:12px 16px;border-radius:8px;margin-bottom:20px;display:none}
    .message.success{background:#d4edda;color:#155724;display:block}
    .message.error{background:#f8d7da;color:#721c24;display:block}
    .tab-content{display:none}
    .tab-content.active{display:block}
    .modal-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);display:none;justify-content:center;align-items:center;z-index:1000}
    .modal-overlay.active{display:flex}
    .modal{background:white;border-radius:16px;padding:30px;max-width:500px;width:90%;max-height:80vh;overflow-y:auto;box-shadow:0 20px 60px rgba(0,0,0,0.3)}
    .modal h3{color:#1f2430;margin:0 0 20px;font-size:1.4rem}
    .modal-actions{display:flex;gap:10px;margin-top:20px}
    .btn-cancel{background:#e0e0e0;color:#333;padding:10px 20px;border:none;border-radius:8px;cursor:pointer;flex:1}
    .btn-confirm{background:linear-gradient(135deg,#6a11cb,#2575fc);color:white;padding:10px 20px;border:none;border-radius:8px;cursor:pointer;flex:1}
    @media(max-width:900px){.sidebar{width:100%;position:relative;top:0;border-radius:0;padding:16px}.main-content{margin-left:0}.admin-layout{flex-direction:column}}
  </style>
</head>
<body class="centered-layout" oncontextmenu="return false">
  <nav class="navbar">
    <ul>
      <li><a href="/">Accueil</a></li>
      <li><a href="/.netlify/functions/api/download-cv">Telechargement</a></li>
    </ul>
    <div><a href="/" style="color:white;text-decoration:none;padding:8px 16px;background:rgba(255,255,255,0.2);border-radius:8px;font-size:0.9rem;">← Retour au CV</a></div>
  </nav>

  <div class="admin-layout">
    <aside class="sidebar">
      <div class="sidebar-header">
        <h2>Console Admin</h2>
        <p>Gestion du CV</p>
      </div>
      <div class="menu-section">
        <div class="menu-section-title">Contenu</div>
        <button class="menu-item active" onclick="showTab('skills')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
          Competences
        </button>
        <button class="menu-item" onclick="showTab('interests')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>
          Centres d'interet
        </button>
        <button class="menu-item" onclick="showTab('experience')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/></svg>
          Experiences
        </button>
        <button class="menu-item" onclick="showTab('contact')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
          Contact
        </button>
      </div>
      <div class="menu-section">
        <div class="menu-section-title">Statistiques</div>
        <button class="menu-item" onclick="showTab('stats')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
          Visites
          <span class="badge" id="visits-badge">-</span>
        </button>
        <button class="menu-item" onclick="showTab('logins')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
          Connexions
          <span class="badge" id="logins-badge">-</span>
        </button>
      </div>
      <div class="menu-section">
        <div class="menu-section-title">Navigation</div>
        <a href="/" class="menu-item">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
          Retour au CV
        </a>
        <a href="/.netlify/functions/api/download-cv" class="menu-item">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          Telecharger CV
        </a>
      </div>
    </aside>

    <main class="main-content">
      <div class="admin-container">
        <div id="message" class="message"></div>

        <div id="tab-skills" class="tab-content active">
          <div class="admin-section">
            <h2>Gerer les Competences</h2>
            <ul class="item-list" id="skills-list"></ul>
            <div class="form-group">
              <label>Nouvelle competence</label>
              <input type="text" id="new-skill" placeholder="Ex: Python, Reseaux, etc.">
            </div>
            <button class="btn-add" onclick="addSkill()">Ajouter une competence</button>
          </div>
        </div>

        <div id="tab-interests" class="tab-content">
          <div class="admin-section">
            <h2>Gerer les Centres d'interet</h2>
            <ul class="item-list" id="interests-list"></ul>
            <div class="form-group">
              <label>Nouveau centre d'interet</label>
              <input type="text" id="new-interest" placeholder="Ex: Sport, Musique, etc.">
            </div>
            <button class="btn-add" onclick="addInterest()">Ajouter un centre d'interet</button>
          </div>
        </div>

        <div id="tab-experience" class="tab-content">
          <div class="admin-section">
            <h2>Gerer les Experiences</h2>
            <ul class="item-list" id="experience-list"></ul>
            <div class="form-group"><label>Titre du poste/stage</label><input type="text" id="exp-title" placeholder="Ex: Stage developpeur"></div>
            <div class="form-group"><label>Entreprise</label><input type="text" id="exp-company" placeholder="Ex: France Televisions"></div>
            <div class="form-group"><label>Tag/Categorie</label><input type="text" id="exp-tag" placeholder="Ex: Audiovisuel"></div>
            <div class="form-group"><label>Date</label><input type="text" id="exp-date" placeholder="Ex: Janvier 2025"></div>
            <div class="form-group"><label>Description</label><textarea id="exp-description" placeholder="Description du poste..."></textarea></div>
            <button class="btn-add" onclick="addExperience()">Ajouter une experience</button>
          </div>
        </div>

        <div id="tab-contact" class="tab-content">
          <div class="admin-section">
            <h2>Informations de Contact</h2>
            <div class="form-group"><label>Email</label><input type="email" id="contact-email" placeholder="votre@email.com"></div>
            <div class="form-group"><label>Telephone</label><input type="tel" id="contact-phone" placeholder="06.XX.XX.XX.XX"></div>
            <div class="form-group"><label>LinkedIn</label><input type="text" id="contact-linkedin" placeholder="Votre profil LinkedIn"></div>
          </div>
        </div>

        <div id="tab-stats" class="tab-content">
          <div class="admin-section">
            <h2>Statistiques de visites</h2>
            <div style="display:flex;gap:20px;flex-wrap:wrap;margin-bottom:20px;">
              <div style="flex:1;min-width:200px;text-align:center;padding:24px;background:linear-gradient(135deg,#6a11cb,#2575fc);border-radius:16px;color:white;">
                <div style="font-size:2.5rem;font-weight:700;" id="total-visits">-</div>
                <div style="font-size:0.9rem;opacity:0.9;">Visites totales</div>
              </div>
              <div style="flex:1;min-width:200px;text-align:center;padding:24px;background:linear-gradient(135deg,#2575fc,#6a11cb);border-radius:16px;color:white;">
                <div style="font-size:2.5rem;font-weight:700;" id="today-visits">-</div>
                <div style="font-size:0.9rem;opacity:0.9;">Aujourd'hui</div>
              </div>
            </div>
            <button class="btn-add" onclick="loadStats()" style="background:linear-gradient(135deg,#2575fc,#6a11cb);">Actualiser les stats</button>
          </div>
        </div>

        <div id="tab-logins" class="tab-content">
          <div class="admin-section">
            <h2>Historique des Connexions</h2>
            <p style="color:#5a6376;margin-bottom:16px;">Liste des utilisateurs connectes via Google OAuth</p>
            <div id="logins-list" style="max-height:400px;overflow-y:auto;"><p style="color:#888;">Chargement...</p></div>
            <button class="btn-add" onclick="loadLogins()" style="margin-top:16px;background:linear-gradient(135deg,#2575fc,#6a11cb);">Actualiser</button>
          </div>
        </div>

        <button class="btn-save" onclick="saveAll()">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
          Sauvegarder les modifications
        </button>
      </div>
    </main>
  </div>

  <div class="modal-overlay" id="editModal">
    <div class="modal">
      <h3 id="modalTitle">Modifier</h3>
      <div id="modalContent"></div>
      <div class="modal-actions">
        <button class="btn-cancel" onclick="closeModal()">Annuler</button>
        <button class="btn-confirm" onclick="confirmEdit()">Enregistrer</button>
      </div>
    </div>
  </div>

  <script>
    let siteData={skills:[],interests:[],experiences:[],contact:{email:'',phone:'',linkedin:''}};
    async function loadData(){try{const r=await fetch('/.netlify/functions/api/admin/data',{credentials:'include'});if(r.ok){siteData=await r.json();renderAll();}}catch(e){console.error(e);}}
    function renderAll(){renderSkills();renderInterests();renderExperiences();renderContact();}
    function renderSkills(){const l=document.getElementById('skills-list');l.innerHTML=siteData.skills.map((s,i)=>'<li><span>'+s+'</span><div><button class="btn-small btn-edit" onclick="editSkill('+i+')">Modifier</button><button class="btn-small btn-delete" onclick="deleteSkill('+i+')">Supprimer</button></div></li>').join('');}
    function renderInterests(){const l=document.getElementById('interests-list');l.innerHTML=siteData.interests.map((s,i)=>'<li><span>'+s+'</span><div><button class="btn-small btn-edit" onclick="editInterest('+i+')">Modifier</button><button class="btn-small btn-delete" onclick="deleteInterest('+i+')">Supprimer</button></div></li>').join('');}
    function renderExperiences(){const l=document.getElementById('experience-list');l.innerHTML=siteData.experiences.map((e,i)=>'<li><span><strong>'+e.title+'</strong> - '+e.company+'</span><div><button class="btn-small btn-edit" onclick="editExperience('+i+')">Modifier</button><button class="btn-small btn-delete" onclick="deleteExperience('+i+')">Supprimer</button></div></li>').join('');}
    function renderContact(){document.getElementById('contact-email').value=siteData.contact.email||'';document.getElementById('contact-phone').value=siteData.contact.phone||'';document.getElementById('contact-linkedin').value=siteData.contact.linkedin||'';}
    function addSkill(){const i=document.getElementById('new-skill');if(i.value.trim()){siteData.skills.push(i.value.trim());i.value='';renderSkills();}}
    function addInterest(){const i=document.getElementById('new-interest');if(i.value.trim()){siteData.interests.push(i.value.trim());i.value='';renderInterests();}}
    function addExperience(){const t=document.getElementById('exp-title').value.trim(),c=document.getElementById('exp-company').value.trim(),g=document.getElementById('exp-tag').value.trim(),d=document.getElementById('exp-date').value.trim(),desc=document.getElementById('exp-description').value.trim();if(t&&c){siteData.experiences.push({title:t,company:c,tag:g,date:d,description:desc});['exp-title','exp-company','exp-tag','exp-date','exp-description'].forEach(id=>document.getElementById(id).value='');renderExperiences();}}
    function deleteSkill(i){siteData.skills.splice(i,1);renderSkills();}
    function deleteInterest(i){siteData.interests.splice(i,1);renderInterests();}
    function deleteExperience(i){siteData.experiences.splice(i,1);renderExperiences();}
    let currentEditType=null,currentEditIndex=null;
    function openModal(t,c){document.getElementById('modalTitle').textContent=t;document.getElementById('modalContent').innerHTML=c;document.getElementById('editModal').classList.add('active');}
    function closeModal(){document.getElementById('editModal').classList.remove('active');currentEditType=null;currentEditIndex=null;}
    function editSkill(i){currentEditType='skill';currentEditIndex=i;openModal('Modifier la competence','<div class="form-group"><label>Competence</label><input type="text" id="edit-value" value="'+siteData.skills[i]+'"></div>');}
    function editInterest(i){currentEditType='interest';currentEditIndex=i;openModal("Modifier le centre d'interet",'<div class="form-group"><label>Centre d\\'interet</label><input type="text" id="edit-value" value="'+siteData.interests[i]+'"></div>');}
    function editExperience(i){currentEditType='experience';currentEditIndex=i;const e=siteData.experiences[i];openModal("Modifier l'experience",'<div class="form-group"><label>Titre</label><input type="text" id="edit-title" value="'+(e.title||'')+'"></div><div class="form-group"><label>Entreprise</label><input type="text" id="edit-company" value="'+(e.company||'')+'"></div><div class="form-group"><label>Tag</label><input type="text" id="edit-tag" value="'+(e.tag||'')+'"></div><div class="form-group"><label>Date</label><input type="text" id="edit-date" value="'+(e.date||'')+'"></div><div class="form-group"><label>Description</label><textarea id="edit-desc">'+(e.description||'')+'</textarea></div>');}
    function confirmEdit(){if(currentEditType==='skill'){const v=document.getElementById('edit-value').value.trim();if(v){siteData.skills[currentEditIndex]=v;renderSkills();}}else if(currentEditType==='interest'){const v=document.getElementById('edit-value').value.trim();if(v){siteData.interests[currentEditIndex]=v;renderInterests();}}else if(currentEditType==='experience'){const t=document.getElementById('edit-title').value.trim(),c=document.getElementById('edit-company').value.trim();if(t&&c){siteData.experiences[currentEditIndex]={title:t,company:c,tag:document.getElementById('edit-tag').value.trim(),date:document.getElementById('edit-date').value.trim(),description:document.getElementById('edit-desc').value.trim()};renderExperiences();}}closeModal();}
    document.getElementById('editModal').addEventListener('click',function(e){if(e.target===this)closeModal();});
    async function saveAll(){siteData.contact.email=document.getElementById('contact-email').value.trim();siteData.contact.phone=document.getElementById('contact-phone').value.trim();siteData.contact.linkedin=document.getElementById('contact-linkedin').value.trim();try{const r=await fetch('/.netlify/functions/api/admin/save',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify(siteData)});const m=document.getElementById('message');if(r.ok){m.textContent='Modifications sauvegardees !';m.className='message success';}else{m.textContent='Erreur lors de la sauvegarde.';m.className='message error';}setTimeout(()=>{m.className='message';},3000);}catch(e){console.error(e);}}
    function showTab(t){document.querySelectorAll('.tab-content').forEach(e=>e.classList.remove('active'));document.querySelectorAll('.menu-item').forEach(e=>e.classList.remove('active'));document.getElementById('tab-'+t).classList.add('active');if(event&&event.target)event.target.closest('.menu-item').classList.add('active');}
    async function loadStats(){try{const r=await fetch('/.netlify/functions/api/admin/stats',{credentials:'include'});if(r.ok){const s=await r.json();document.getElementById('total-visits').textContent=s.visits||0;document.getElementById('visits-badge').textContent=s.visits||0;const today=new Date().toISOString().split('T')[0];const td=s.lastVisits?.find(v=>v.date===today);document.getElementById('today-visits').textContent=td?.count||0;}}catch(e){console.error(e);}}
    async function loadLogins(){const c=document.getElementById('logins-list');c.innerHTML='<p style="color:#888;">Chargement...</p>';try{const r=await fetch('/.netlify/functions/api/admin/logins',{credentials:'include'});if(r.ok){const l=await r.json();document.getElementById('logins-badge').textContent=l.length;if(l.length===0){c.innerHTML='<p style="color:#888;">Aucune connexion.</p>';}else{c.innerHTML='<ul class="item-list">'+l.map(x=>'<li style="flex-direction:column;align-items:flex-start;gap:4px;padding:12px;"><div style="display:flex;align-items:center;gap:10px;width:100%;flex-wrap:wrap;">'+(x.photo?'<img src="'+x.photo+'" style="width:36px;height:36px;border-radius:50%;">':'')+'<div style="flex:1;min-width:200px;"><strong style="color:#1f2430;">'+(x.name||'Utilisateur')+'</strong><span style="color:#5a6376;font-size:0.9rem;margin-left:8px;">'+(x.email||'')+'</span></div><small style="color:#888;white-space:nowrap;">'+(x.date?new Date(x.date).toLocaleString('fr-FR'):'')+'</small></div></li>').join('')+'</ul>';}}}catch(e){console.error(e);c.innerHTML='<p style="color:#ff4757;">Erreur reseau.</p>';}}
    loadData();loadStats();loadLogins();
    document.addEventListener('keydown',e=>{if(e.key==='F12'||(e.ctrlKey&&e.shiftKey))e.preventDefault();});
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

