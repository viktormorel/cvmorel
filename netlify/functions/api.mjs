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

// Console admin securisee - Redirection vers admin.html
app.get(["/admin-console", "/secure/admin", "/.netlify/functions/api/admin-console"], (req, res) => {
  if (!req.isAuthenticated() || req.session.twoFA !== true || !isAdmin(req)) {
    return res.redirect("/");
  }
  // Rediriger vers la page admin.html avec le beau menu
  res.redirect("/admin.html");
});

// 404 JSON pour routes inconnues (évite HTML "Cannot POST")
app.use((req, res) => {
  res.status(404).json({ error: "not_found", path: req.path, method: req.method });
});

// Export Netlify handler
export const handler = serverless(app);

