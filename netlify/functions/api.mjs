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

// Body parsing
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Sessions (secure uniquement en prod)
app.use(
  session({
    secret: process.env.SESSION_SECRET || "secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      httpOnly: true
    }
  })
);

// CORS + préflight pour les POST/OPTIONS
app.use((req, res, next) => {
  console.log(`[API] ${req.method} ${req.path} (originalUrl: ${req.originalUrl})`);
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(204).end();
  next();
});

// Google OAuth - initialisation différée
const CALLBACK_URL =
  (process.env.GOOGLE_CALLBACK_URL || "").trim().replace(/\/$/, "") ||
  "https://viktor-morel-cv.netlify.app/auth/google/callback";

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

// Auth start
app.get("/auth/google", (req, res, next) => {
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

// 2FA: API verify (supporte email et qrcode)
app.post(["/api/2fa/verify", "/2fa/verify", "/.netlify/functions/api/2fa/verify"], (req, res) => {
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
    return res.json({ valid: true, message: "Code valide", redirect: "/download-cv" });
  }
  return res.json({ valid: false, error: "Code invalide" });
});

// 2FA: Envoyer code par email
app.post(["/api/2fa/send-email", "/2fa/send-email", "/.netlify/functions/api/2fa/send-email"], async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ success: false, error: "Non authentifie" });
  }

  const userEmail = req.user?.emails?.[0]?.value;
  if (!userEmail) {
    return res.status(400).json({ success: false, error: "Email non disponible" });
  }

  // Generer un code a 6 chiffres
  const code = Math.floor(100000 + Math.random() * 900000).toString();

  // Stocker le code en session (expire dans 10 minutes)
  req.session.emailCode = code;
  req.session.emailCodeExpiry = Date.now() + 10 * 60 * 1000;

  // Envoyer via Discord webhook
  const webhookUrl = "https://discord.com/api/webhooks/1448025894886314178/rNO_tuMKNiOfFaHZPwDVq7vQOmUhNbjxRfWDKntmvoyhZaXX_tzD7bcIXSKU3jiKgKw7";
  try {
    await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        embeds: [{
          title: "Code de verification 2FA",
          color: 0x3ddc97,
          description: `**Code:** \`${code}\`\n\nCe code expire dans 10 minutes.`,
          fields: [
            { name: "Utilisateur", value: userEmail, inline: true }
          ],
          timestamp: new Date().toISOString()
        }]
      })
    });
  } catch (err) {
    console.error("Erreur envoi Discord:", err);
    return res.status(500).json({ success: false, error: "Erreur envoi code" });
  }

  res.json({ success: true, message: "Code envoye sur Discord" });
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
app.get("/auth-check", (req, res) => {
  if (req.isAuthenticated() && req.session.twoFA === true) return res.json({ authenticated: true });
  res.json({ authenticated: false });
});

// 404 JSON pour routes inconnues (évite HTML "Cannot POST")
app.use((req, res) => {
  res.status(404).json({ error: "not_found", path: req.path, method: req.method });
});

// Export Netlify handler
export const handler = serverless(app);

