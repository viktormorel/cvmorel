// netlify/functions/api.mjs
import serverless from "serverless-http";
import express from "express";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import speakeasy from "speakeasy";
import session from "express-session";
import path from "path";
import fs from "fs";
import QRCode from "qrcode";

// Fichier de données persistant (Lambda: /tmp)
const DATA_FILE = path.join("/tmp", "site-data.json");
const LOGINS_FILE = path.join("/tmp", "logins.json");

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

function loadSiteData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    }
  } catch (err) {
    console.error("Erreur lecture site-data.json:", err);
  }
  return DEFAULT_DATA;
}

function saveSiteData(data) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), "utf8");
  } catch (err) {
    console.error("Erreur écriture site-data.json:", err);
    throw err;
  }
}

// Gestion des connexions
function loadLogins() {
  try {
    if (fs.existsSync(LOGINS_FILE)) {
      return JSON.parse(fs.readFileSync(LOGINS_FILE, "utf8"));
    }
  } catch (err) {
    console.error("Erreur lecture logins.json:", err);
  }
  return [];
}

function saveLogin(user) {
  try {
    const logins = loadLogins();
    logins.unshift({
      name: user.displayName || "",
      email: user.emails?.[0]?.value || "",
      photo: user.photos?.[0]?.value || "",
      date: new Date().toISOString()
    });
    // Garder max 100 connexions
    if (logins.length > 100) logins.length = 100;
    fs.writeFileSync(LOGINS_FILE, JSON.stringify(logins, null, 2), "utf8");
  } catch (err) {
    console.error("Erreur sauvegarde login:", err);
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
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  if (!webhookUrl) return;

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
  "https://viktorvahemorelcv.netlify.app/auth/google/callback";

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
  passport.authenticate("google", (err, user) => {
    if (err) {
      console.error("OAuth error:", err);
      return res.status(500).send("Erreur OAuth");
    }
    if (!user) return res.redirect("/");
    req.logIn(user, (loginErr) => {
      if (loginErr) {
        console.error("Erreur de connexion:", loginErr);
        return res.status(500).send("Erreur de connexion.");
      }
      // Enregistrer la connexion et notifier Discord
      saveLogin(user);
      notifyDiscord(user);

      // Si admin, bypass 2FA et accès direct
      const userEmail = user.emails?.[0]?.value || "";
      const adminEmail = process.env.ADMIN_EMAIL || "vikvahe@gmail.com";
      if (userEmail === adminEmail) {
        req.session.twoFA = true;
        return res.redirect("/download.html");
      }

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

  // Envoyer via Discord webhook (pour l'instant)
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  if (webhookUrl) {
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
    }
  }

  // TODO: Integrer un vrai service d'email (SendGrid, Mailgun, etc.)
  // Pour l'instant, on simule l'envoi - le code est envoye sur Discord

  res.json({ success: true, message: "Code envoye" });
});

// Info utilisateur (pour afficher l'email)
app.get(["/api/user-info", "/user-info", "/.netlify/functions/api/user-info"], (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Non authentifie" });
  }
  res.json({
    email: req.user?.emails?.[0]?.value || "",
    name: req.user?.displayName || ""
  });
});

// Admin
app.get(["/api/admin/check", "/admin/check", "/.netlify/functions/api/admin/check"], ensureAuthenticated, (req, res) => res.json({ isAdmin: isAdmin(req) }));
app.get(["/api/admin/check-login", "/admin/check-login", "/.netlify/functions/api/admin/check-login"], (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ isAdmin: false });
  res.json({ isAdmin: isAdmin(req) });
});
app.get(["/api/admin/data", "/admin/data", "/.netlify/functions/api/admin/data"], ensureAdmin, (req, res) => res.json(loadSiteData()));
app.post(["/api/admin/save", "/admin/save", "/.netlify/functions/api/admin/save"], ensureAdmin, (req, res) => {
  try {
    saveSiteData(req.body);
    res.json({ success: true });
  } catch (err) {
    console.error("Erreur sauvegarde:", err);
    res.status(500).json({ error: "Erreur sauvegarde" });
  }
});

// Admin: historique des connexions
app.get(["/api/admin/logins", "/admin/logins", "/.netlify/functions/api/admin/logins"], ensureAdmin, (req, res) => {
  res.json(loadLogins());
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

