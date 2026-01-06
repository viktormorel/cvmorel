// netlify/functions/api.js
import serverless from "serverless-http";
import express from "express";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import speakeasy from "speakeasy";
import session from "express-session";
import path from "path";
import fs from "fs";
import QRCode from "qrcode";

const DATA_FILE = path.join("/tmp", "site-data.json");

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
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), "utf8");
}

function isAdmin(req) {
  if (!req.user || !req.user.emails || req.user.emails.length === 0) return false;
  const userEmail = req.user.emails[0].value;
  const adminEmail = process.env.ADMIN_EMAIL || "vikvahe@gmail.com";
  return userEmail === adminEmail;
}

function ensureAdmin(req, res, next) {
  if (req.isAuthenticated() && req.session.twoFA === true && isAdmin(req)) {
    return next();
  }
  res.status(403).json({ error: "Acces refuse - Admin uniquement" });
}

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated() && req.session.twoFA === true) return next();
  res.redirect("/auth/google");
}

const app = express();
app.set("trust proxy", 1);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "secret-key",
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: true,
      sameSite: "lax"
    }
  })
);

const CALLBACK_URL =
  process.env.GOOGLE_CALLBACK_URL ||
  "https://viktor-vahe-morel-cv.netlify.app/.netlify/functions/api/auth/google/callback";

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

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  next();
});

// Routes
app.get("/health", (req, res) => res.json({ status: "ok" }));

app.get(["/auth/google", "/.netlify/functions/api/auth/google"], passport.authenticate("google", { scope: ["profile", "email"] }));

app.get(["/auth/google/callback", "/.netlify/functions/api/auth/google/callback"], (req, res, next) => {
  passport.authenticate("google", (err, user) => {
    if (err) {
      console.error("OAuth error:", err);
      return res.status(500).send("Erreur OAuth");
    }
    if (!user) return res.redirect("/");
    req.logIn(user, (loginErr) => {
      if (loginErr) return res.status(500).send("Erreur de connexion.");
      res.redirect("/login-2fa.html");
    });
  })(req, res, next);
});

// 2FA Verify (form)
app.post("/verify-2fa", (req, res) => {
  const secret = req.session.twoFASecret || process.env.TWOFA_SECRET;
  if (!secret) return res.status(400).send("<h2>Erreur serveur : secret 2FA manquant.</h2>");
  const verified = speakeasy.totp.verify({
    secret,
    encoding: "base32",
    token: req.body.token,
    window: 1
  });
  if (verified) {
    req.session.twoFA = true;
    return res.redirect("/admin.html");
  }
  res.send("<h2>Code invalide, réessaie.</h2><a href='/login-2fa.html'>Retour</a>");
});

// 2FA Generate (API)
app.post("/api/2fa/generate", (req, res) => {
  try {
    const secret = speakeasy.generateSecret({ length: 20, name: "ViktorMorel" });
    req.session.twoFASecret = secret.base32;
    QRCode.toDataURL(secret.otpauth_url)
      .then((dataUrl) => res.json({ secret: secret.base32, qrCode: dataUrl }))
      .catch(() => res.status(500).json({ error: "QR generation failed" }));
  } catch {
    res.status(500).json({ error: "2FA generate failed" });
  }
});

// 2FA Verify (API)
app.post("/api/2fa/verify", (req, res) => {
  const token = req.body.token;
  const secret = req.session.twoFASecret || process.env.TWOFA_SECRET;
  if (!token) return res.status(400).json({ valid: false, error: "token missing" });
  if (!secret) return res.status(400).json({ valid: false, error: "secret missing" });
  const verified = speakeasy.totp.verify({ secret, encoding: "base32", token, window: 1 });
  if (verified) {
    req.session.twoFA = true;
    return res.json({ valid: true, redirect: "/admin.html" });
  }
  return res.json({ valid: false, error: "Invalid 2FA code" });
});

// Admin
app.get("/api/admin/check", ensureAuthenticated, (req, res) => res.json({ isAdmin: isAdmin(req) }));
app.get("/api/admin/check-login", (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ isAdmin: false });
  res.json({ isAdmin: isAdmin(req) });
});
app.get("/api/admin/data", ensureAdmin, (req, res) => res.json(loadSiteData()));
app.post("/api/admin/save", ensureAdmin, (req, res) => {
  try {
    saveSiteData(req.body);
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: "Erreur sauvegarde" });
  }
});

app.get("/auth-check", (req, res) => {
  if (req.isAuthenticated() && req.session.twoFA === true) return res.json({ authenticated: true });
  res.json({ authenticated: false });
});

export const handler = serverless(app);
