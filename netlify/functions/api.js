// netlify/functions/api.js - viktorvahecvmorel.netlify.app
import serverless from "serverless-http";
import express from "express";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import speakeasy from "speakeasy";
import session from "express-session";
import QRCode from "qrcode";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import { getStore } from "@netlify/blobs";

const JWT_SECRET = process.env.JWT_SECRET || process.env.SESSION_SECRET || "jwt-secret-key";

// Config Netlify Blobs pour persistance
const BLOB_STORE_NAME = "cv-data";
const BLOB_KEY = "site-data";

// Helper pour obtenir le store avec config explicite
function getBlobStore() {
  // Netlify fournit automatiquement ces variables en production
  const siteID = process.env.SITE_ID; // Variable auto fournie par Netlify
  const token = process.env.NETLIFY_AUTH_TOKEN || process.env.NETLIFY_ACCESS_TOKEN;

  // Si on a les credentials, utiliser config explicite
  if (siteID && token) {
    return getStore({
      name: BLOB_STORE_NAME,
      siteID: siteID,
      token: token
    });
  }

  // Sinon, laisser Netlify gérer automatiquement (contexte de déploiement)
  return getStore(BLOB_STORE_NAME);
}

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
  experiences: [
    { title: "Stage de Terminale CIEL", company: "", tag: "Decouverte metiers du numerique", date: "1er-19 dec. 2025 / 5-23 janv. 2026", description: "Objectif : decouverte des metiers du numerique, observation et participation aux activites techniques." },
    { title: "France Televisions", company: "Stage de 3e", tag: "Audiovisuel", date: "1 semaine", description: "Decouverte de l'entreprise et du secteur audiovisuel. Observation des metiers de production." },
    { title: "INGEMART", company: "Bureau d'etude VRD", tag: "Voirie & reseaux divers", date: "3 semaines (seconde)", description: "Participation aux plans d'amenagement, decouverte du bureau d'etude. Lecture de plans et DAO." },
    { title: "Restos du Coeur", company: "Chantier d'insertion", tag: "Renovation et demantelement IT", date: "3 semaines (seconde)", description: "Renovation d'ordinateurs et demantelement de materiel informatique. Tri et remise en etat." },
    { title: "Restos du Coeur", company: "Chantier d'insertion", tag: "Approfondissement IT", date: "Stage de premiere", description: "Approfondissement des connaissances et competences techniques. Diagnostics materiels." },
    { title: "Palan Informatique", company: "Plaisir", tag: "Diagnostics & reparations", date: "Stage de premiere", description: "Diagnostic, reparation et relation clientele. Tests materiels et logiciels." }
  ],
  formations: [
    { title: "Terminale CIEL", school: "Lycee pro Jean Moulin", year: "En cours", location: "Le Chesnay (78)", description: "Bac pro Cybersecurite, Informatique et Reseaux Electroniques." }
  ],
  contact: {
    email: "viktormorel@mailo.com",
    phone: "06.14.09.93.55",
    linkedin: "viktormorel"
  },
  logins: [
    { name: "Vahé Vik", email: "vikvahe@gmail.com", photo: "https://lh3.googleusercontent.com/a/ACg8ocLkWCI13o5eJ7reEki7Es1XxBqXIGdcOwl9Q39ZwtfSNqCWarQT=s96-c", date: "2026-01-06T11:04:13.852Z" },
    { name: "Xx Xx", email: "abricotpomme1234@gmail.com", photo: "https://lh3.googleusercontent.com/a/ACg8ocJcfbXrBn5AlNnFH6QxLqzAKvuhVJ0FtIfypnzgIC9WuMbXEQ=s96-c", date: "2026-01-03T16:11:12.258Z" }
  ],
  stats: {
    visits: 68,
    lastVisits: [
      { date: "2026-01-06", count: 11 },
      { date: "2026-01-05", count: 4 },
      { date: "2026-01-03", count: 7 },
      { date: "2025-12-28", count: 3 },
      { date: "2025-12-23", count: 2 },
      { date: "2025-12-19", count: 24 },
      { date: "2025-12-18", count: 17 }
    ]
  }
};

// Gestion des connexions (utilise Netlify Blobs)
async function loadLogins() {
  const data = await loadSiteData();
  return data.logins || [];
}

async function saveLogin(user) {
  try {
    const data = await loadSiteData();
    let logins = data.logins || [];
    const userEmail = user.emails?.[0]?.value || "";
    const now = Date.now();

    // Éviter les doublons : ne pas enregistrer si même email dans les 5 dernières minutes
    const fiveMinutesAgo = now - (5 * 60 * 1000);
    const recentLogin = logins.find(login =>
      login.email === userEmail &&
      login.date &&
      new Date(login.date).getTime() > fiveMinutesAgo
    );

    if (recentLogin) {
      console.log("Connexion déjà enregistrée récemment pour:", userEmail);
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

    // Sauvegarder
    data.logins = logins;
    await saveSiteData(data);
    console.log("Connexion sauvegardée pour:", user.displayName);
  } catch (err) {
    console.error("Erreur sauvegarde connexion:", err);
  }
}

// Compteur de visites
async function incrementVisits() {
  const data = await loadSiteData();
  let stats = data.stats || { visits: 0, lastVisits: [] };

  const now = new Date();
  const today = now.toISOString().split('T')[0];

  // Incrémenter le compteur total
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

  // Sauvegarder
  data.stats = stats;
  await saveSiteData(data);
  console.log("Stats mises à jour:", stats.visits);

  return stats;
}

async function getStats() {
  const data = await loadSiteData();
  return data.stats || { visits: 0, lastVisits: [] };
}

// Charger les données depuis Netlify Blobs
// IMPORTANT: Toujours lire depuis Blobs pour avoir les données à jour
async function loadSiteData() {
  try {
    const store = getBlobStore();
    const data = await store.get(BLOB_KEY, { type: "json" });

    if (data) {
      // S'assurer que les données ont la structure attendue
      // Utiliser DEFAULT_DATA si le champ est absent OU si c'est un tableau vide
      if (!data.skills || data.skills.length === 0) data.skills = DEFAULT_DATA.skills || [];
      if (!data.interests || data.interests.length === 0) data.interests = DEFAULT_DATA.interests || [];
      if (!data.experiences || data.experiences.length === 0) data.experiences = DEFAULT_DATA.experiences || [];
      if (!data.formations || data.formations.length === 0) data.formations = DEFAULT_DATA.formations || [];
      if (!data.contact) data.contact = DEFAULT_DATA.contact || {};
      console.log("Données chargées depuis Netlify Blobs");
      return data;
    } else {
      console.log("Aucune donnée trouvée dans Blobs, initialisation avec données par défaut");
      // Sauvegarder les données par défaut dans Blobs pour la première fois
      await store.setJSON(BLOB_KEY, DEFAULT_DATA);
      return { ...DEFAULT_DATA };
    }
  } catch (err) {
    console.error("Erreur lecture Netlify Blobs:", err);
  }

  // Toujours retourner des données valides (par défaut si nécessaire)
  return { ...DEFAULT_DATA };
}

// Sauvegarder les données sur Netlify Blobs
async function saveSiteData(data) {
  try {
    const store = getBlobStore();
    await store.setJSON(BLOB_KEY, data);
    console.log("Données sauvegardées sur Netlify Blobs");
  } catch (err) {
    console.error("Erreur sauvegarde Netlify Blobs:", err);
    throw err; // Propager l'erreur pour informer l'appelant
  }
}

function isAdmin(req) {
  // Vérifier via JWT d'abord
  if (req.jwtUser?.isAdmin) return true;
  // Sinon vérifier via req.user
  const userEmail = req.user?.emails?.[0]?.value || req.jwtUser?.email;
  if (!userEmail) return false;
  const adminEmail = process.env.ADMIN_EMAIL || "vikvahe@gmail.com";
  return userEmail === adminEmail;
}

function ensureAdmin(req, res, next) {
  const hasAuth = (req.isAuthenticated() && req.session.twoFA === true) || (req.jwtUser && req.jwtUser.twoFA);
  const userIsAdmin = isAdmin(req);
  if (hasAuth && userIsAdmin) {
    return next();
  }
  res.status(403).json({ error: "Acces refuse - Admin uniquement" });
}

function ensureAuthenticated(req, res, next) {
  const hasAuth = (req.isAuthenticated() && req.session.twoFA === true) || (req.jwtUser && req.jwtUser.twoFA);
  if (hasAuth) return next();
  res.redirect("/auth/google");
}

// Fonction pour créer et envoyer le JWT auth
function setAuthCookie(res, user, twoFA = true) {
  const email = user?.emails?.[0]?.value || user?.email || "";
  const name = user?.displayName || user?.name || "";
  const token = jwt.sign(
    { email, name, twoFA, isAdmin: email === (process.env.ADMIN_EMAIL || "vikvahe@gmail.com") },
    JWT_SECRET,
    { expiresIn: "24h" }
  );
  res.cookie("auth_token", token, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge: 24 * 60 * 60 * 1000
  });
}

const app = express();
app.set("trust proxy", 1);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true,
      sameSite: "none",
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000
    }
  })
);

// Middleware pour vérifier le JWT et restaurer la session
app.use((req, res, next) => {
  const token = req.cookies?.auth_token;
  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.jwtUser = decoded;
      // Restaurer les infos de session depuis le JWT
      if (!req.session.twoFA && decoded.twoFA) {
        req.session.twoFA = true;
      }
      if (!req.user && decoded.email) {
        req.user = { emails: [{ value: decoded.email }], displayName: decoded.name };
      }
    } catch (err) {
      // Token invalide, on continue sans
    }
  }
  next();
});

const CALLBACK_URL =
  process.env.GOOGLE_CALLBACK_URL ||
  "https://viktorvahecvmorel.netlify.app/.netlify/functions/api/auth/google/callback";

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
  if (req.method === "OPTIONS") return res.status(204).end();
  next();
});

// Routes
app.get(["/health", "/.netlify/functions/api/health"], (req, res) => res.json({ status: "ok" }));

// Public data - accessible sans auth (pour le site public)
app.get(["/public-data", "/api/public-data", "/.netlify/functions/api/public-data"], async (req, res) => {
  try {
    const data = await loadSiteData();
    // Retourner seulement les données publiques (pas les logins/stats)
    // Toujours retourner un objet valide même si les données sont vides
    res.json({
      skills: Array.isArray(data.skills) ? data.skills : [],
      interests: Array.isArray(data.interests) ? data.interests : [],
      experiences: Array.isArray(data.experiences) ? data.experiences : [],
      formations: Array.isArray(data.formations) ? data.formations : [],
      contact: data.contact && typeof data.contact === 'object' ? data.contact : {}
    });
  } catch (err) {
    console.error("[Public] Error:", err);
    // En cas d'erreur, retourner les données par défaut plutôt qu'une erreur 500
    res.json({
      skills: DEFAULT_DATA.skills || [],
      interests: DEFAULT_DATA.interests || [],
      experiences: DEFAULT_DATA.experiences || [],
      formations: DEFAULT_DATA.formations || [],
      contact: DEFAULT_DATA.contact || {}
    });
  }
});

app.get(["/auth/google", "/.netlify/functions/api/auth/google"], passport.authenticate("google", { scope: ["profile", "email"] }));

app.get(["/auth/google/callback", "/.netlify/functions/api/auth/google/callback"], (req, res, next) => {
  passport.authenticate("google", async (err, user) => {
    try {
      if (err) {
        console.error("OAuth error:", err);
        return res.status(500).send("Erreur OAuth");
      }
      if (!user) return res.redirect("/");
      req.logIn(user, async (loginErr) => {
        try {
          if (loginErr) {
            console.error("Login error:", loginErr);
            return res.status(500).send("Erreur de connexion.");
          }
          // Sauvegarder la connexion
          await saveLogin(user);
          // Rediriger vers le menu de choix après 2FA
          req.session.redirectAfter2FA = "/menu-choice.html";
          res.redirect("/login-2fa.html");
        } catch (loginError) {
          console.error("Erreur lors du login:", loginError);
          res.status(500).send("Erreur de connexion.");
        }
      });
    } catch (authError) {
      console.error("Erreur authentification OAuth:", authError);
      res.status(500).send("Erreur OAuth");
    }
  })(req, res, next);
});

// 2FA Verify (form)
app.post(["/verify-2fa", "/.netlify/functions/api/verify-2fa"], (req, res) => {
  try {
    // Validation de l'authentification
    if (!req.isAuthenticated()) {
      return res.status(401).send("<h2>Non authentifié.</h2><a href='/login-2fa.html'>Retour</a>");
    }

    const token = String(req.body.token || "").trim();
    if (!token) return res.status(400).send("<h2>Code manquant.</h2><a href='/login-2fa.html'>Retour</a>");
    
    // Validation du format (6 chiffres)
    if (!/^\d{6}$/.test(token)) {
      return res.status(400).send("<h2>Code invalide : doit contenir 6 chiffres.</h2><a href='/login-2fa.html'>Retour</a>");
    }

    // Vérifier le code email d'abord
    if (req.session.emailCode && req.session.emailCodeExpiry && Date.now() < req.session.emailCodeExpiry) {
      if (req.session.emailCode === token) {
        req.session.twoFA = true;
        setAuthCookie(res, req.user);
        delete req.session.emailCode;
        delete req.session.emailCodeExpiry;
        // Forcer redirection vers menu-choice.html
        return res.redirect("/menu-choice.html");
      }
    }

    // Sinon vérifier le TOTP
    const secret = process.env.TOTP_SECRET || req.session.twoFASecret;
    if (!secret) {
      console.error("Secret 2FA manquant pour l'utilisateur:", req.user?.emails?.[0]?.value);
      return res.status(500).send("<h2>Erreur serveur : secret 2FA manquant.</h2><a href='/login-2fa.html'>Retour</a>");
    }

    let verified = false;
    try {
      verified = speakeasy.totp.verify({
        secret,
        encoding: "base32",
        token: token,
        window: 2
      });
    } catch (verifyErr) {
      console.error("Erreur vérification TOTP:", verifyErr);
      return res.status(500).send("<h2>Erreur lors de la vérification.</h2><a href='/login-2fa.html'>Retour</a>");
    }

    if (verified) {
      req.session.twoFA = true;
      setAuthCookie(res, req.user);
      // Forcer redirection vers menu-choice.html
      return res.redirect("/menu-choice.html");
    }

    res.status(400).send("<h2>Code invalide, réessaie.</h2><a href='/login-2fa.html'>Retour</a>");
  } catch (err) {
    console.error("Erreur vérification 2FA (form):", err);
    res.status(500).send("<h2>Erreur serveur.</h2><a href='/login-2fa.html'>Retour</a>");
  }
});

// 2FA Generate (API)
app.post(["/api/2fa/generate", "/.netlify/functions/api/2fa/generate"], (req, res) => {
  try {
    // Validation de l'authentification
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Non authentifié" });
    }

    const secret = speakeasy.generateSecret({ length: 20, name: "ViktorMorel" });
    if (!secret || !secret.base32) {
      throw new Error("Erreur génération secret");
    }
    
    req.session.twoFASecret = secret.base32;
    
    if (!secret.otpauth_url) {
      return res.status(500).json({ error: "URL OTP manquante" });
    }
    
    QRCode.toDataURL(secret.otpauth_url)
      .then((dataUrl) => {
        if (!dataUrl) {
          throw new Error("QR code vide");
        }
        res.json({ secret: secret.base32, qrCode: dataUrl });
      })
      .catch((err) => {
        console.error("QR generation error:", err);
        res.status(500).json({ error: "QR generation failed" });
      });
  } catch (err) {
    console.error("2FA generate error:", err);
    res.status(500).json({ error: "2FA generate failed" });
  }
});

// 2FA Send Email (API)
app.post(["/api/2fa/send-email", "/.netlify/functions/api/2fa/send-email"], async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ success: false, error: "Non authentifie" });
  }

  const userEmail = req.user?.emails?.[0]?.value;
  const userName = req.user?.displayName || "Utilisateur";
  if (!userEmail) {
    return res.status(400).json({ success: false, error: "Email non disponible" });
  }

  // Générer un code à 6 chiffres
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  req.session.emailCode = code;
  req.session.emailCodeExpiry = Date.now() + 10 * 60 * 1000; // 10 minutes

  // Envoyer l'email via Mailjet
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
            <h2>Code de vérification</h2>
            <p>Bonjour ${userName},</p>
            <p>Votre code de vérification à 2 facteurs est :</p>
            <h1 style="font-size: 32px; color: #6366f1; letter-spacing: 8px;">${code}</h1>
            <p>Ce code est valide pendant 10 minutes.</p>
            <p><small>Si vous n'avez pas demandé ce code, ignorez cet email.</small></p>
          `
        }]
      })
    });

    if (emailResponse.ok) {
      console.log(`Code email envoyé à ${userEmail}`);
      res.json({ success: true });
    } else {
      const errorText = await emailResponse.text();
      console.error("Mailjet error:", emailResponse.status, errorText);
      res.status(500).json({ success: false, error: "Erreur envoi email" });
    }
  } catch (err) {
    console.error("Erreur envoi email:", err);
    res.status(500).json({ success: false, error: "Erreur serveur" });
  }
});

// 2FA Verify (API)
app.post(["/api/2fa/verify", "/.netlify/functions/api/2fa/verify"], (req, res) => {
  try {
    // Validation de l'authentification
    if (!req.isAuthenticated()) {
      return res.status(401).json({ valid: false, error: "Non authentifié" });
    }

    const token = String(req.body.token || "").trim();
    if (!token) return res.status(400).json({ valid: false, error: "token missing" });
    
    // Validation du format (6 chiffres)
    if (!/^\d{6}$/.test(token)) {
      return res.status(400).json({ valid: false, error: "Code invalide : doit contenir 6 chiffres" });
    }

    // Vérifier le code email d'abord
    if (req.session.emailCode && req.session.emailCodeExpiry && Date.now() < req.session.emailCodeExpiry) {
      if (req.session.emailCode === token) {
        req.session.twoFA = true;
        setAuthCookie(res, req.user);
        delete req.session.emailCode;
        delete req.session.emailCodeExpiry;
        console.log("Code email vérifié avec succès pour:", req.user?.emails?.[0]?.value);
        // Forcer redirection vers menu-choice.html
        return res.json({ valid: true, redirect: "/menu-choice.html" });
      }
    }

    // Sinon vérifier le TOTP
    const secret = process.env.TOTP_SECRET || req.session.twoFASecret;
    if (!secret) {
      console.error("Secret 2FA manquant pour l'utilisateur:", req.user?.emails?.[0]?.value);
      return res.status(500).json({ valid: false, error: "secret missing" });
    }

    let verified = false;
    try {
      verified = speakeasy.totp.verify({ secret, encoding: "base32", token, window: 2 });
    } catch (verifyErr) {
      console.error("Erreur vérification TOTP:", verifyErr);
      return res.status(500).json({ valid: false, error: "Erreur lors de la vérification" });
    }

    if (verified) {
      req.session.twoFA = true;
      setAuthCookie(res, req.user);
      console.log("Code TOTP vérifié avec succès pour:", req.user?.emails?.[0]?.value);
      // Forcer redirection vers menu-choice.html
      return res.json({ valid: true, redirect: "/menu-choice.html" });
    }

    console.log("Code invalide pour:", req.user?.emails?.[0]?.value);
    return res.json({ valid: false, error: "Invalid 2FA code" });
  } catch (err) {
    console.error("Erreur vérification 2FA (API):", err);
    return res.status(500).json({ valid: false, error: "Erreur serveur" });
  }
});

// User Info (API)
app.get(["/api/user-info", "/user-info", "/.netlify/functions/api/user-info"], (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Non authentifie" });
  }
  const isAdminUser = isAdmin(req);
  console.log(`User info requested - Email: ${req.user?.emails?.[0]?.value}, Admin: ${isAdminUser}`);
  res.json({
    email: req.user?.emails?.[0]?.value || "",
    name: req.user?.displayName || "",
    isAdmin: isAdminUser
  });
});

// Admin 2FA Code (API)
// Route pour définir la redirection admin après 2FA
app.post(["/api/admin/set-redirect", "/.netlify/functions/api/admin/set-redirect"], (req, res) => {
  if (!req.isAuthenticated()) {
    // Si pas encore authentifié, on accepte quand même (l'utilisateur sera vérifié après 2FA)
    req.session.redirectAfter2FA = "/.netlify/functions/api/admin";
    return res.json({ success: true, redirect: "/.netlify/functions/api/admin" });
  }
  // Si authentifié, vérifier qu'il est admin
  if (!isAdmin(req)) {
    return res.status(403).json({ error: "Non autorisé" });
  }
  req.session.redirectAfter2FA = "/.netlify/functions/api/admin";
  res.json({ success: true, redirect: "/.netlify/functions/api/admin" });
});

app.get(["/api/admin/2fa-code", "/admin/2fa-code", "/.netlify/functions/api/admin/2fa-code"], (req, res) => {
  if (!req.isAuthenticated()) {
    console.error("Admin code request - Non authentifié");
    return res.status(401).json({ error: "Non authentifie" });
  }
  if (!isAdmin(req)) {
    console.error(`Admin code request - Accès refusé pour ${req.user?.emails?.[0]?.value}`);
    return res.status(403).json({ error: "Admin uniquement" });
  }

  let code = req.session.emailCode;
  if (!code || Date.now() > (req.session.emailCodeExpiry || 0)) {
    code = Math.floor(100000 + Math.random() * 900000).toString();
    req.session.emailCode = code;
    req.session.emailCodeExpiry = Date.now() + 10 * 60 * 1000;
    console.log(`Nouveau code admin généré: ${code}`);
  } else {
    console.log(`Code admin existant réutilisé: ${code}`);
  }

  res.json({ code });
});

// Admin routes
app.get(["/api/admin/check", "/admin/check", "/.netlify/functions/api/admin/check"], (req, res) => {
  // Vérifier l'authentification et la 2FA sans rediriger (pour le script JS)
  const hasAuth = (req.isAuthenticated() && req.session.twoFA === true) || (req.jwtUser && req.jwtUser.twoFA);
  if (!hasAuth) {
    return res.json({ isAdmin: false });
  }
  // Vérifier si admin via JWT ou via req.user
  const userIsAdmin = req.jwtUser?.isAdmin || isAdmin(req);
  res.json({ isAdmin: userIsAdmin });
});

app.get(["/api/admin/check-login", "/admin/check-login", "/.netlify/functions/api/admin/check-login"], (req, res) => {
  const hasAuth = req.isAuthenticated() || (req.jwtUser && req.jwtUser.email);
  if (!hasAuth) return res.status(401).json({ isAdmin: false });
  const userIsAdmin = req.jwtUser?.isAdmin || isAdmin(req);
  res.json({ isAdmin: userIsAdmin });
});

app.get(["/api/admin/data", "/admin/data", "/.netlify/functions/api/admin/data"], ensureAdmin, async (req, res) => {
  try {
    const data = await loadSiteData();
    res.json(data);
  } catch (err) {
    console.error("Erreur chargement données:", err);
    res.status(500).json({ error: "Erreur chargement" });
  }
});

app.post(["/api/admin/save", "/admin/save", "/.netlify/functions/api/admin/save"], ensureAdmin, async (req, res) => {
  try {
    // Validation des données
    if (!req.body || typeof req.body !== 'object') {
      return res.status(400).json({ error: "Données invalides" });
    }

    // Charger les données existantes pour préserver logins/stats
    const existingData = await loadSiteData();

    // Fusionner avec les nouvelles données (préserver logins et stats existants)
    const data = {
      skills: Array.isArray(req.body.skills) ? req.body.skills : existingData.skills || [],
      interests: Array.isArray(req.body.interests) ? req.body.interests : existingData.interests || [],
      experiences: Array.isArray(req.body.experiences) ? req.body.experiences : existingData.experiences || [],
      formations: Array.isArray(req.body.formations) ? req.body.formations : existingData.formations || [],
      contact: req.body.contact && typeof req.body.contact === 'object' ? req.body.contact : existingData.contact || {},
      logins: existingData.logins || [],
      stats: existingData.stats || {}
    };

    // Validation des champs contact
    if (data.contact.email && typeof data.contact.email !== 'string') {
      return res.status(400).json({ error: "Email invalide" });
    }
    if (data.contact.phone && typeof data.contact.phone !== 'string') {
      return res.status(400).json({ error: "Téléphone invalide" });
    }
    if (data.contact.linkedin && typeof data.contact.linkedin !== 'string') {
      return res.status(400).json({ error: "LinkedIn invalide" });
    }

    await saveSiteData(data);
    console.log("Données admin sauvegardées par:", req.user?.emails?.[0]?.value);
    res.json({ success: true });
  } catch (err) {
    console.error("Erreur sauvegarde admin:", err);
    res.status(500).json({ error: "Erreur sauvegarde: " + (err.message || "inconnue") });
  }
});

app.get(["/auth-check", "/.netlify/functions/api/auth-check"], (req, res) => {
  const hasAuth = (req.isAuthenticated() && req.session.twoFA === true) || (req.jwtUser && req.jwtUser.twoFA);
  if (hasAuth) return res.json({ authenticated: true });
  res.json({ authenticated: false });
});

// Admin: Upload CV file
app.post(["/api/admin/upload-cv", "/admin/upload-cv", "/.netlify/functions/api/admin/upload-cv"], ensureAdmin, async (req, res) => {
  try {
    const { filename, data } = req.body;

    if (!filename || !data) {
      return res.status(400).json({ error: "Fichier manquant" });
    }

    // Validate file extension
    if (!filename.match(/\.(docx|doc)$/i)) {
      return res.status(400).json({ error: "Format invalide. Utilise .docx ou .doc" });
    }

    // Extract base64 data (remove data:...;base64, prefix)
    const base64Data = data.replace(/^data:[^;]+;base64,/, "");
    const fileBuffer = Buffer.from(base64Data, "base64");

    // Validate file size (max 10MB)
    if (fileBuffer.length > 10 * 1024 * 1024) {
      return res.status(400).json({ error: "Fichier trop volumineux (max 10 Mo)" });
    }

    // Store CV in Netlify Blobs
    const store = getBlobStore();
    await store.set("cv-file", fileBuffer, {
      metadata: {
        filename: filename,
        uploadedAt: new Date().toISOString(),
        uploadedBy: req.jwtUser?.email || req.user?.emails?.[0]?.value || "admin"
      }
    });

    console.log("CV uploaded successfully:", filename, "by", req.jwtUser?.email || req.user?.emails?.[0]?.value);
    res.json({ success: true, message: "CV mis a jour avec succes" });
  } catch (err) {
    console.error("Erreur upload CV:", err);
    res.status(500).json({ error: "Erreur lors de l'upload" });
  }
});

// Admin: Upload Lettre de motivation
app.post(["/api/admin/upload-letter", "/admin/upload-letter", "/.netlify/functions/api/admin/upload-letter"], ensureAdmin, async (req, res) => {
  try {
    const { filename, data } = req.body;

    if (!filename || !data) {
      return res.status(400).json({ error: "Fichier manquant" });
    }

    // Validate file extension
    if (!filename.match(/\.(docx|doc|pdf)$/i)) {
      return res.status(400).json({ error: "Format invalide. Utilise .docx, .doc ou .pdf" });
    }

    // Extract base64 data (remove data:...;base64, prefix)
    const base64Data = data.replace(/^data:[^;]+;base64,/, "");
    const fileBuffer = Buffer.from(base64Data, "base64");

    // Validate file size (max 10MB)
    if (fileBuffer.length > 10 * 1024 * 1024) {
      return res.status(400).json({ error: "Fichier trop volumineux (max 10 Mo)" });
    }

    // Store Letter in Netlify Blobs
    const store = getBlobStore();
    await store.set("letter-file", fileBuffer, {
      metadata: {
        filename: filename,
        uploadedAt: new Date().toISOString(),
        uploadedBy: req.jwtUser?.email || req.user?.emails?.[0]?.value || "admin"
      }
    });

    console.log("Lettre uploaded successfully:", filename, "by", req.jwtUser?.email || req.user?.emails?.[0]?.value);
    res.json({ success: true, message: "Lettre de motivation mise a jour avec succes" });
  } catch (err) {
    console.error("Erreur upload Lettre:", err);
    res.status(500).json({ error: "Erreur lors de l'upload" });
  }
});

// Admin: historique des connexions
app.get(["/api/admin/logins", "/admin/logins", "/.netlify/functions/api/admin/logins"], ensureAdmin, async (req, res) => {
  try {
    const logins = await loadLogins();
    res.json(logins);
  } catch (err) {
    console.error("Erreur chargement logins:", err);
    res.status(500).json({ error: "Erreur chargement logins" });
  }
});

// Statistiques de visites (public - pas de données sensibles)
app.get(["/api/admin/stats", "/admin/stats", "/.netlify/functions/api/admin/stats"], async (req, res) => {
  try {
    const stats = await getStats();
    res.json(stats);
  } catch (err) {
    console.error("Erreur chargement stats:", err);
    res.status(500).json({ error: "Erreur chargement stats" });
  }
});

// Tracking: incrémenter le compteur de visites
app.post(["/api/track-visit", "/track-visit", "/.netlify/functions/api/track-visit"], async (req, res) => {
  try {
    const stats = await incrementVisits();
    res.json({ success: true, visits: stats.visits });
  } catch (err) {
    console.error("Erreur tracking visite:", err);
    res.json({ success: false, visits: 0 });
  }
});

// Page download sécurisée - HTML servi uniquement si authentifié
app.get(["/download-cv", "/.netlify/functions/api/download-cv"], (req, res) => {
  try {
    if (!req.isAuthenticated() || req.session.twoFA !== true) {
      return res.redirect("/");
    }
    const isAdminUser = isAdmin(req);
    // Échapper le nom d'utilisateur pour éviter XSS
    const userName = String(req.user?.displayName?.split(' ')[0] || 'Utilisateur')
      .replace(/[<>]/g, '');
    
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(`<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Accès Sécurisé - CV Viktor Morel</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Inter', system-ui, sans-serif;
      background: #0f0f23;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
      overflow: hidden;
    }
    .bg-animation {
      position: fixed;
      inset: 0;
      z-index: 0;
      overflow: hidden;
    }
    .orb {
      position: absolute;
      border-radius: 50%;
      filter: blur(80px);
      opacity: 0.6;
      animation: float 20s ease-in-out infinite;
    }
    .orb-1 {
      width: 500px;
      height: 500px;
      background: linear-gradient(135deg, #667eea, #764ba2);
      top: -150px;
      left: -100px;
    }
    .orb-2 {
      width: 400px;
      height: 400px;
      background: linear-gradient(135deg, #f093fb, #f5576c);
      bottom: -100px;
      right: -100px;
      animation-delay: -10s;
    }
    @keyframes float {
      0%, 100% { transform: translate(0, 0) scale(1); }
      25% { transform: translate(30px, -30px) scale(1.05); }
      50% { transform: translate(-20px, 20px) scale(0.95); }
      75% { transform: translate(20px, 30px) scale(1.02); }
    }
    .grid-pattern {
      position: fixed;
      inset: 0;
      background-image:
        linear-gradient(rgba(255,255,255,0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,0.03) 1px, transparent 1px);
      background-size: 50px 50px;
      z-index: 1;
    }
    .card {
      position: relative;
      z-index: 10;
      background: rgba(255, 255, 255, 0.08);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid rgba(255, 255, 255, 0.15);
      border-radius: 28px;
      padding: 48px 40px;
      width: 100%;
      max-width: 480px;
      box-shadow: 0 25px 50px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.1);
      animation: cardIn 0.6s cubic-bezier(0.16, 1, 0.3, 1);
    }
    @keyframes cardIn {
      from { opacity: 0; transform: translateY(30px) scale(0.95); }
      to { opacity: 1; transform: translateY(0) scale(1); }
    }
    .success-icon {
      width: 80px;
      height: 80px;
      background: linear-gradient(135deg, #10b981, #059669);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 24px;
      box-shadow: 0 10px 40px rgba(16, 185, 129, 0.4);
      animation: pulse 2s ease-in-out infinite;
    }
    @keyframes pulse {
      0%, 100% { box-shadow: 0 10px 40px rgba(16, 185, 129, 0.4); }
      50% { box-shadow: 0 10px 60px rgba(16, 185, 129, 0.6); }
    }
    .success-icon svg {
      width: 40px;
      height: 40px;
      color: white;
    }
    .title {
      color: white;
      font-size: 1.8rem;
      font-weight: 700;
      text-align: center;
      margin-bottom: 8px;
    }
    .greeting {
      color: rgba(255, 255, 255, 0.7);
      font-size: 1rem;
      text-align: center;
      margin-bottom: 32px;
      line-height: 1.6;
    }
    .greeting strong {
      color: #a78bfa;
    }
    .btn {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 12px;
      width: 100%;
      padding: 18px 24px;
      border: none;
      border-radius: 16px;
      font-family: inherit;
      font-size: 1.05rem;
      font-weight: 600;
      cursor: pointer;
      text-decoration: none;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      margin-bottom: 12px;
      position: relative;
      overflow: hidden;
    }
    .btn::before {
      content: '';
      position: absolute;
      top: 50%;
      left: 50%;
      width: 0;
      height: 0;
      border-radius: 50%;
      background: rgba(255, 255, 255, 0.2);
      transform: translate(-50%, -50%);
      transition: width 0.6s, height 0.6s;
    }
    .btn:hover::before {
      width: 300px;
      height: 300px;
    }
    .btn span, .btn svg {
      position: relative;
      z-index: 1;
    }
    .btn-primary {
      background: linear-gradient(135deg, #667eea, #764ba2);
      color: white;
      box-shadow: 0 8px 30px rgba(102, 126, 234, 0.4);
    }
    .btn-primary:hover {
      transform: translateY(-3px);
      box-shadow: 0 12px 40px rgba(102, 126, 234, 0.5);
    }
    .btn-admin {
      background: linear-gradient(135deg, #f59e0b, #ef4444);
      color: white;
      box-shadow: 0 8px 30px rgba(245, 158, 11, 0.3);
    }
    .btn-admin:hover {
      transform: translateY(-3px);
      box-shadow: 0 12px 40px rgba(245, 158, 11, 0.4);
    }
    .btn-group {
      display: flex;
      flex-direction: column;
      gap: 12px;
      width: 100%;
    }
    .btn svg {
      width: 22px;
      height: 22px;
    }
    .back-link {
      position: fixed;
      top: 24px;
      left: 24px;
      z-index: 20;
      display: flex;
      align-items: center;
      gap: 8px;
      color: rgba(255, 255, 255, 0.6);
      text-decoration: none;
      font-size: 0.9rem;
      font-weight: 500;
      padding: 10px 16px;
      border-radius: 12px;
      background: rgba(255, 255, 255, 0.05);
      backdrop-filter: blur(10px);
      border: 1px solid rgba(255, 255, 255, 0.1);
      transition: all 0.3s;
    }
    .back-link:hover {
      color: white;
      background: rgba(255, 255, 255, 0.1);
      transform: translateX(-4px);
    }
  </style>
</head>
<body>
  <div class="bg-animation">
    <div class="orb orb-1"></div>
    <div class="orb orb-2"></div>
  </div>
  <div class="grid-pattern"></div>
  <a href="/" class="back-link">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M19 12H5M12 19l-7-7 7-7"/>
    </svg>
    Retour au CV
  </a>
  <div class="card">
    <div class="success-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <polyline points="20 6 9 17 4 12"/>
      </svg>
    </div>
    <h1 class="title">Accès Autorisé</h1>
    <p class="greeting">Bienvenue <strong>${userName}</strong> ! Tu t'es authentifié avec succès via Google et as validé la vérification 2FA.</p>
    <div class="btn-group">
      <a href="/.netlify/functions/api/download-cv/file" class="btn btn-primary">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
          <polyline points="7 10 12 15 17 10"/>
          <line x1="12" y1="15" x2="12" y2="3"/>
        </svg>
        <span>Télécharger le CV</span>
      </a>
      ${isAdminUser ? `<a href="/.netlify/functions/api/admin" class="btn btn-admin">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 15v2m-6 4h12a2 2 0 0 0 2-2v-6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2zm10-10V7a4 4 0 0 0-8 0v4h8z"/>
        </svg>
        <span>Accéder à l'admin</span>
      </a>` : ''}
    </div>
  </div>
</body>
</html>`);
  } catch (err) {
    console.error("Erreur génération page download-cv:", err);
    res.status(500).send("<!DOCTYPE html><html><head><meta charset='utf-8'><title>Erreur</title></head><body><h1>Erreur serveur</h1><p><a href='/'>Retour au CV</a></p></body></html>");
  }
});

// Route pour télécharger le fichier CV (protégée par auth)
app.get(["/download-cv/file", "/.netlify/functions/api/download-cv/file"], async (req, res) => {
  try {
    const hasAuth = (req.isAuthenticated() && req.session.twoFA === true) || (req.jwtUser && req.jwtUser.twoFA);
    if (!hasAuth) {
      return res.status(401).json({ error: "Non autorisé" });
    }

    // Try to get CV from Netlify Blobs first
    try {
      const store = getBlobStore();
      const cvData = await store.get("cv-file", { type: "arrayBuffer" });

      if (cvData) {
        // Get metadata to retrieve original filename
        const metadata = await store.getMetadata("cv-file");
        const filename = metadata?.metadata?.filename || "cv-viktor-morel.docx";

        res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
        res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
        res.setHeader("Cache-Control", "no-store");
        return res.send(Buffer.from(cvData));
      }
    } catch (blobErr) {
      console.log("CV not found in Blobs, falling back to static file:", blobErr.message);
    }

    // Fallback to static file
    res.redirect("/cv-viktor-morel.docx");
  } catch (err) {
    console.error("Erreur téléchargement CV:", err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// Route pour télécharger la Lettre de Motivation (protégée par auth)
app.get(["/download-letter/file", "/.netlify/functions/api/download-letter/file"], async (req, res) => {
  try {
    const hasAuth = (req.isAuthenticated() && req.session.twoFA === true) || (req.jwtUser && req.jwtUser.twoFA);
    if (!hasAuth) {
      return res.status(401).json({ error: "Non autorisé" });
    }

    // Try to get Letter from Netlify Blobs
    try {
      const store = getBlobStore();
      const letterData = await store.get("letter-file", { type: "arrayBuffer" });

      if (letterData) {
        // Get metadata to retrieve original filename
        const metadata = await store.getMetadata("letter-file");
        const filename = metadata?.metadata?.filename || "lettre-motivation-viktor-morel.docx";

        // Determine content type based on extension
        const isPdf = filename.toLowerCase().endsWith('.pdf');
        const contentType = isPdf
          ? "application/pdf"
          : "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

        res.setHeader("Content-Type", contentType);
        res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
        res.setHeader("Cache-Control", "no-store");
        return res.send(Buffer.from(letterData));
      }
    } catch (blobErr) {
      console.log("Letter not found in Blobs:", blobErr.message);
    }

    // No letter uploaded yet
    res.status(404).json({ error: "Aucune lettre de motivation disponible pour le moment" });
  } catch (err) {
    console.error("Erreur téléchargement Lettre:", err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// Route Admin - rediriger vers admin.html (fichier statique servi par Netlify CDN)
app.get(["/admin", "/.netlify/functions/api/admin"], ensureAdmin, (req, res) => {
  return res.redirect("/admin.html");
});

// Formulaire de contact - envoie vers Discord (webhook protégé côté serveur)
app.post(["/api/contact", "/contact", "/.netlify/functions/api/contact"], async (req, res) => {
  const { name, email, message } = req.body;

  // Validation basique
  if (!name || !email || !message) {
    return res.status(400).json({ success: false, error: "Tous les champs sont requis" });
  }

  // Validation email simple
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ success: false, error: "Email invalide" });
  }

  // Anti-spam: limite la taille des champs
  if (name.length > 100 || email.length > 100 || message.length > 2000) {
    return res.status(400).json({ success: false, error: "Message trop long" });
  }

  const webhookUrl = "https://discord.com/api/webhooks/1448025894886314178/rNO_tuMKNiOfFaHZPwDVq7vQOmUhNbjxRfWDKntmvoyhZaXX_tzD7bcIXSKU3jiKgKw7";

  try {
    const payload = {
      embeds: [{
        title: "📩 Nouveau message de contact",
        color: 0x6a11cb,
        fields: [
          { name: "Nom", value: name.slice(0, 100), inline: true },
          { name: "Email", value: email.slice(0, 100), inline: true },
          { name: "Message", value: message.slice(0, 1000) }
        ],
        timestamp: new Date().toISOString()
      }]
    };

    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    if (response.ok) {
      res.json({ success: true, message: "Message envoyé avec succès" });
    } else {
      console.error("Discord webhook error:", response.status);
      res.status(500).json({ success: false, error: "Erreur lors de l'envoi" });
    }
  } catch (err) {
    console.error("Contact form error:", err);
    res.status(500).json({ success: false, error: "Erreur serveur" });
  }
});

export const handler = serverless(app);
