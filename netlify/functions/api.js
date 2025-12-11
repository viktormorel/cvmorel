const serverless = require('serverless-http');
const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const speakeasy = require('speakeasy');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const QRCode = require('qrcode');

// Fichier de donnees du site (pour l'admin)
const DATA_FILE = path.join('/tmp', 'site-data.json');

// Donnees par defaut
const DEFAULT_DATA = {
  skills: ['Anglais (LV)', 'Certification Pix (3e)', 'Renovation d\'ordinateurs', 'Diagnostics materiels', 'Bases reseaux', 'Sens du service'],
  interests: ['Sport - Ultimate, tennis, natation', 'Gaming en reseau', 'Reseaux sociaux - TikTok, Instagram, YouTube'],
  experiences: [],
  contact: {
    email: 'viktormorel@mailo.com',
    phone: '06.14.09.93.55',
    linkedin: 'viktormorel'
  }
};

function loadSiteData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    }
  } catch (err) {
    console.error('Erreur lecture site-data.json:', err);
  }
  return DEFAULT_DATA;
}

function saveSiteData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
}

function isAdmin(req) {
  if (!req.user || !req.user.emails || req.user.emails.length === 0) return false;
  const userEmail = req.user.emails[0].value;
  const adminEmail = process.env.ADMIN_EMAIL;
  return userEmail === adminEmail;
}

function ensureAdmin(req, res, next) {
  if (req.isAuthenticated() && req.session.twoFA === true && isAdmin(req)) {
    return next();
  }
  res.status(403).json({ error: 'Acces refuse - Admin uniquement' });
}

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated() && req.session.twoFA === true) return next();
  res.redirect('/.netlify/functions/api/auth/google');
}

const app = express();
app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session avec cookie sécurisé
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: true,
    sameSite: 'lax'
  }
}));

// Config Google OAuth
const CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || 'https://cv-viktor-morel.netlify.app/.netlify/functions/api/auth/google/callback';

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: CALLBACK_URL
}, (accessToken, refreshToken, profile, done) => {
  return done(null, profile);
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// CORS
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  next();
});

// Health
app.get('/.netlify/functions/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Auth Google
app.get('/.netlify/functions/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/.netlify/functions/api/auth/google/callback', (req, res, next) => {
  passport.authenticate('google', (err, user, info) => {
    if (err) {
      console.error('OAuth error:', err);
      return res.status(500).send('Erreur OAuth');
    }
    if (!user) {
      return res.redirect('/');
    }
    req.logIn(user, (loginErr) => {
      if (loginErr) {
        return res.status(500).send('Erreur de connexion.');
      }
      res.redirect('/login-2fa.html');
    });
  })(req, res, next);
});

// 2FA verification
app.post('/.netlify/functions/api/verify-2fa', (req, res) => {
  const secret = req.session.twoFASecret || process.env.TWOFA_SECRET;
  if (!secret) {
    return res.status(400).send('<h2>Erreur serveur : secret 2FA manquant.</h2>');
  }
  const verified = speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: req.body.token,
    window: 1
  });
  if (verified) {
    req.session.twoFA = true;
    return res.redirect('/download.html');
  }
  res.send('<h2>Code invalide, réessaie.</h2><a href="/login-2fa.html">Retour</a>');
});

// 2FA generate
app.post('/.netlify/functions/api/api/2fa/generate', (req, res) => {
  try {
    const secret = speakeasy.generateSecret({ length: 20, name: 'ViktorMorel' });
    req.session.twoFASecret = secret.base32;
    QRCode.toDataURL(secret.otpauth_url)
      .then((dataUrl) => {
        res.json({ secret: secret.base32, otpauth_url: secret.otpauth_url, qrCode: dataUrl });
      })
      .catch((err) => {
        res.status(500).json({ error: 'QR generation failed' });
      });
  } catch (e) {
    res.status(500).json({ error: '2FA generate failed' });
  }
});

// 2FA verify API
app.post('/.netlify/functions/api/api/2fa/verify', (req, res) => {
  const token = req.body.token;
  const secret = req.session.twoFASecret || process.env.TWOFA_SECRET;
  if (!token) return res.status(400).json({ valid: false, message: 'token missing' });
  if (!secret) return res.status(400).json({ valid: false, message: 'secret missing' });
  const verified = speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: token,
    window: 1
  });
  if (verified) {
    req.session.twoFA = true;
    return res.json({ valid: true, message: 'Code valide' });
  }
  return res.json({ valid: false, message: 'Code invalide' });
});

// 2FA code display
app.get('/.netlify/functions/api/api/2fa/code', (req, res) => {
  const secret = req.session.twoFASecret || process.env.TWOFA_SECRET;
  if (!secret) return res.status(400).json({ error: 'secret_missing' });
  if (process.env.ALLOW_TOTP_DISPLAY !== 'true') return res.status(403).json({ error: 'not_allowed' });
  try {
    const token = speakeasy.totp({ secret: secret, encoding: 'base32' });
    return res.json({ token });
  } catch (err) {
    return res.status(500).json({ error: 'internal_error' });
  }
});

// Admin check
app.get('/.netlify/functions/api/api/admin/check', ensureAuthenticated, (req, res) => {
  res.json({ isAdmin: isAdmin(req) });
});

app.get('/.netlify/functions/api/api/admin/check-login', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ isAdmin: false });
  }
  res.json({ isAdmin: isAdmin(req) });
});

// Admin data
app.get('/.netlify/functions/api/api/admin/data', ensureAdmin, (req, res) => {
  res.json(loadSiteData());
});

app.post('/.netlify/functions/api/api/admin/save', ensureAdmin, (req, res) => {
  try {
    saveSiteData(req.body);
    res.json({ success: true, message: 'Donnees sauvegardees' });
  } catch (err) {
    res.status(500).json({ error: 'Erreur sauvegarde' });
  }
});

// Auth check pour téléchargement
app.get('/.netlify/functions/api/auth-check', (req, res) => {
  if (req.isAuthenticated() && req.session.twoFA === true) {
    return res.json({ authenticated: true });
  }
  res.json({ authenticated: false });
});

module.exports.handler = serverless(app);
