const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const speakeasy = require('speakeasy');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const QRCode = require('qrcode');
require('dotenv').config();
console.log('GOOGLE_CLIENT_ID loaded:', !!process.env.GOOGLE_CLIENT_ID);

// Fichier de donnees du site (pour l'admin)
const DATA_FILE = path.join(__dirname, 'site-data.json');

// Charger ou initialiser les donnees du site
function loadSiteData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    }
  } catch (err) {
    console.error('Erreur lecture site-data.json:', err);
  }
  // Donnees par defaut
  return {
    skills: ['Anglais (LV)', 'Certification Pix (3e)', 'Renovation d\'ordinateurs', 'Diagnostics materiels', 'Bases reseaux', 'Sens du service'],
    interests: ['Sport - Ultimate, tennis, natation', 'Gaming en reseau', 'Reseaux sociaux - TikTok, Instagram, YouTube'],
    experiences: [],
    contact: {
      email: 'viktormorel@mailo.com',
      phone: '06.14.09.93.55',
      linkedin: 'viktormorel'
    }
  };
}

// Sauvegarder les donnees du site
function saveSiteData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
}

// Verifier si l'utilisateur est admin
function isAdmin(req) {
  if (!req.user || !req.user.emails || req.user.emails.length === 0) return false;
  const userEmail = req.user.emails[0].value;
  const adminEmail = process.env.ADMIN_EMAIL;
  return userEmail === adminEmail;
}

// Middleware admin
function ensureAdmin(req, res, next) {
  if (req.isAuthenticated() && req.session.twoFA === true && isAdmin(req)) {
    return next();
  }
  res.status(403).json({ error: 'Acces refuse - Admin uniquement' });
}

// Définir l'URL de callback depuis l'env si fournie, sinon construire une valeur par défaut
const DEFAULT_BASE = process.env.BASE_URL || 'http://localhost:3001';
const CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || `${DEFAULT_BASE}/auth/google/callback`;
console.log('Using GOOGLE_CALLBACK_URL:', CALLBACK_URL);

const app = express();
// Si l'application est derrière un proxy (Heroku/nginx/etc.), activer trust proxy
app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({ secret: 'secret', resave: false, saveUninitialized: true }));

// Config Google OAuth - utilisez l'URL exacte enregistrée dans la Google Console
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: CALLBACK_URL
}, (accessToken, refreshToken, profile, done) => {
  return done(null, profile);
}));

app.use(passport.initialize());
app.use(passport.session());

// Servir les fichiers statiques (CSS, JS, images, etc.)
app.use(express.static(path.join(__dirname)));

// Autoriser les requêtes cross-origin pour les vérifications health (dev)
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  next();
});

// Endpoint health pour permettre au client de vérifier que l'auth est disponible
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// Middleware de sécurité
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated() && req.session.twoFA === true) return next();
  res.redirect('/auth/google');
}

// Étape 1 : Connexion Google
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Callback personnalisé avec logs pour diagnostiquer les erreurs OAuth
app.get('/auth/google/callback', (req, res, next) => {
  passport.authenticate('google', (err, user, info) => {
    if (err) {
      console.error('OAuth error:', err);
      console.error('oauth statusCode:', err && err.statusCode ? err.statusCode : '(none)');
      console.error('oauth data/body:', err && (err.data || err.body) ? (err.data || err.body) : '(none)');
      console.error('Query params:', req.query);
      // Cas fréquent: redirect_uri_mismatch ou invalid_client -> fournir des instructions utiles
      const body = (err && (err.data || err.body)) ? (err.data || err.body) : err.message || JSON.stringify(err);
      if (String(body).includes('redirect_uri_mismatch') || String(body).includes('redirect_uri')) {
        return res.status(400).send(`<h2>Erreur OAuth : redirect_uri_mismatch</h2>
          <p>La redirection utilisée par l'application (<code>${CALLBACK_URL}</code>) ne correspond pas à l'URI autorisée dans la Google Cloud Console.</p>
          <p>Solution rapide :</p>
          <ol>
            <li>Ouvre la Google Cloud Console → APIs & Services → Credentials → ton client OAuth.</li>
            <li>Ajoute exactement cette URI de redirection : <code>${CALLBACK_URL}</code></li>
            <li>Enregistre, puis réessaye la connexion.</li>
          </ol>
          <p>Si tu veux, définis aussi <code>GOOGLE_CALLBACK_URL</code> dans ton <code>.env</code> pour forcer une autre URL.</p>`);
      }

      if (String(body).includes('invalid_client') || String(body).includes('Unauthorized') || err && err.statusCode === 401) {
        return res.status(401).send(`<h2>Erreur OAuth : Unauthorized / invalid_client</h2>
          <p>Vérifie que <code>GOOGLE_CLIENT_ID</code> et <code>GOOGLE_CLIENT_SECRET</code> dans ton <code>.env</code> sont corrects et non révoqués.</p>
          <p>Si ces identifiants ont été exposés, régénère le <strong>client secret</strong> dans la Google Cloud Console, mets à jour ton <code>.env</code>, puis redémarre le serveur.</p>`);
      }

      return res.status(500).send('Erreur OAuth : ' + (err.message || JSON.stringify(err)));
    }
    if (!user) {
      console.error('Aucun utilisateur retourné. Info:', info, 'Query:', req.query);
      return res.redirect('/');
    }
    req.logIn(user, (loginErr) => {
      if (loginErr) {
        console.error('Erreur login:', loginErr);
        return res.status(500).send('Erreur de connexion.');
      }
      res.redirect('/login-2fa');
    });
  })(req, res, next);
});

// Étape 2 : Page 2FA
app.get('/login-2fa', (req, res) => {
  res.sendFile(path.join(__dirname, 'login-2fa.html'));
});

// Vérification du code 2FA
app.post('/verify-2fa', (req, res) => {
  const secret = req.session.twoFASecret || process.env.TWOFA_SECRET;
  if (!secret) {
    console.error('verify-2fa: no secret available in session or env');
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
    return res.redirect('/download-cv');
  }

  res.send('<h2>❌ Code invalide, réessaie.</h2><a href="/login-2fa">Retour</a>');
});

// API: générer un secret 2FA et retourner le QR code (stocke le secret en session)
app.post('/api/2fa/generate', (req, res) => {
  try {
    const secret = speakeasy.generateSecret({ length: 20, name: `ViktorMorel` });
    // Stocker le secret pour la session en cours (pour tests/démo)
    req.session.twoFASecret = secret.base32;
    const otpauth = secret.otpauth_url;
    QRCode.toDataURL(otpauth)
      .then((dataUrl) => {
        res.json({ secret: secret.base32, otpauth_url: otpauth, qrCode: dataUrl });
      })
      .catch((err) => {
        console.error('QR generation error:', err);
        res.status(500).json({ error: 'QR generation failed' });
      });
  } catch (e) {
    console.error('2FA generate error:', e);
    res.status(500).json({ error: '2FA generate failed' });
  }
});

// API: vérifier le token 2FA (utilise le secret stocké en session ou le secret global)
app.post('/api/2fa/verify', (req, res) => {
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

// API: retourner le code TOTP courant (DEVELOPMENT ONLY)
// Activez l'accès en définissant ALLOW_TOTP_DISPLAY=true dans .env
app.get('/api/2fa/code', (req, res) => {
  const secret = req.session.twoFASecret || process.env.TWOFA_SECRET;
  if (!secret) return res.status(400).json({ error: 'secret_missing' });
  if (process.env.ALLOW_TOTP_DISPLAY !== 'true') return res.status(403).json({ error: 'not_allowed' });

  try {
    const token = speakeasy.totp({ secret: secret, encoding: 'base32' });
    return res.json({ token });
  } catch (err) {
    console.error('Error generating current token:', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// Étape 3 : Page protégée pour télécharger le CV
app.get('/download-cv', ensureAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'download.html'));
});

// Endpoint pour télécharger réellement le fichier (protégé)
app.get('/download-cv/file', ensureAuthenticated, (req, res) => {
  const fs = require('fs');
  // Prefer the DOCX file if present
  const docxPath = path.join(__dirname, 'Viktor Morel CV.docx');
  if (fs.existsSync(docxPath)) {
    return res.download(docxPath, 'Viktor Morel CV.docx', (err) => {
      if (err) {
        console.error('Erreur lors du téléchargement (docx):', err);
        res.status(500).send('Erreur lors du téléchargement.');
      }
    });
  }

  // Fallback to PDF
  const pdfPath = path.join(__dirname, 'cv.pdf');
  if (fs.existsSync(pdfPath)) {
    return res.download(pdfPath, 'Viktor_Morel_CV.pdf', (err) => {
      if (err) {
        console.error('Erreur lors du téléchargement (pdf):', err);
        res.status(500).send('Erreur lors du téléchargement.');
      }
    });
  }

  console.warn('download-cv: no CV file found');
  return res.status(404).send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CV introuvable</title><style>body{font-family:system-ui,Arial,sans-serif;background:#f6f8fb;color:#223;margin:0;padding:36px} .card{max-width:720px;margin:30px auto;background:white;padding:24px;border-radius:12px;box-shadow:0 8px 30px rgba(20,30,60,.08)}</style></head><body><div class="card"><h1>CV non disponible</h1><p>Le fichier <code>Viktor Morel CV.docx</code> ou <code>cv.pdf</code> est introuvable sur le serveur.</p><p>Veuillez déposer le fichier dans le répertoire du projet.</p></div></body></html>`);
});

// Page d’accueil
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Page d'aide pour configurer la 2FA localement (génère QR lié à la session)
app.get('/setup-2fa', (req, res) => {
  res.sendFile(path.join(__dirname, 'setup-2fa.html'));
});

// API: verifier si l'utilisateur est admin (apres 2FA)
app.get('/api/admin/check', ensureAuthenticated, (req, res) => {
  res.json({ isAdmin: isAdmin(req) });
});

// API: verifier si l'utilisateur est admin (avant 2FA, juste apres Google login)
app.get('/api/admin/check-login', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ isAdmin: false });
  }
  res.json({ isAdmin: isAdmin(req) });
});

// Page admin (protegee)
app.get('/admin', ensureAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// API: charger les donnees du site
app.get('/api/admin/data', ensureAdmin, (req, res) => {
  const data = loadSiteData();
  res.json(data);
});

// API: sauvegarder les donnees du site
app.post('/api/admin/save', ensureAdmin, (req, res) => {
  try {
    saveSiteData(req.body);
    res.json({ success: true, message: 'Donnees sauvegardees' });
  } catch (err) {
    console.error('Erreur sauvegarde:', err);
    res.status(500).json({ error: 'Erreur sauvegarde' });
  }
});

// Lancement serveur
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Serveur lancé sur http://localhost:${PORT}`);
});
