// netlify/functions/api/2fa/generate.js
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");
const jwt = require("jsonwebtoken");

exports.handler = async () => {
  try {
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      return {
        statusCode: 500,
        body: JSON.stringify({ error: "Missing JWT_SECRET environment variable" })
      };
    }

    // Génère un secret TOTP
    const secret = speakeasy.generateSecret({
      name: "Viktor Morel CV (2FA)",
      length: 20
    });

    // Génère le QR code en base64
    const qrCodeDataUrl = await qrcode.toDataURL(secret.otpauth_url);

    // 🔑 Crée un JWT qui stocke le secret côté serveur
    const sessionToken = jwt.sign(
      { twoFASecret: secret.base32, twoFA: false },
      jwtSecret,
      { expiresIn: "15m" }
    );

    // ✅ Réponse avec cookie + QR code
    return {
      statusCode: 200,
      headers: {
        "Set-Cookie": `session=${sessionToken}; HttpOnly; Secure; Path=/; SameSite=Lax`,
        "Cache-Control": "no-store"
      },
      body: JSON.stringify({
        qrCode: qrCodeDataUrl
        // ⚠️ On ne renvoie pas le secret en clair pour la prod
      })
    };

  } catch (err) {
    console.error("❌ Erreur génération QR:", err);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "Erreur génération QR", details: err.message })
    };
  }
};

