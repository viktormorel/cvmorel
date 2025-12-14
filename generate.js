// netlify/functions/api/2fa/generate.js
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");

exports.handler = async () => {
  try {
    // Génère un secret TOTP
    const secret = speakeasy.generateSecret({
      name: "Viktor Morel CV (2FA)",
      length: 20
    });

    // Génère l'otpauth URL
    const otpauthUrl = secret.otpauth_url;

    // Génère le QR code en base64
    const qrCodeDataUrl = await qrcode.toDataURL(otpauthUrl);

    return {
      statusCode: 200,
      body: JSON.stringify({
        secret: secret.base32,
        qrCode: qrCodeDataUrl
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
