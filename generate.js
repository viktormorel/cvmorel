// netlify/functions/api/2fa/generate.js
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");

exports.handler = async () => {
  try {
    const secret = speakeasy.generateSecret({ length: 20 });

    const otpauth = secret.otpauth_url;
    const qrCode = await qrcode.toDataURL(otpauth);

    return {
      statusCode: 200,
      body: JSON.stringify({
        secret: secret.base32,
        qrCode
      })
    };
  } catch (err) {
    console.error("❌ Erreur dans generate.js:", err);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "Erreur génération QR", details: err.message })
    };
  }
};