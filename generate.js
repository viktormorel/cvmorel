const speakeasy = require("speakeasy");
const qrcode = require("qrcode");
const jwt = require("jsonwebtoken");

exports.handler = async (event) => {
  try {
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) return { statusCode: 500, body: JSON.stringify({ error: "Missing JWT_SECRET" }) };

    // Lire session existante
    const rawCookies = event.headers.cookie || "";
    const cookies = rawCookies.split(";").map(c => c.trim()).filter(Boolean);
    const sessionPair = cookies.find(c => c.startsWith("session="));
    let basePayload = {};
    if (sessionPair) {
      const oldToken = sessionPair.slice("session=".length);
      try { basePayload = jwt.verify(oldToken, jwtSecret) || {}; } catch {}
    }

    // Générer secret et QR
    const secret = speakeasy.generateSecret({ name: "Viktor Morel CV (2FA)", length: 20 });
    const qrCodeDataUrl = await qrcode.toDataURL(secret.otpauth_url);

    // Nouveau JWT avec secret
    const sessionToken = jwt.sign(
      {
        email: basePayload.email,
        googleId: basePayload.googleId,
        twoFA: false,
        twoFASecret: secret.base32
      },
      jwtSecret,
      { expiresIn: "15m" }
    );

    return {
      statusCode: 200,
      headers: {
        "Set-Cookie": `session=${sessionToken}; HttpOnly; Secure; Path=/; SameSite=Lax`,
        "Cache-Control": "no-store"
      },
      body: JSON.stringify({ qrCode: qrCodeDataUrl })
    };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: "Erreur génération QR", details: err.message }) };
  }
};

