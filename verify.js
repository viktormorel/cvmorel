// netlify/functions/api/2fa/verify.js
const speakeasy = require("speakeasy");
const jwt = require("jsonwebtoken");

exports.handler = async (event) => {
  try {
    if (event.httpMethod !== "POST") {
      return {
        statusCode: 405,
        headers: { Allow: "POST" },
        body: JSON.stringify({ error: "Method Not Allowed" })
      };
    }

    const { token } = JSON.parse(event.body || "{}");
    if (!token || !/^\d{6}$/.test(token)) {
      return { statusCode: 400, body: JSON.stringify({ error: "Code invalide" }) };
    }

    const secret = process.env.TOTP_SECRET;
    const jwtSecret = process.env.JWT_SECRET;
    if (!secret || !jwtSecret) {
      return { statusCode: 500, body: JSON.stringify({ error: "Missing environment variables" }) };
    }

    // Vérification du code TOTP
    const valid = speakeasy.totp.verify({
      secret,
      encoding: "base32",
      token,
      window: 1
    });

    if (!valid) {
      return { statusCode: 401, body: JSON.stringify({ error: "Invalid 2FA code" }) };
    }

    // Lecture du cookie JWT existant
    const rawCookies = event.headers.cookie || "";
    const cookies = rawCookies.split(";").map(c => c.trim()).filter(Boolean);
    const sessionPair = cookies.find(c => c.startsWith("session="));
    if (!sessionPair) {
      return { statusCode: 401, body: JSON.stringify({ error: "No session cookie found" }) };
    }

    const oldToken = sessionPair.slice("session=".length);
    let payload;
    try {
      payload = jwt.verify(oldToken, jwtSecret);
    } catch (err) {
      return { statusCode: 401, body: JSON.stringify({ error: "Invalid session token" }) };
    }

    // Création d’un nouveau JWT avec twoFA:true
    const newToken = jwt.sign(
      { email: payload.email, googleId: payload.googleId, twoFA: true },
      jwtSecret,
      { expiresIn: "15m" }
    );

    // ✅ Réponse JSON + nouveau cookie
    return {
      statusCode: 200,
      headers: {
        "Set-Cookie": `session=${newToken}; HttpOnly; Secure; Path=/; SameSite=Lax`,
        "Cache-Control": "no-store"
      },
      body: JSON.stringify({ valid: true, redirect: "/admin.html" })
    };

  } catch (err) {
    console.error("❌ Erreur dans verify.js:", err);
    return { statusCode: 500, body: JSON.stringify({ error: "Erreur vérification", details: err.message }) };
  }
};

