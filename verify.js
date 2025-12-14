// netlify/functions/api/2fa/verify.js
const speakeasy = require("speakeasy");
const jwt = require("jsonwebtoken");

exports.handler = async (event) => {
  try {
    // Autoriser uniquement POST
    if (event.httpMethod !== "POST") {
      return {
        statusCode: 405,
        headers: { Allow: "POST" },
        body: JSON.stringify({ valid: false, error: "Method Not Allowed" })
      };
    }

    // Parsing du body
    let body;
    try {
      body = JSON.parse(event.body || "{}");
    } catch {
      return { statusCode: 400, body: JSON.stringify({ valid: false, error: "Invalid JSON body" }) };
    }

    const token = body.token;
    if (!token || !/^\d{6}$/.test(token)) {
      return { statusCode: 400, body: JSON.stringify({ valid: false, error: "Code invalide" }) };
    }

    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      return { statusCode: 500, body: JSON.stringify({ valid: false, error: "Missing JWT_SECRET environment variable" }) };
    }

    // Lecture du cookie session
    const rawCookies = event.headers.cookie || "";
    const cookies = rawCookies.split(";").map(c => c.trim()).filter(Boolean);
    const sessionPair = cookies.find(c => c.startsWith("session="));
    if (!sessionPair) {
      return { statusCode: 401, body: JSON.stringify({ valid: false, error: "No session cookie found" }) };
    }

    const oldToken = sessionPair.slice("session=".length);
    let payload;
    try {
      payload = jwt.verify(oldToken, jwtSecret);
    } catch {
      return { statusCode: 401, body: JSON.stringify({ valid: false, error: "Invalid session token" }) };
    }

    if (!payload.twoFASecret) {
      return { statusCode: 400, body: JSON.stringify({ valid: false, error: "No 2FA secret in session" }) };
    }

    // Vérification du code TOTP
    const valid = speakeasy.totp.verify({
      secret: payload.twoFASecret,
      encoding: "base32",
      token,
      window: 1
    });

    if (!valid) {
      return { statusCode: 401, body: JSON.stringify({ valid: false, error: "Invalid 2FA code" }) };
    }

    // Nouveau JWT sans le secret, 2FA activé
    const newToken = jwt.sign(
      { email: payload.email, googleId: payload.googleId, twoFA: true },
      jwtSecret,
      { expiresIn: "15m" }
    );

    // Flags cookie: Secure seulement si HTTPS
    const isHttps = (event.headers["x-forwarded-proto"] || "").toLowerCase() === "https";
    const cookieFlags = ["HttpOnly", "Path=/", "SameSite=Lax"].concat(isHttps ? ["Secure"] : []).join("; ");

    return {
      statusCode: 200,
      headers: {
        "Set-Cookie": `session=${newToken}; ${cookieFlags}`,
        "Cache-Control": "no-store"
      },
      body: JSON.stringify({ valid: true, redirect: "/admin.html" })
    };

  } catch (err) {
    console.error("❌ Erreur dans verify.js:", err);
    return {
      statusCode: 500,
      body: JSON.stringify({ valid: false, error: "Erreur vérification", details: err.message })
    };
  }
};



