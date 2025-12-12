// netlify/functions/api/auth/google-callback.js
const jwt = require("jsonwebtoken");

exports.handler = async (event) => {
  try {
    const code = new URLSearchParams(event.queryStringParameters).get("code");
    if (!code) {
      return { statusCode: 400, body: JSON.stringify({ error: "Missing authorization code" }) };
    }

    const clientId = process.env.GOOGLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
    const redirectUri = process.env.GOOGLE_CALLBACK_URL;
    const jwtSecret = process.env.JWT_SECRET;

    // 1️⃣ Échange du code contre un token
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: "authorization_code"
      })
    });
    const tokenData = await tokenRes.json();

    if (!tokenData.access_token) {
      return { statusCode: 400, body: JSON.stringify({ error: "Failed to retrieve access token", details: tokenData }) };
    }

    // 2️⃣ Récupération des infos utilisateur
    const userRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const userData = await userRes.json();

    // 3️⃣ Création d’un JWT avec l’email
    const sessionToken = jwt.sign(
      { email: userData.email, googleId: userData.id, twoFA: false },
      jwtSecret,
      { expiresIn: "15m" }
    );

    // ✅ Redirection vers /2fa avec cookie
    return {
      statusCode: 302,
      headers: {
        "Set-Cookie": `session=${sessionToken}; HttpOnly; Secure; Path=/; SameSite=Lax`,
        Location: "/2fa"
      }
    };

  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: "Internal Server Error", details: err.message }) };
  }
};
