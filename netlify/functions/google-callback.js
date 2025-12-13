// netlify/functions/api/auth/google-callback.js
const jwt = require("jsonwebtoken");
const fetch = (...args) => import("node-fetch").then(({ default: fetch }) => fetch(...args));

exports.handler = async (event) => {
  try {
    // 🔎 Lecture du code Google
    const code = event.queryStringParameters?.code;
    if (!code) {
      console.error("❌ Aucun code reçu dans le callback");
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "Missing authorization code" })
      };
    }
    console.log("🔑 Code reçu du callback:", code);

    // ✅ Variables d'environnement
    const clientId = process.env.GOOGLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
    let redirectUri = process.env.GOOGLE_CALLBACK_URL; 
    const jwtSecret = process.env.JWT_SECRET;

    if (!clientId || !clientSecret || !redirectUri || !jwtSecret) {
      console.error("❌ Variables manquantes:", { clientId, clientSecret, redirectUri, jwtSecret });
      return {
        statusCode: 500,
        body: JSON.stringify({ error: "Missing environment variables" })
      };
    }

    // ✅ Normalisation stricte du redirectUri
    redirectUri = redirectUri.trim();
    if (redirectUri.endsWith("/")) {
      redirectUri = redirectUri.slice(0, -1);
    }

    // 1️⃣ Échange du code contre un token
    let tokenData;
    try {
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

      const rawToken = await tokenRes.text();
      if (!tokenRes.ok) {
        console.error("❌ Échec échange token:", rawToken);
        return {
          statusCode: 400,
          body: JSON.stringify({ error: "Failed to exchange code", details: rawToken })
        };
      }
      tokenData = JSON.parse(rawToken);
    } catch (err) {
      console.error("❌ Erreur lors de l’échange du token:", err);
      return {
        statusCode: 500,
        body: JSON.stringify({ error: "Token exchange failed", details: err.message })
      };
    }

    if (!tokenData.access_token) {
      console.error("❌ Pas d'access_token:", tokenData);
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "No access_token", details: tokenData })
      };
    }

    // 2️⃣ Récupération des infos utilisateur
    let userData;
    try {
      const userRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
        headers: { Authorization: `Bearer ${tokenData.access_token}` }
      });

      const rawUser = await userRes.text();
      if (!userRes.ok) {
        console.error("❌ Échec récupération user:", rawUser);
        return {
          statusCode: 400,
          body: JSON.stringify({ error: "Failed to fetch user info", details: rawUser })
        };
      }
      userData = JSON.parse(rawUser);
    } catch (err) {
      console.error("❌ Erreur lors de la récupération user:", err);
      return {
        statusCode: 500,
        body: JSON.stringify({ error: "User info fetch failed", details: err.message })
      };
    }

    if (!userData.email) {
      console.error("❌ Email utilisateur manquant:", userData);
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "No user email found", details: userData })
      };
    }

    // 3️⃣ Création du JWT
    const sessionToken = jwt.sign(
      { email: userData.email, googleId: userData.id, twoFA: false },
      jwtSecret,
      { expiresIn: "15m" }
    );

    // ✅ Redirection vers login-2fa.html avec cookie sécurisé
    return {
      statusCode: 302,
      headers: {
        "Set-Cookie": `session=${sessionToken}; HttpOnly; Secure; Path=/; SameSite=Lax`,
        "Cache-Control": "no-store",
        Location: "/login-2fa.html"
      }
    };

  } catch (err) {
    console.error("❌ Erreur interne:", err);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "Internal Server Error", details: err.message })
    };
  }
};



