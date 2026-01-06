// netlify/functions/google-callback.mjs
import jwt from "jsonwebtoken";
import fetch from "node-fetch";

export const handler = async (event) => {
  try {
    const code = event.queryStringParameters?.code;
    if (!code) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "Missing authorization code" })
      };
    }

    const clientId = process.env.GOOGLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
    let redirectUri = process.env.GOOGLE_CALLBACK_URL || "https://viktor-vahe-morel-cv.netlify.app/.netlify/functions/api/auth/google/callback";
    const jwtSecret = process.env.JWT_SECRET;

    if (!clientId || !clientSecret || !redirectUri || !jwtSecret) {
      return {
        statusCode: 500,
        body: JSON.stringify({ error: "Missing environment variables" })
      };
    }

    // Nettoyage de l’URL de redirection
    redirectUri = redirectUri.trim().replace(/\/$/, "");

    // Échange du code contre un token
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
    if (!tokenRes.ok || !tokenData.access_token) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "Failed to exchange code", details: tokenData })
      };
    }

    // Infos utilisateur
    const userRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });

    const userData = await userRes.json();
    if (!userRes.ok || !userData.email) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "Failed to fetch user info", details: userData })
      };
    }

    // Création du JWT de session
    const sessionToken = jwt.sign(
      { email: userData.email, googleId: userData.id, twoFA: false },
      jwtSecret,
      { expiresIn: "15m" }
    );

    return {
      statusCode: 200,
      headers: {
        "Set-Cookie": `session=${sessionToken}; HttpOnly; Secure; Path=/; SameSite=Lax`,
        "Cache-Control": "no-store"
      },
      body: JSON.stringify({ success: true, redirect: "/login-2fa.html" })
    };
  } catch (err) {
    console.error("google-callback error:", err);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "Internal Server Error", details: err.message })
    };
  }
};







