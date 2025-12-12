// netlify/functions/api/auth/google.js
const querystring = require("querystring");

exports.handler = async () => {
  try {
    // ✅ Récupération des variables d'environnement
    const clientId = process.env.GOOGLE_CLIENT_ID;
    const redirectUri = process.env.GOOGLE_CALLBACK_URL; // doit être EXACTEMENT celui déclaré dans Google Cloud Console
    const scope = ["openid", "email", "profile"].join(" ");

    // 🔎 Vérification des variables
    if (!clientId || !redirectUri) {
      console.error("❌ Variables manquantes:", { clientId, redirectUri });
      return {
        statusCode: 500,
        body: JSON.stringify({
          error: "Missing environment variables",
          details: {
            GOOGLE_CLIENT_ID: clientId || "undefined",
            GOOGLE_CALLBACK_URL: redirectUri || "undefined"
          }
        })
      };
    }

    // ✅ Construction des paramètres OAuth
    const params = querystring.stringify({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: "code",
      scope,
      access_type: "offline",
      prompt: "consent"
    });

    const googleAuthUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params}`;

    // 🔎 Debug log pour vérifier l’URL générée
    console.log("🔗 Google Auth URL générée:", googleAuthUrl);

    // ✅ Redirection vers Google OAuth
    return {
      statusCode: 302,
      headers: {
        Location: googleAuthUrl
      }
    };

  } catch (err) {
    console.error("❌ Erreur dans google.js:", err);
    return {
      statusCode: 500,
      body: JSON.stringify({
        error: "Internal Server Error",
        details: err.message
      })
    };
  }
};



