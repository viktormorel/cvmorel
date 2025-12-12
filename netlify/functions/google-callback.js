// netlify/functions/api/auth/google-callback.js
exports.handler = async (event) => {
  const code = new URLSearchParams(event.queryStringParameters).get("code");

  // 🔎 Debug log pour vérifier que Google renvoie bien un code
  console.log("🔑 Code reçu du callback:", code);

  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  const redirectUri = process.env.GOOGLE_CALLBACK_URL;

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
  console.log("📦 Token Data:", tokenData);

  // 2️⃣ Récupération des infos utilisateur
  const userRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
    headers: { Authorization: `Bearer ${tokenData.access_token}` }
  });

  const userData = await userRes.json();
  console.log("👤 User Data:", userData);

  return {
    statusCode: 200,
    body: JSON.stringify({ tokenData, userData })
  };
};
