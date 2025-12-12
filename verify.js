// netlify/functions/api/2fa/verify.js
const speakeasy = require("speakeasy");

exports.handler = async (event) => {
  try {
    const { token } = JSON.parse(event.body || "{}");

    if (!token || !/^\d{6}$/.test(token)) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "Code invalide" })
      };
    }

    // ⚠️ Pour test local : secret en dur
    const secret = "JBSWY3DPEHPK3PXP"; // à remplacer par celui généré dynamiquement si tu stockes en session

    const valid = speakeasy.totp.verify({
      secret,
      encoding: "base32",
      token,
      window: 1
    });

    return {
      statusCode: 200,
      body: JSON.stringify({ valid })
    };

  } catch (err) {
    console.error("❌ Erreur dans verify.js:", err);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "Erreur vérification", details: err.message })
    };
  }
};
