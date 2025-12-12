// netlify/functions/api/auth/google.js
const querystring = require("querystring");

exports.handler = async (event, context) => {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const redirectUri = "https://cvviktormorel.netlify.app/.netlify/functions/api/auth/google/callback";
  const scope = [
    "openid",
    "email",
    "profile"
  ].join(" ");

  const params = querystring.stringify({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope,
    access_type: "offline",
    prompt: "consent"
  });

  const googleAuthUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params}`;

  return {
    statusCode: 302,
    headers: {
      Location: googleAuthUrl
    }
  };
};