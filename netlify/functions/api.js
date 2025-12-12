// netlify/functions/api/auth/google.js
const querystring = require("querystring");

exports.handler = async () => {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const redirectUri = process.env.GOOGLE_CALLBACK_URL;
  const scope = ["openid", "email", "profile"].join(" ");

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
