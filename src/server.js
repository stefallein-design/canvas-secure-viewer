// src/server.js
import express from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import { importJWK, exportJWK, jwtVerify, createRemoteJWKSet } from "jose";

const app = express();

// Body parsers (Canvas stuurt vaak form-encoded POSTs)
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// -------------------------
// Health check
// -------------------------
app.get("/", (req, res) => {
  res.status(200).send("OK - tool is running");
});

// -------------------------
// Tool JWKS endpoint (publieke sleutel van jouw tool)
// Canvas leest dit om jouw tool te vertrouwen (signing keys)
// -------------------------
app.get("/.well-known/jwks.json", async (req, res) => {
  try {
    const raw = process.env.TOOL_PRIVATE_JWK;
    if (!raw) {
      return res.status(500).json({
        error: "TOOL_PRIVATE_JWK missing in Render environment variables",
      });
    }

    const privateJwk = JSON.parse(raw);

    // private key importeren, en daaruit public jwk exporteren
    const key = await importJWK(privateJwk, "RS256");
    const jwk = await exportJWK(key);

    // Strip private velden (veiligheidsmaatregel)
    const { d, p, q, dp, dq, qi, oth, ...pub } = jwk;

    pub.kid = privateJwk.kid;
    pub.use = "sig";
    pub.alg = "RS256";

    res.json({ keys: [pub] });
  } catch (e) {
    res.status(500).json({ error: "Failed to build JWKS", details: String(e) });
  }
});

// -------------------------
// Canvas JWKS (om Canvas id_token te verifiëren)
// -------------------------
const canvasJwksUrl =
  process.env.CANVAS_JWKS_URL || "https://sso.canvaslms.com/api/lti/security/jwks";
const canvasJwks = createRemoteJWKSet(new URL(canvasJwksUrl));

// -------------------------
// OIDC initiation endpoint
// Canvas roept dit aan om de login-flow te starten
// -------------------------
app.get("/lti/oidc/init", (req, res) => {
  const { iss, login_hint, lti_message_hint, client_id, target_link_uri } =
    req.query;

  if (!iss || !login_hint || !lti_message_hint || !client_id || !target_link_uri) {
    return res.status(400).send("Missing required OIDC params");
  }

  // state & nonce beschermen tegen replay/CSRF
  const state = crypto.randomBytes(16).toString("hex");
  const nonce = crypto.randomBytes(16).toString("hex");

  // Bewaar state/nonce tijdelijk in cookies (MVP)
  // SameSite=None is nodig voor iframe-context in Canvas
  res.cookie("lti_state", state, { httpOnly: true, secure: true, sameSite: "none" });
  res.cookie("lti_nonce", nonce, { httpOnly: true, secure: true, sameSite: "none" });

  // Canvas OIDC authorize endpoint (Canvas cloud)
  const authorizeUrl = "https://sso.canvaslms.com/api/lti/authorize_redirect";

  // redirect_uri = jouw launch endpoint
  const redirectUri = `${req.protocol}://${req.get("host")}/lti/launch`;

  const params = new URLSearchParams({
    scope: "openid",
    response_type: "id_token",
    response_mode: "form_post",
    prompt: "none",
    client_id: String(client_id),
    redirect_uri: redirectUri,
    login_hint: String(login_hint),
    state,
    nonce,
    lti_message_hint: String(lti_message_hint),
  });

  res.redirect(`${authorizeUrl}?${params.toString()}`);
});

// -------------------------
// Launch endpoint
// Canvas POST hier een id_token (JWT) na OIDC
// -------------------------
app.post("/lti/launch", async (req, res) => {
  try {
    const { id_token, state } = req.body;

    if (!id_token || !state) {
      return res.status(400).send("Missing id_token or state");
    }

    // Check state cookie
    const expectedState = req.cookies.lti_state;
    const expectedNonce = req.cookies.lti_nonce;

    if (!expectedState || state !== expectedState) {
      return res.status(400).send("Invalid state");
    }

    // Als je later je Canvas client_id hebt, zet je dit aan:
    // const clientId = process.env.LTI_CLIENT_ID;
    // if (!clientId) return res.status(500).send("Missing LTI_CLIENT_ID env var");

    const { payload } = await jwtVerify(id_token, canvasJwks, {
      // audience: clientId,
      // issuer: "https://canvas.instructure.com" // pas later exact aan op jouw Canvas iss
    });

    // Nonce check (zit in payload.nonce)
    if (expectedNonce && payload.nonce && payload.nonce !== expectedNonce) {
      return res.status(400).send("Invalid nonce");
    }

    // LTI claims
    const roles = payload["https://purl.imsglobal.org/spec/lti/claim/roles"] || [];
    const context = payload["https://purl.imsglobal.org/spec/lti/claim/context"] || {};
    const messageType =
      payload["https://purl.imsglobal.org/spec/lti/claim/message_type"] || "";

    // Basic info
    const sub = payload.sub;
    const iss = payload.iss;
    const aud = payload.aud;

    res.status(200).send(`
      <h2>✅ LTI Launch OK</h2>
      <p>Je tool heeft een geldig Canvas <code>id_token</code> ontvangen en geverifieerd.</p>
      <hr/>
      <p><b>Issuer (iss):</b> ${iss}</p>
      <p><b>User (sub):</b> ${sub}</p>
      <p><b>Audience (aud):</b> ${Array.isArray(aud) ? aud.join(", ") : aud}</p>
      <p><b>Message type:</b> ${messageType}</p>
      <p><b>Roles:</b> ${
        Array.isArray(roles) ? roles.join(", ") : String(roles)
      }</p>
      <p><b>Context:</b> ${context?.title || ""} (${context?.id || ""})</p>
      <hr/>
      <p><i>Volgende stap:</i> hierna gaan we doorsturen naar de echte viewer en pagina-images streamen.</p>
    `);
  } catch (e) {
    res.status(401).send(`Launch verify failed: ${String(e)}`);
  }
});

// -------------------------
// Start server
// -------------------------
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});

