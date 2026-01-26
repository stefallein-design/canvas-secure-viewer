// src/server.js (LTI 1.1 MVP)
import express from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import OAuth from "oauth-1.0a";

const app = express();

// Canvas LTI 1.1 launch is a POST (form-encoded)
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

app.get("/", (req, res) => {
  res.status(200).send("OK - tool is running (LTI 1.1 mode)");
});

// Helpers
function getBaseUrl(req) {
  // Render is behind a proxy; respect forwarded proto
  const proto = (req.headers["x-forwarded-proto"] || req.protocol).split(",")[0];
  return `${proto}://${req.get("host")}`;
}

function buildOAuth() {
  const consumerKey = process.env.LTI11_CONSUMER_KEY;
  const consumerSecret = process.env.LTI11_SHARED_SECRET;

  if (!consumerKey || !consumerSecret) {
    throw new Error("Missing LTI11_CONSUMER_KEY or LTI11_SHARED_SECRET in environment variables");
  }

  return {
    consumerKey,
    oauth: new OAuth({
      consumer: { key: consumerKey, secret: consumerSecret },
      signature_method: "HMAC-SHA1",
      hash_function(baseString, key) {
        return crypto.createHmac("sha1", key).update(baseString).digest("base64");
      },
    }),
  };
}

function verifyLti11Launch(req) {
  const { consumerKey, oauth } = buildOAuth();

  // 1) Check required LTI fields
  if (req.body.lti_message_type !== "basic-lti-launch-request") {
    throw new Error("Not a basic LTI launch request");
  }
  if (!req.body.oauth_consumer_key || req.body.oauth_consumer_key !== consumerKey) {
    throw new Error("Invalid oauth_consumer_key");
  }
  if (!req.body.oauth_signature) {
    throw new Error("Missing oauth_signature");
  }

  // 2) URL must include query string if present (e.g. ?doc=H1)
  const url = `${getBaseUrl(req)}${req.originalUrl}`;

  // 3) For signature generation, exclude oauth_signature itself from parameters
  const data = { ...req.body };
  const providedSigRaw = data.oauth_signature;
  delete data.oauth_signature;

  const requestData = { url, method: "POST", data };

  // 4) Compute signature and compare
  const computed = oauth.authorize(requestData);
  const computedSig = computed.oauth_signature;

  // Canvas often percent-encodes the signature
  const providedSig = decodeURIComponent(providedSigRaw);

  if (computedSig !== providedSig && computedSig !== providedSigRaw) {
    throw new Error("OAuth signature mismatch");
  }

  return true;
}

// LTI 1.1 Launch endpoint
app.post("/lti11/launch", (req, res) => {
  try {
    verifyLti11Launch(req);

    // Minimal “identity”
    const roles = req.body.roles || "";
    const userId = req.body.user_id || "";
    const courseId = req.body.context_id || "";
    const courseTitle = req.body.context_title || "";

    // Doc id: we support ?doc=... in the launch URL OR custom_doc param
    // If you add "?doc=H1" to the tool URL in Canvas, it arrives in the launch URL query
    // (Canvas may also send custom params as "custom_*")
    const doc = req.query.doc || req.body.custom_doc || "default";

    // Create a short-lived session cookie (so later we can stream images securely)
    const session = crypto.randomBytes(18).toString("hex");
    res.cookie("sv_session", session, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 10 * 60 * 1000, // 10 min
    });

    res.status(200).send(`
      <h2>✅ LTI 1.1 Launch OK</h2>
      <p><b>Doc:</b> ${doc}</p>
      <p><b>User:</b> ${userId}</p>
      <p><b>Roles:</b> ${roles}</p>
      <p><b>Course:</b> ${courseTitle} (${courseId})</p>
      <hr/>
      <p>Volgende stap: hier vervangen we deze pagina door de echte viewer en gaan we pagina-afbeeldingen streamen.</p>
    `);
  } catch (e) {
    res.status(401).send(`LTI 1.1 launch rejected: ${String(e)}`);
  }
});

// Start server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});

