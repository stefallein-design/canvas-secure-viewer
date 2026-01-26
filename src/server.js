import express from "express";
import cookieParser from "cookie-parser";
import { importJWK, exportJWK } from "jose";

const app = express();

// Canvas stuurt vaak form-encoded POSTs
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// Health check
app.get("/", (req, res) => {
  res.status(200).send("OK - tool is running");
});

// Placeholder routes (vullen we later in)
app.get("/lti/oidc/init", (req, res) => {
  res.status(200).send("OIDC init endpoint - coming next");
});

app.post("/lti/launch", (req, res) => {
  res.status(200).send("Launch endpoint - coming next");
});

const port = process.env.PORT || 3000;

// JWKS endpoint: Canvas gebruikt dit om jouw tool te vertrouwen
app.get("/.well-known/jwks.json", async (req, res) => {
  try {
    const raw = process.env.TOOL_PRIVATE_JWK;
    if (!raw) {
      return res.status(500).json({
        error: "TOOL_PRIVATE_JWK missing in Render environment variables"
      });
    }

    const privateJwk = JSON.parse(raw);

    // private key importeren, en daaruit public jwk exporteren
    const key = await importJWK(privateJwk, "RS256");
    const publicJwk = await exportJWK(key);

    // exportJWK geeft soms ook private velden terug afhankelijk van key-object;
    // daarom strippen we alles wat private kan zijn:
    const { d, p, q, dp, dq, qi, oth, ...pub } = publicJwk;

    pub.kid = privateJwk.kid;
    pub.use = "sig";
    pub.alg = "RS256";

    res.json({ keys: [pub] });
  } catch (e) {
    res.status(500).json({ error: "Failed to build JWKS", details: String(e) });
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
