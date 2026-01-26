// src/server.js (LTI 1.1 + secure image streaming)
import express from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import OAuth from "oauth-1.0a";
import fs from "fs";
import fsp from "fs/promises";
import path from "path";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// ---- Paths
const DATA_DIR = process.env.DATA_DIR || "/var/data";
const PDF_DIR = path.join(DATA_DIR, "pdfs");
const CACHE_DIR = path.join(DATA_DIR, "cache");

// Ensure dirs exist
async function ensureDirs() {
  await fsp.mkdir(PDF_DIR, { recursive: true });
  await fsp.mkdir(CACHE_DIR, { recursive: true });
}
ensureDirs().catch(() => {});

// ---- Helpers
function getBaseUrl(req) {
  const proto = (req.headers["x-forwarded-proto"] || req.protocol).split(",")[0];
  return `${proto}://${req.get("host")}`;
}

function buildOAuth() {
  const consumerKey = process.env.LTI11_CONSUMER_KEY;
  const consumerSecret = process.env.LTI11_SHARED_SECRET;

  if (!consumerKey || !consumerSecret) {
    throw new Error("Missing LTI11_CONSUMER_KEY or LTI11_SHARED_SECRET in env vars");
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

  if (req.body.lti_message_type !== "basic-lti-launch-request") {
    throw new Error("Not a basic LTI launch request");
  }
  if (!req.body.oauth_consumer_key || req.body.oauth_consumer_key !== consumerKey) {
    throw new Error("Invalid oauth_consumer_key");
  }
  if (!req.body.oauth_signature) {
    throw new Error("Missing oauth_signature");
  }

  // include query string if present
  const url = `${getBaseUrl(req)}${req.originalUrl}`;

  // exclude oauth_signature from base string params
  const data = { ...req.body };
  const providedSigRaw = data.oauth_signature;
  delete data.oauth_signature;

  const requestData = { url, method: "POST", data };
  const computed = oauth.authorize(requestData);
  const computedSig = computed.oauth_signature;

  const providedSig = decodeURIComponent(providedSigRaw);
  if (computedSig !== providedSig && computedSig !== providedSigRaw) {
    throw new Error("OAuth signature mismatch");
  }
  return true;
}

// ---- Signed auth cookie (no server memory needed)
const AUTH_SECRET = process.env.SV_AUTH_SECRET || process.env.LTI11_SHARED_SECRET || "dev-secret";

function makeAuthToken(payloadObj) {
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString("base64url");
  const sig = crypto.createHmac("sha256", AUTH_SECRET).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}

function readAuthToken(req) {
  const token = req.cookies.sv_auth;
  if (!token) return null;
  const [payload, sig] = token.split(".");
  if (!payload || !sig) return null;

  const expected = crypto.createHmac("sha256", AUTH_SECRET).update(payload).digest("base64url");
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;

  try {
    const obj = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (typeof obj.exp !== "number" || Date.now() > obj.exp) return null;
    return obj;
  } catch {
    return null;
  }
}

function requireAuth(req, res, next) {
  const auth = readAuthToken(req);
  if (!auth) return res.status(401).send("Not authorized");
  req.svAuth = auth;
  next();
}

// ---- PDF utilities
function pdfPathFor(doc) {
  return path.join(PDF_DIR, `${doc}.pdf`);
}
function docCacheDir(doc) {
  return path.join(CACHE_DIR, doc);
}
function pageCachePath(doc, pageNum) {
  return path.join(docCacheDir(doc), `page-${pageNum}.png`);
}

async function getPdfPageCount(pdfPath) {
  // pdfinfo output contains: "Pages:          12"
  const { stdout } = await execFileAsync("pdfinfo", [pdfPath]);
  const line = stdout.split("\n").find((l) => l.startsWith("Pages:"));
  if (!line) throw new Error("Could not read page count");
  const pages = parseInt(line.replace("Pages:", "").trim(), 10);
  if (!Number.isFinite(pages) || pages < 1) throw new Error("Invalid page count");
  return pages;
}

async function renderPageToCache(doc, pageNum) {
  const pdf = pdfPathFor(doc);
  if (!fs.existsSync(pdf)) throw new Error(`PDF not found for doc '${doc}'`);

  const outDir = docCacheDir(doc);
  await fsp.mkdir(outDir, { recursive: true });

  const outPrefix = path.join(outDir, `tmp-${pageNum}`);
  // pdftoppm output will be tmp-<page>-1.png (because it appends -1 etc.)
  await execFileAsync("pdftoppm", [
    "-f", String(pageNum),
    "-l", String(pageNum),
    "-png",
    "-r", "144",          // resolution: 144dpi (balance quality/perf)
    pdf,
    outPrefix
  ]);

  // Find generated file
  // pdftoppm usually outputs: `${outPrefix}-1.png`
  const generated = `${outPrefix}-1.png`;
  const target = pageCachePath(doc, pageNum);

  await fsp.rename(generated, target);
  return target;
}

// -------------------------
// Basics
// -------------------------
app.get("/", (req, res) => {
  res.status(200).send("OK - tool is running (LTI 1.1 + viewer)");
});

// -------------------------
// Admin upload (protected)
// -------------------------
app.get("/admin/upload", (req, res) => {
  const token = req.query.token || "";
  if (!process.env.ADMIN_UPLOAD_TOKEN || token !== process.env.ADMIN_UPLOAD_TOKEN) {
    return res.status(403).send("Forbidden");
  }

  res.send(`
    <h2>Upload PDF</h2>
    <form method="POST" action="/admin/upload?token=${encodeURIComponent(token)}" enctype="multipart/form-data">
      <label>Doc ID (bv H1): <input name="doc" required /></label><br/><br/>
      <input type="file" name="pdf" accept="application/pdf" required /><br/><br/>
      <button type="submit">Upload</button>
    </form>
  `);
});

// tiny multipart handler without extra libs: accept small PDFs only
// (later kunnen we multer toevoegen, maar dit is MVP)
app.post("/admin/upload", async (req, res) => {
  const token = req.query.token || "";
  if (!process.env.ADMIN_UPLOAD_TOKEN || token !== process.env.ADMIN_UPLOAD_TOKEN) {
    return res.status(403).send("Forbidden");
  }
  // For MVP simplicity, we require you to upload via Render Shell or add multer.
  // We'll implement multer next if you want file uploads in browser.
  res.status(501).send("Upload handler not enabled yet. Next step: add multer for real uploads.");
});

// -------------------------
// LTI 1.1 Launch → sets auth cookie → redirects to viewer
// -------------------------
app.post("/lti11/launch", (req, res) => {
  try {
    verifyLti11Launch(req);

    const roles = req.body.roles || "";
    const userId = req.body.user_id || "";
    const courseId = req.body.context_id || "";
    const courseTitle = req.body.context_title || "";

    const docFromCustom = req.body.custom_doc;
    const docFromQuery = req.query.doc;
    const doc = docFromQuery || docFromCustom || "default";

    // auth cookie valid for 15 minutes
    const token = makeAuthToken({
      exp: Date.now() + 15 * 60 * 1000,
      doc,
      userId,
      roles,
      courseId,
      courseTitle
    });

    res.cookie("sv_auth", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 15 * 60 * 1000,
    });

    res.redirect(`/viewer/${encodeURIComponent(doc)}`);
  } catch (e) {
    res.status(401).send(`LTI 1.1 launch rejected: ${String(e)}`);
  }
});

// -------------------------
// Viewer (HTML + JS)
// -------------------------
app.get("/viewer/:doc", requireAuth, async (req, res) => {
  const doc = req.params.doc;

  // Allow only Canvas to frame this (basic hardening)
  res.setHeader(
    "Content-Security-Policy",
    "frame-ancestors 'self' https://canvas.instructure.com https://*.instructure.com"
  );

  // Serve viewer HTML
  const htmlPath = path.join(process.cwd(), "src", "viewer", "viewer.html");
  res.type("html").send(await fsp.readFile(htmlPath, "utf8"));
});

app.get("/viewer/viewer.js", requireAuth, async (req, res) => {
  const jsPath = path.join(process.cwd(), "src", "viewer", "viewer.js");
  res.type("application/javascript").send(await fsp.readFile(jsPath, "utf8"));
});

// -------------------------
// API: manifest & pages
// -------------------------
app.get("/api/docs/:doc/manifest", requireAuth, async (req, res) => {
  try {
    const doc = req.params.doc;
    const pdf = pdfPathFor(doc);
    if (!fs.existsSync(pdf)) return res.status(404).json({ error: "PDF not found" });

    const pages = await getPdfPageCount(pdf);
    res.json({ doc, pages });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.get("/api/docs/:doc/page/:n", requireAuth, async (req, res) => {
  try {
    const doc = req.params.doc;
    const n = parseInt(req.params.n, 10);
    if (!Number.isFinite(n) || n < 1) return res.status(400).send("Invalid page number");

    const cached = pageCachePath(doc, n);
    if (!fs.existsSync(cached)) {
      await renderPageToCache(doc, n);
    }

    res.setHeader("Cache-Control", "private, no-store");
    res.type("image/png").send(await fsp.readFile(cached));
  } catch (e) {
    res.status(500).send(String(e));
  }
});

// -------------------------
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on port ${port}`));

