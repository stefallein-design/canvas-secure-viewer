// src/server.js (LTI 1.1 + secure image streaming + admin PDF upload + temp poppler debug)
import express from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import OAuth from "oauth-1.0a";
import multer from "multer";
import fs from "fs";
import fsp from "fs/promises";
import path from "path";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

const app = express();

// Canvas LTI 1.1 launch is a POST (form-encoded)
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// ---- Paths (Persistent Disk should be mounted at /var/data)
const DATA_DIR = process.env.DATA_DIR || "/var/data";
const PDF_DIR = path.join(DATA_DIR, "pdfs");
const CACHE_DIR = path.join(DATA_DIR, "cache");

// Ensure dirs exist
async function ensureDirs() {
  await fsp.mkdir(PDF_DIR, { recursive: true });
  await fsp.mkdir(CACHE_DIR, { recursive: true });
}
ensureDirs().catch(() => {});

// -------------------------
// Basics
// -------------------------
app.get("/", (req, res) => {
  res.status(200).send("OK - tool is running (LTI 1.1 + viewer)");
});

// TEMP DEBUG: check if poppler tools exist (pdfinfo)
app.get("/debug/poppler", async (req, res) => {
  try {
    const { stdout, stderr } = await execFileAsync("pdfinfo", ["-v"]);
    res.type("text").send(stdout || stderr || "pdfinfo returned no output");
  } catch (e) {
    res.status(500).type("text").send(String(e));
  }
});

// -------------------------
// Helpers
// -------------------------
function getBaseUrl(req) {
  // Render is behind a proxy; respect forwarded proto
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

  // URL must include query string if present
  const url = `${getBaseUrl(req)}${req.originalUrl}`;

  // Exclude oauth_signature itself from signature generation params
  const data = { ...req.body };
  const providedSigRaw = data.oauth_signature;
  delete data.oauth_signature;

  const requestData = { url, method: "POST", data };

  const computed = oauth.authorize(requestData);
  const computedSig = computed.oauth_signature;

  // Canvas often percent-encodes the signature
  const providedSig = decodeURIComponent(providedSigRaw);

  if (computedSig !== providedSig && computedSig !== providedSigRaw) {
    throw new Error("OAuth signature mismatch");
  }

  return true;
}

// ---- Stateless auth cookie (HMAC signed)
const AUTH_SECRET =
  process.env.SV_AUTH_SECRET || process.env.LTI11_SHARED_SECRET || "dev-secret";

function makeAuthToken(payloadObj) {
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString("base64url");
  const sig = crypto.createHmac("sha256", AUTH_SECRET).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}

function readAuthToken(req) {
  // 1) query token (meest robuust in iframe)
  const tokenFromQuery = req.query.t;
  if (typeof tokenFromQuery === "string" && tokenFromQuery.includes(".")) {
    return verifyAuthToken(tokenFromQuery);
  }

  // 2) Authorization header (optioneel)
  const authHeader = req.headers.authorization || "";
  if (authHeader.startsWith("Bearer ")) {
    const token = authHeader.slice("Bearer ".length).trim();
    const obj = verifyAuthToken(token);
    if (obj) return obj;
  }

  // 3) cookie (als cookies wél werken)
  const tokenFromCookie = req.cookies.sv_auth;
  if (typeof tokenFromCookie === "string" && tokenFromCookie.includes(".")) {
    return verifyAuthToken(tokenFromCookie);
  }

  return null;
}

function verifyAuthToken(token) {
  const [payload, sig] = token.split(".");
  if (!payload || !sig) return null;

  const expected = crypto.createHmac("sha256", AUTH_SECRET).update(payload).digest("base64url");
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  } catch {
    return null;
  }

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


// -------------------------
// PDF utilities
// -------------------------
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

  // Render exact 1 pagina
  await execFileAsync("pdftoppm", [
    "-f", String(pageNum),
    "-l", String(pageNum),
    "-png",
    "-r", "144",
    pdf,
    outPrefix
  ]);

  // pdftoppm kan outputten als tmp-<page>-<page>.png (bv tmp-2-2.png)
  // of tmp-<page>-1.png afhankelijk van versie.
  const files = await fsp.readdir(outDir);
  const base = path.basename(outPrefix); // bv "tmp-2"
  const candidates = files
    .filter((f) => f.startsWith(base + "-") && f.endsWith(".png"))
    .sort();

  if (candidates.length === 0) {
    throw new Error(`pdftoppm produced no PNG for doc='${doc}' page=${pageNum}`);
  }

  const generated = path.join(outDir, candidates[0]);
  const target = pageCachePath(doc, pageNum);

  // Als target al bestaat, overschrijven
  await fsp.rm(target, { force: true });
  await fsp.rename(generated, target);

  // Opruimen: als er om één of andere reden meerdere candidates zijn
  for (let i = 1; i < candidates.length; i++) {
    await fsp.rm(path.join(outDir, candidates[i]), { force: true });
  }

  return target;
}


// -------------------------
// Viewer files (served from repo)
// -------------------------
async function readViewerFile(relPath) {
  const p = path.join(process.cwd(), "src", "viewer", relPath);
  return await fsp.readFile(p, "utf8");
}

// -------------------------
// Admin upload (protected by token)
// -------------------------
app.get("/admin/upload", async (req, res) => {
  const token = req.query.token || "";
  if (!process.env.ADMIN_UPLOAD_TOKEN || token !== process.env.ADMIN_UPLOAD_TOKEN) {
    return res.status(403).send("Forbidden");
  }

  res.send(`
    <h2>Upload PDF</h2>
    <p>Gebruik exact dezelfde Doc ID als je in Canvas bij <code>custom_doc</code> zet (bv. H1).</p>
    <form method="POST" action="/admin/upload?token=${encodeURIComponent(
      token
    )}" enctype="multipart/form-data">
      <label>Doc ID: <input name="doc" required /></label><br/><br/>
      <input type="file" name="pdf" accept="application/pdf" required /><br/><br/>
      <button type="submit">Upload</button>
    </form>
  `);
});

const upload = multer({ limits: { fileSize: 50 * 1024 * 1024 } }); // 50MB

app.post("/admin/upload", upload.single("pdf"), async (req, res) => {
  const token = req.query.token || "";
  if (!process.env.ADMIN_UPLOAD_TOKEN || token !== process.env.ADMIN_UPLOAD_TOKEN) {
    return res.status(403).send("Forbidden");
  }

  const doc = (req.body.doc || "").trim();
  if (!doc) return res.status(400).send("Missing doc");
  if (!req.file) return res.status(400).send("Missing pdf file");

  await ensureDirs();

  const target = pdfPathFor(doc);
  await fsp.writeFile(target, req.file.buffer);

  // Clear cache for this doc
  await fsp.rm(docCacheDir(doc), { recursive: true, force: true });

  res.send(`✅ Uploaded ${doc}.pdf and cleared cache.`);
});

// -------------------------
// LTI 1.1 Launch → sets auth cookie → redirects to viewer
// -------------------------
app.post("/lti11/launch", (req, res) => {
  try {
    verifyLti11Launch(req);

    const roles = req.body.roles || "";
    const canvasUserId = req.body.custom_canvas_user_id || req.body.user_id || "";

const name =
  req.body.lis_person_name_full ||
  [req.body.lis_person_name_given, req.body.lis_person_name_family].filter(Boolean).join(" ") ||
  req.body.custom_canvas_user_name ||
  "";

    const courseId = req.body.context_id || "";
    const courseTitle = req.body.context_title || "";

    const docFromCustom = req.body.custom_doc;
    const docFromQuery = req.query.doc;
    const doc = docFromQuery || docFromCustom || "default";

    const name =
  req.body.lis_person_name_full ||
  [req.body.lis_person_name_given, req.body.lis_person_name_family].filter(Boolean).join(" ") ||
  req.body.custom_canvas_user_name ||
  "";

const token = makeAuthToken({
  exp: Date.now() + 15 * 60 * 1000,
  doc,
  userId: canvasUserId,
  name
});



    res.cookie("sv_auth", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 15 * 60 * 1000,
    });

    res.redirect(`/viewer/${encodeURIComponent(doc)}?t=${encodeURIComponent(token)}`);

  } catch (e) {
    res.status(401).send(`LTI 1.1 launch rejected: ${String(e)}`);
  }
});

// -------------------------
// Viewer (HTML + JS)
// Note: requires auth cookie.
// -------------------------
app.get("/viewer/:doc", requireAuth, async (req, res) => {
  // Basic hardening: allow framing only from Canvas domains
  res.setHeader(
    "Content-Security-Policy",
    "frame-ancestors 'self' https://canvas.instructure.com https://*.instructure.com"
  );

  res.type("html").send(await readViewerFile("viewer.html"));
});

app.get("/viewer/viewer.js", async (req, res) => {
  res.type("application/javascript").send(await readViewerFile("viewer.js"));
});

// -------------------------
// API: manifest & pages (requires auth cookie)
// -------------------------
app.get("/api/docs/:doc/manifest", requireAuth, async (req, res) => {
  try {
    const doc = req.params.doc;
    const pdf = pdfPathFor(doc);

    if (!fs.existsSync(pdf)) {
      return res.status(404).json({ error: "PDF not found. Upload it in /admin/upload" });
    }

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
    res.status(500).type("text").send(String(e));
  }
});

// Gives viewer the logged-in Canvas identity (for watermark)
app.get("/api/me", requireAuth, (req, res) => {
  res.json({
    userId: req.svAuth?.userId || "",
    name: req.svAuth?.name || ""
  });
});


// -------------------------
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on port ${port}`));
