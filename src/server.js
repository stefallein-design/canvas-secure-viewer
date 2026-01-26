// src/server.js (LTI 1.1 + secure image streaming + admin PDF upload + /api/me watermark + slug-based doc ids)
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
// Slug / canonical doc id
// -------------------------
function canonicalDocId(input) {
  // decode if it's URL-encoded (viewer path like wiskunde%201%20-%20integraal)
  let s = String(input || "");
  try {
    s = decodeURIComponent(s);
  } catch {
    // ignore decode errors
  }

  s = s
    .trim()
    .toLowerCase()
    // remove common HTML entity patterns that sometimes sneak in
    .replace(/&\d+/g, "")       // e.g. &201
    .replace(/&[a-z]+;/g, "")   // e.g. &nbsp;
    // make file-safe slug
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "");

  return s || "default";
}

// -------------------------
// Basics / health
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

// -------------------------
// Stateless auth token (HMAC signed) + auth middleware
// Token can be passed via ?t=... or cookie sv_auth
// -------------------------
const AUTH_SECRET =
  process.env.SV_AUTH_SECRET || process.env.LTI11_SHARED_SECRET || "dev-secret";

function makeAuthToken(payloadObj) {
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString("base64url");
  const sig = crypto.createHmac("sha256", AUTH_SECRET).update(payload).digest("base64url");
  return `${payload}.${sig}`;
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

function readAuthToken(req) {
  // 1) query token (most robust inside iframes)
  const tokenFromQuery = req.query.t;
  if (typeof tokenFromQuery === "string" && tokenFromQuery.includes(".")) {
    const obj = verifyAuthToken(tokenFromQuery);
    if (obj) return obj;
  }

  // 2) Authorization header (optional)
  const authHeader = req.headers.authorization || "";
  if (authHeader.startsWith("Bearer ")) {
    const token = authHeader.slice("Bearer ".length).trim();
    const obj = verifyAuthToken(token);
    if (obj) return obj;
  }

  // 3) cookie (if allowed)
  const tokenFromCookie = req.cookies.sv_auth;
  if (typeof tokenFromCookie === "string" && tokenFromCookie.includes(".")) {
    const obj = verifyAuthToken(tokenFromCookie);
    if (obj) return obj;
  }

  return null;
}

function requireAuth(req, res, next) {
  const auth = readAuthToken(req);
  if (!auth) return res.status(401).send("Not authorized");
  req.svAuth = auth;
  next();
}

// -------------------------
// PDF utilities (poppler)
// -------------------------
function pdfPathFor(docRaw) {
  const doc = canonicalDocId(docRaw);
  return path.join(PDF_DIR, `${doc}.pdf`);
}
function docCacheDir(docRaw) {
  const doc = canonicalDocId(docRaw);
  return path.join(CACHE_DIR, doc);
}
function pageCachePath(docRaw, pageNum) {
  const doc = canonicalDocId(docRaw);
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

async function renderPageToCache(docRaw, pageNum) {
  const doc = canonicalDocId(docRaw);
  const pdf = pdfPathFor(doc);
  if (!fs.existsSync(pdf)) throw new Error(`PDF not found for doc '${doc}'`);

  const outDir = docCacheDir(doc);
  await fsp.mkdir(outDir, { recursive: true });

  const outPrefix = path.join(outDir, `tmp-${pageNum}`);

  // Render exactly one page
  await execFileAsync("pdftoppm", [
    "-f",
    String(pageNum),
    "-l",
    String(pageNum),
    "-png",
    "-r",
    "144",
    pdf,
    outPrefix,
  ]);

  // pdftoppm output naming differs by version; find the PNG dynamically
  const files = await fsp.readdir(outDir);
  const base = path.basename(outPrefix); // e.g. "tmp-2"
  const candidates = files
    .filter((f) => f.startsWith(base + "-") && f.endsWith(".png"))
    .sort();

  if (candidates.length === 0) {
    throw new Error(`pdftoppm produced no PNG for doc='${doc}' page=${pageNum}`);
  }

  const generated = path.join(outDir, candidates[0]);
  const target = pageCachePath(doc, pageNum);

  await fsp.rm(target, { force: true });
  await fsp.rename(generated, target);

  // Clean up any leftovers
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
// Upload doc id is ALSO canonicalized to the same slug used by Canvas
// -------------------------
app.get("/admin/upload", async (req, res) => {
  const token = req.query.token || "";
  if (!process.env.ADMIN_UPLOAD_TOKEN || token !== process.env.ADMIN_UPLOAD_TOKEN) {
    return res.status(403).send("Forbidden");
  }

  res.send(`
    <h2>Upload PDF</h2>
    <p><b>Doc ID</b> mag een titel zijn (met spaties). Wij maken er automatisch een veilige slug van.</p>
    <form method="POST" action="/admin/upload?token=${encodeURIComponent(
      token
    )}" enctype="multipart/form-data">
      <label>Doc ID / titel: <input name="doc" required /></label><br/><br/>
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

  const docSlug = canonicalDocId(req.body.doc);
  if (!docSlug) return res.status(400).send("Missing doc");
  if (!req.file) return res.status(400).send("Missing pdf file");

  await ensureDirs();

  const target = pdfPathFor(docSlug);
  await fsp.writeFile(target, req.file.buffer);

  // Clear cache for this doc
  await fsp.rm(docCacheDir(docSlug), { recursive: true, force: true });

  res.send(`✅ Uploaded ${docSlug}.pdf and cleared cache.`);
});

// -------------------------
// Admin: list + delete (protected by ADMIN_UPLOAD_TOKEN)
// -------------------------
app.get("/admin", async (req, res) => {
  const token = req.query.token || "";
  if (!process.env.ADMIN_UPLOAD_TOKEN || token !== process.env.ADMIN_UPLOAD_TOKEN) {
    return res.status(403).send("Forbidden");
  }

  await ensureDirs();

  const files = (await fsp.readdir(PDF_DIR)).filter((f) => f.toLowerCase().endsWith(".pdf")).sort();

  const rows = files
    .map((f) => {
      const doc = f.replace(/\.pdf$/i, "");
      const delUrl = `/admin/delete?token=${encodeURIComponent(token)}&doc=${encodeURIComponent(doc)}`;
      const viewUrl = `/viewer/${encodeURIComponent(doc)}?t=${encodeURIComponent(
        makeAuthToken({
          exp: Date.now() + 5 * 60 * 1000, // 5 min admin view token
          doc,
          userId: "ADMIN",
          name: "Admin",
        })
      )}`;

      return `
        <tr>
          <td><code>${doc}</code></td>
          <td><a href="${viewUrl}" target="_blank" rel="noopener">Open viewer</a></td>
          <td><a href="${delUrl}" onclick="return confirm('Delete ${doc}.pdf?')">Delete</a></td>
        </tr>
      `;
    })
    .join("");

  res.type("html").send(`
    <h2>Admin – PDF Library</h2>
    <p><a href="/admin/upload?token=${encodeURIComponent(token)}">➕ Upload new PDF</a></p>
    <table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse;">
      <thead>
        <tr>
          <th>Doc ID (slug / filename)</th>
          <th>Viewer</th>
          <th>Delete</th>
        </tr>
      </thead>
      <tbody>
        ${rows || `<tr><td colspan="3">No PDFs found.</td></tr>`}
      </tbody>
    </table>
  `);
});

app.get("/admin/delete", async (req, res) => {
  const token = req.query.token || "";
  if (!process.env.ADMIN_UPLOAD_TOKEN || token !== process.env.ADMIN_UPLOAD_TOKEN) {
    return res.status(403).send("Forbidden");
  }

  await ensureDirs();

  // doc can be either slug or original-ish; we canonicalize to be safe
  const doc = canonicalDocId(req.query.doc || "");
  if (!doc) return res.status(400).send("Missing doc");

  const pdf = path.join(PDF_DIR, `${doc}.pdf`);
  const cache = path.join(CACHE_DIR, doc);

  await fsp.rm(pdf, { force: true });
  await fsp.rm(cache, { recursive: true, force: true });

  // back to admin list
  res.redirect(`/admin?token=${encodeURIComponent(token)}`);
});


// -------------------------
// LTI 1.1 Launch → verify → set token cookie + redirect to viewer with ?t=...
// Doc is canonicalized so Canvas encoding never breaks lookup
// -------------------------
app.post("/lti11/launch", (req, res) => {
  try {
    verifyLti11Launch(req);

    const docFromCustom = req.body.custom_doc;
    const docFromQuery = req.query.doc;
    const doc = canonicalDocId(docFromQuery || docFromCustom || "default");

    // ID priority (as you requested)
    const canvasUserId = req.body.custom_canvas_user_id || req.body.user_id || "";

    const canvasName =
      req.body.lis_person_name_full ||
      [req.body.lis_person_name_given, req.body.lis_person_name_family]
        .filter(Boolean)
        .join(" ") ||
      req.body.custom_canvas_user_name ||
      "";

    const token = makeAuthToken({
      exp: Date.now() + 15 * 60 * 1000,
      doc,
      userId: canvasUserId,
      name: canvasName,
    });

    // Cookie (optional)
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
// API: "me" (for watermark) — only name + userId
// -------------------------
app.get("/api/me", requireAuth, (req, res) => {
  res.json({
    userId: req.svAuth?.userId || "",
    name: req.svAuth?.name || "",
  });
});

// -------------------------
// Viewer (HTML) — requires auth
// -------------------------
app.get("/viewer/:doc", requireAuth, async (req, res) => {
  // Allow framing only from Canvas domains
  res.setHeader(
    "Content-Security-Policy",
    "frame-ancestors 'self' https://canvas.instructure.com https://*.instructure.com"
  );

  res.type("html").send(await readViewerFile("viewer.html"));
});

// -------------------------
// API: manifest & pages (requires auth)
// IMPORTANT: doc param is canonicalized so URLs with weird encoding still map correctly
// -------------------------
app.get("/api/docs/:doc/manifest", requireAuth, async (req, res) => {
  try {
    const doc = canonicalDocId(req.params.doc);
    const pdf = pdfPathFor(doc);

    if (!fs.existsSync(pdf)) {
      return res.status(404).json({
        error:
          "PDF not found. Upload it in /admin/upload. (Doc ID is slug-normalized automatically.)",
        doc,
      });
    }

    const pages = await getPdfPageCount(pdf);
    res.json({ doc, pages });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.get("/api/docs/:doc/page/:n", requireAuth, async (req, res) => {
  try {
    const doc = canonicalDocId(req.params.doc);
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

// -------------------------
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on port ${port}`));

