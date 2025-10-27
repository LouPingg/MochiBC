import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { nanoid } from "nanoid";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";

dotenv.config();

/* ========= ENV ========= */
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || "development";
const RAW_ORIGINS =
  process.env.CORS_ORIGINS ||
  "https://loupingg.github.io,http://127.0.0.1:5500,http://localhost:5500";
const ALLOWED_ORIGINS = RAW_ORIGINS.split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const JWT_SECRET = process.env.JWT_SECRET || "change_me_secret";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || "";
const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME;
const CLOUDINARY_API_KEY = process.env.CLOUDINARY_API_KEY;
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET;

/* ========= APP ========= */
const app = express();

/* ========= DEBUG: log all requests ========= */
app.use((req, res, next) => {
  console.log("📩 Request:", req.method, req.url, "from", req.headers.origin);
  next();
});

/* ========= CORS ========= */
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.header("Access-Control-Allow-Origin", origin);
    res.header("Vary", "Origin");
    res.header("Access-Control-Allow-Credentials", "true");
    res.header(
      "Access-Control-Allow-Headers",
      "Content-Type, Authorization, X-Requested-With"
    );
    res.header("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
  }
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
app.use(cors({ credentials: true, origin: ALLOWED_ORIGINS }));

app.use(express.json());
app.use(cookieParser());

/* ========= Cloudinary ========= */
const CLOUD_OK = !!(
  CLOUDINARY_CLOUD_NAME &&
  CLOUDINARY_API_KEY &&
  CLOUDINARY_API_SECRET
);
if (CLOUD_OK) {
  cloudinary.config({
    cloud_name: CLOUDINARY_CLOUD_NAME,
    api_key: CLOUDINARY_API_KEY,
    api_secret: CLOUDINARY_API_SECRET,
  });
}
const upload = multer({ storage: multer.memoryStorage() });

async function cloudUploadFromBuffer(buffer, folder = "mochi") {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder },
      (err, result) => {
        if (err || !result)
          return reject(err || new Error("Cloudinary upload failed"));
        resolve(result);
      }
    );
    stream.end(buffer);
  });
}

/* ========= Auth ========= */
function extractToken(req) {
  if (req.cookies?.token) return req.cookies.token;
  const h = req.headers.authorization || "";
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1] : null;
}

function requireAdmin(req, res, next) {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: "unauthorized" });
  try {
    jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "invalid token" });
  }
}

app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (username !== ADMIN_USERNAME)
    return res.status(401).json({ error: "bad credentials" });
  if (!ADMIN_PASSWORD_HASH)
    return res.status(500).json({ error: "ADMIN_PASSWORD_HASH missing" });

  const ok = await bcrypt.compare(password || "", ADMIN_PASSWORD_HASH);
  if (!ok) return res.status(401).json({ error: "bad credentials" });

  const token = jwt.sign({ role: "admin" }, JWT_SECRET, { expiresIn: "2h" });
  res.cookie("token", token, {
    httpOnly: true,
    sameSite: NODE_ENV === "production" ? "None" : "lax",
    secure: NODE_ENV === "production",
    maxAge: 2 * 60 * 60 * 1000,
  });
  res.json({ ok: true, token });
});

app.post("/auth/logout", (_req, res) => {
  res.clearCookie("token");
  res.json({ ok: true });
});

app.get("/auth/me", (req, res) => {
  const token = extractToken(req);
  if (!token) return res.json({ authenticated: false });
  try {
    jwt.verify(token, JWT_SECRET);
    res.json({ authenticated: true });
  } catch {
    res.json({ authenticated: false });
  }
});

/* ========= IMAGES ========= */
app.get("/images", async (_req, res) => {
  try {
    if (!CLOUD_OK)
      return res.status(400).json({ error: "Cloudinary not configured" });

    const result = await cloudinary.search
      .expression("folder:mochi")
      .sort_by("created_at", "desc")
      .max_results(100)
      .execute();

    const images = result.resources.map((r) => ({
      public_id: r.public_id,
      url: r.secure_url,
      width: r.width,
      height: r.height,
      created_at: r.created_at,
    }));

    res.json(images);
  } catch (err) {
    console.error("❌ /images failed:", err);
    res.status(500).json({ error: "Failed to fetch images" });
  }
});

/* ========= UPLOAD ========= */
app.post("/photos", requireAdmin, upload.single("file"), async (req, res) => {
  console.log("📸 POST /photos received", {
    hasFile: !!req.file,
    body: req.body,
  });
  try {
    let { url, orientation } = req.body || {};
    if (req.file) {
      if (!CLOUD_OK)
        return res.status(400).json({ error: "Cloudinary not configured" });
      const up = await cloudUploadFromBuffer(req.file.buffer, "mochi");
      url = up.secure_url;
      orientation = up.width >= up.height ? "landscape" : "portrait";
      console.log("✅ Cloudinary uploaded:", up.secure_url);
    }

    if (!url) return res.status(400).json({ error: "file or url required" });

    const photo = {
      id: nanoid(10),
      url,
      orientation: orientation || "landscape",
    };
    res.status(201).json(photo);
  } catch (e) {
    console.error("❌ Upload failed:", e);
    res.status(500).json({ error: e.message || "photo create failed" });
  }
});

/* ========= 404 ========= */
app.use((_req, res) =>
  res.status(404).type("text/plain").send("404 – Mochi backend (Express)")
);

/* ========= START ========= */
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Server listening on 0.0.0.0:${PORT}`);
  console.log("CORS allowed:", ALLOWED_ORIGINS);
  console.log(`Cloudinary configured: ${CLOUD_OK ? "yes" : "no"}`);
  console.log(`NODE_ENV: ${NODE_ENV}`);
});
