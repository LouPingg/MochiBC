import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";

dotenv.config();

/* ========= ENV ========= */
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || "development";
const RAW_ORIGINS =
  process.env.CORS_ORIGINS ||
  "https://loupingg.github.io,http://127.0.0.1:5500,http://localhost:5500";
const ALLOWED_ORIGINS = RAW_ORIGINS.split(",").map((s) => s.trim());

const JWT_SECRET = process.env.JWT_SECRET || "change_me_secret";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || "";

const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME;
const CLOUDINARY_API_KEY = process.env.CLOUDINARY_API_KEY;
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET;

/* ========= APP ========= */
const app = express();
app.use(express.json());
app.use(cookieParser());

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

/* ========= Cloudinary ========= */
cloudinary.config({
  cloud_name: CLOUDINARY_CLOUD_NAME,
  api_key: CLOUDINARY_API_KEY,
  api_secret: CLOUDINARY_API_SECRET,
});
const upload = multer({ storage: multer.memoryStorage() });

async function uploadToCloudinary(buffer, folder) {
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

/* ========= AUTH ========= */
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
    res.status(401).json({ error: "invalid token" });
  }
}

app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (username !== ADMIN_USERNAME)
    return res.status(401).json({ error: "bad credentials" });
  if (!ADMIN_PASSWORD_HASH)
    return res.status(500).json({ error: "missing password hash" });

  const ok = await bcrypt.compare(password || "", ADMIN_PASSWORD_HASH);
  if (!ok) return res.status(401).json({ error: "bad credentials" });

  const token = jwt.sign({ role: "admin" }, JWT_SECRET, { expiresIn: "2h" });
  res.cookie("token", token, {
    httpOnly: true,
    sameSite: NODE_ENV === "production" ? "None" : "Lax",
    secure: NODE_ENV === "production",
    maxAge: 2 * 60 * 60 * 1000,
  });
  res.json({ ok: true, token });
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

/* ========= ALBUMS ========= */

/**
 * GET /albums
 * Liste tous les dossiers mochi/* (un dossier = un album)
 */
app.get("/albums", async (_req, res) => {
  try {
    const { resources } = await cloudinary.search
      .expression("folder:mochi/*")
      .sort_by("public_id", "desc")
      .max_results(100)
      .execute();

    // on récupère le premier fichier de chaque dossier
    const albums = {};
    for (const r of resources) {
      const folder = r.folder.split("/")[1];
      if (!albums[folder]) {
        albums[folder] = {
          title: folder,
          coverUrl: r.secure_url,
          orientation: r.width >= r.height ? "landscape" : "portrait",
        };
      }
    }

    res.json(Object.values(albums));
  } catch (e) {
    console.error("Error listing albums:", e);
    res.status(500).json({ error: "Failed to list albums" });
  }
});

/**
 * POST /albums
 * Crée un nouvel album avec sa première photo
 */
app.post("/albums", requireAdmin, upload.single("file"), async (req, res) => {
  try {
    const { title, url, orientation } = req.body || {};
    if (!title) return res.status(400).json({ error: "title required" });

    const folder = `mochi/${title.trim().replace(/\s+/g, "_")}`;
    let up;

    if (req.file) {
      up = await uploadToCloudinary(req.file.buffer, folder);
    } else if (url) {
      up = await cloudinary.uploader.upload(url, { folder });
    } else {
      return res.status(400).json({ error: "file or url required" });
    }

    res.status(201).json({
      title,
      coverUrl: up.secure_url,
      orientation:
        orientation || (up.width >= up.height ? "landscape" : "portrait"),
    });
  } catch (e) {
    console.error("Album create error:", e);
    res.status(500).json({ error: e.message || "album create failed" });
  }
});

/**
 * DELETE /albums/:title
 * Supprime un dossier (album complet)
 */
app.delete("/albums/:title", requireAdmin, async (req, res) => {
  try {
    const folder = `mochi/${req.params.title}`;
    await cloudinary.api.delete_resources_by_prefix(folder);
    await cloudinary.api.delete_folder(folder);
    res.json({ ok: true });
  } catch (e) {
    console.error("Album delete error:", e);
    res.status(500).json({ error: e.message || "delete failed" });
  }
});

/* ========= PHOTOS ========= */

/**
 * GET /photos
 * Liste toutes les photos (tous dossiers)
 */
app.get("/photos", async (_req, res) => {
  try {
    const { resources } = await cloudinary.search
      .expression("folder:mochi/*")
      .sort_by("public_id", "desc")
      .max_results(200)
      .execute();

    const imgs = resources.map((r) => ({
      id: r.public_id,
      url: r.secure_url,
      width: r.width,
      height: r.height,
      orientation: r.width >= r.height ? "landscape" : "portrait",
    }));

    res.json(imgs);
  } catch (e) {
    console.error("Error listing photos:", e);
    res.status(500).json({ error: "Failed to list photos" });
  }
});

/**
 * POST /photos
 * Ajoute une photo à un album existant
 */
app.post("/photos", requireAdmin, upload.single("file"), async (req, res) => {
  try {
    const { album, url, orientation } = req.body || {};
    if (!album) return res.status(400).json({ error: "album required" });

    const folder = `mochi/${album}`;
    let up;
    if (req.file) {
      up = await uploadToCloudinary(req.file.buffer, folder);
    } else if (url) {
      up = await cloudinary.uploader.upload(url, { folder });
    } else {
      return res.status(400).json({ error: "file or url required" });
    }

    res.status(201).json({
      url: up.secure_url,
      orientation:
        orientation || (up.width >= up.height ? "landscape" : "portrait"),
    });
  } catch (e) {
    console.error("Photo upload error:", e);
    res.status(500).json({ error: e.message || "photo upload failed" });
  }
});

/* ========= 404 ========= */
app.use((_req, res) =>
  res.status(404).type("text/plain").send("404 – Mochi backend (Express)")
);

console.log("Cloudinary config:", {
  cloud_name: CLOUDINARY_CLOUD_NAME,
  api_key: CLOUDINARY_API_KEY ? "OK" : "MISSING",
  api_secret: CLOUDINARY_API_SECRET ? "OK" : "MISSING",
});

/* ========= START ========= */
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Server listening on 0.0.0.0:${PORT}`);
  console.log("CORS allowed:", ALLOWED_ORIGINS);
  console.log(`NODE_ENV: ${NODE_ENV}`);
});
