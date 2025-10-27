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
const ALLOWED_ORIGINS = RAW_ORIGINS.split(",").map((s) => s.trim());

const JWT_SECRET = process.env.JWT_SECRET || "change_me_secret";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || "";
const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME;
const CLOUDINARY_API_KEY = process.env.CLOUDINARY_API_KEY;
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET;

/* ========= APP ========= */
const app = express();

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
cloudinary.config({
  cloud_name: CLOUDINARY_CLOUD_NAME,
  api_key: CLOUDINARY_API_KEY,
  api_secret: CLOUDINARY_API_SECRET,
});
const upload = multer({ storage: multer.memoryStorage() });

async function cloudUploadFromBuffer(buffer, folder) {
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

/* ========= ALBUMS (Cloudinary-only) ========= */

// Liste des albums
app.get("/albums", async (_req, res) => {
  try {
    // Vérifie ou crée le dossier racine
    let subFolders;
    try {
      const result = await cloudinary.api.sub_folders("mochi");
      subFolders = result.folders || [];
    } catch {
      console.log("[INIT] Creating base folder 'mochi' in Cloudinary…");
      await cloudinary.api.create_folder("mochi");
      subFolders = [];
    }

    // Si aucun sous-dossier → liste vide
    if (!subFolders.length) return res.json([]);

    // Pour chaque dossier → récupère 1 image (cover)
    const albums = await Promise.all(
      subFolders.map(async (f) => {
        const search = await cloudinary.search
          .expression(`folder:${f.path}`)
          .sort_by("created_at", "desc")
          .max_results(1)
          .execute()
          .catch(() => ({ resources: [] }));

        const cover = search.resources[0];
        return {
          title: f.name,
          coverUrl: cover?.secure_url || "",
          orientation: cover?.width >= cover?.height ? "landscape" : "portrait",
        };
      })
    );

    res.json(albums);
  } catch (e) {
    console.error("Error listing albums:", e);
    res.status(500).json({ error: "Failed to list albums" });
  }
});

// Création d’un album + première photo
app.post("/albums", requireAdmin, upload.single("file"), async (req, res) => {
  try {
    const { title, url, orientation } = req.body || {};
    if (!title) return res.status(400).json({ error: "title required" });

    const folder = `mochi/${title.replace(/\s+/g, "_")}`;
    let uploaded;

    if (req.file) {
      uploaded = await cloudUploadFromBuffer(req.file.buffer, folder);
    } else if (url) {
      uploaded = await cloudinary.uploader.upload(url, { folder });
    } else {
      return res.status(400).json({ error: "no image provided" });
    }

    const orient =
      orientation ||
      (uploaded.width >= uploaded.height ? "landscape" : "portrait");

    res.status(201).json({
      title,
      coverUrl: uploaded.secure_url,
      orientation: orient,
    });
  } catch (e) {
    console.error("Error creating album:", e);
    res.status(500).json({ error: "Failed to create album" });
  }
});

/* ========= PHOTOS (à venir) ========= */
// TODO: ajout/suppression de photos dans un album existant

/* ========= 404 ========= */
app.use((_req, res) =>
  res.status(404).type("text/plain").send("404 – Mochi backend (Express)")
);

/* ========= START ========= */
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Server listening on 0.0.0.0:${PORT}`);
  console.log("CORS allowed:", ALLOWED_ORIGINS);
  console.log(`NODE_ENV: ${NODE_ENV}`);
  console.log("Cloudinary config:", {
    cloud_name: CLOUDINARY_CLOUD_NAME,
    api_key: CLOUDINARY_API_KEY ? "OK" : "MISSING",
    api_secret: CLOUDINARY_API_SECRET ? "OK" : "MISSING",
  });
});
