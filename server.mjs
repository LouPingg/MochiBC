import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";

dotenv.config();

const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || "development";
const RAW_ORIGINS =
  process.env.CORS_ORIGINS ||
  "https://loupingg.github.io/Mochi,https://loupingg.github.io,http://127.0.0.1:5500,http://localhost:5500";
const ALLOWED_ORIGINS = RAW_ORIGINS.split(",").map((s) => s.trim());

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || "";

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const app = express();
app.use(express.json());
app.use(cookieParser());

/* ====== CORS ====== */
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.header("Access-Control-Allow-Origin", origin);
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

/* ====== Upload ====== */
const upload = multer({ storage: multer.memoryStorage() });

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

/* ====== AUTH ====== */
app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (username !== ADMIN_USERNAME)
    return res.status(401).json({ error: "bad credentials" });

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

/* ====== ALBUMS (Cloudinary-only) ====== */
app.get("/albums", async (_req, res) => {
  try {
    const result = await cloudinary.api.sub_folders("mochi");
    const albums = result.folders.map((f) => ({
      title: f.name,
      coverUrl: "",
      orientation: "portrait",
    }));

    // Ajoute la première image de chaque dossier comme cover
    for (const album of albums) {
      try {
        const imgs = await cloudinary.api.resources({
          type: "upload",
          prefix: `mochi/${album.title}/`,
          max_results: 1,
        });
        if (imgs.resources.length) {
          const img = imgs.resources[0];
          album.coverUrl = img.secure_url;
          album.orientation =
            img.width >= img.height ? "landscape" : "portrait";
        }
      } catch {}
    }

    res.json(albums);
  } catch (e) {
    console.error("List albums error:", e);
    res.status(500).json({ error: "Failed to list albums" });
  }
});

/* ====== Create album (with first photo as cover) ====== */
app.post("/albums", requireAdmin, upload.single("file"), async (req, res) => {
  try {
    const { title } = req.body || {};
    if (!title) return res.status(400).json({ error: "title required" });

    let coverUrl = "";
    let orientation = "portrait";

    if (req.file) {
      const result = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { folder: `mochi/${title}` },
          (err, uploadRes) => {
            if (err) reject(err);
            else resolve(uploadRes);
          }
        );
        stream.end(req.file.buffer);
      });
      coverUrl = result.secure_url;
      orientation = result.width >= result.height ? "landscape" : "portrait";
    }

    res.status(201).json({ title, coverUrl, orientation });
  } catch (e) {
    console.error("Create album error:", e);
    res.status(500).json({ error: e.message || "album create failed" });
  }
});

/* ====== Add photo to album ====== */
app.post(
  "/albums/:album/photos",
  requireAdmin,
  upload.single("file"),
  async (req, res) => {
    try {
      const album = req.params.album;
      if (!album) return res.status(400).json({ error: "album required" });
      if (!req.file) return res.status(400).json({ error: "file required" });

      const result = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { folder: `mochi/${album}` },
          (err, uploadRes) => {
            if (err) reject(err);
            else resolve(uploadRes);
          }
        );
        stream.end(req.file.buffer);
      });

      const orientation =
        result.width >= result.height ? "landscape" : "portrait";
      res.status(201).json({ url: result.secure_url, orientation });
    } catch (e) {
      console.error("Add photo error:", e);
      res.status(500).json({ error: e.message || "add photo failed" });
    }
  }
);

app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Server listening on 0.0.0.0:${PORT}`);
  console.log("CORS allowed:", ALLOWED_ORIGINS);
  console.log(`NODE_ENV: ${NODE_ENV}`);
});
// === Photos par album ===
app.get("/albums/:title/photos", async (req, res) => {
  try {
    const folder = `mochi/${req.params.title}`;
    const result = await cloudinary.api.resources({
      type: "upload",
      prefix: folder + "/",
      max_results: 100,
    });
    const list = result.resources.map((r) => ({
      id: r.public_id,
      url: r.secure_url,
      orientation: r.width >= r.height ? "landscape" : "portrait",
    }));
    res.json(list);
  } catch (err) {
    res.status(500).json({ error: "Failed to list photos" });
  }
});

// === Ajout photo à un album existant ===
app.post(
  "/albums/:title/photos",
  requireAdmin,
  upload.single("file"),
  async (req, res) => {
    try {
      const albumTitle = req.params.title;
      let fileUrl = req.body.url;
      let orient = req.body.orientation;

      if (req.file) {
        const up = await cloudUploadFromBuffer(
          req.file.buffer,
          `mochi/${albumTitle}`
        );
        fileUrl = up.secure_url;
        orient = up.width >= up.height ? "landscape" : "portrait";
      }

      if (!fileUrl) return res.status(400).json({ error: "no file or URL" });
      res.status(201).json({ url: fileUrl, orientation: orient });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);
