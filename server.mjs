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
const NODE_ENV = process.env.NODE_ENV || "production";
const RAW_ORIGINS =
  process.env.CORS_ORIGINS ||
  "https://loupingg.github.io/Mochi,https://loupingg.github.io,http://127.0.0.1:5500,http://localhost:5500";
const ALLOWED_ORIGINS = RAW_ORIGINS.split(",").map((s) => s.trim());
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || "";

/* ========= CLOUDINARY ========= */
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});
const upload = multer({ storage: multer.memoryStorage() });

async function cloudUploadFromBuffer(buffer, folder) {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder },
      (err, result) => (err ? reject(err) : resolve(result))
    );
    stream.end(buffer);
  });
}

/* ========= APP ========= */
const app = express();
app.use(express.json());
app.use(cookieParser());

/* ========= CORS ========= */
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
  try {
    jwt.verify(token, JWT_SECRET);
    res.json({ authenticated: true });
  } catch {
    res.json({ authenticated: false });
  }
});

/* ========= ALBUMS ========= */
app.get("/albums", async (_req, res) => {
  try {
    const result = await cloudinary.api.sub_folders("mochi");
    const albums = await Promise.all(
      result.folders.map(async (f) => {
        const imgs = await cloudinary.api.resources({
          type: "upload",
          prefix: `mochi/${f.name}/`,
          max_results: 1,
        });
        const img = imgs.resources[0];
        return {
          title: f.name,
          coverUrl: img?.secure_url || "",
          orientation:
            img && img.width >= img.height ? "landscape" : "portrait",
        };
      })
    );
    res.json(albums);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to list albums" });
  }
});

app.post("/albums", requireAdmin, upload.single("file"), async (req, res) => {
  try {
    const { title } = req.body || {};
    if (!title) return res.status(400).json({ error: "title required" });
    const up = await cloudUploadFromBuffer(req.file.buffer, `mochi/${title}`);
    const orient = up.width >= up.height ? "landscape" : "portrait";
    res
      .status(201)
      .json({ title, coverUrl: up.secure_url, orientation: orient });
  } catch (err) {
    res.status(500).json({ error: "Album create failed" });
  }
});

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
  } catch {
    res.status(500).json({ error: "Failed to list photos" });
  }
});

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

/* ========= DELETE ========= */
app.delete("/photos/:id", requireAdmin, async (req, res) => {
  try {
    await cloudinary.uploader.destroy(req.params.id);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Failed to delete photo" });
  }
});

app.delete("/albums/:title", requireAdmin, async (req, res) => {
  try {
    const folder = `mochi/${req.params.title}`;
    const resources = await cloudinary.api.resources({
      type: "upload",
      prefix: folder + "/",
      max_results: 100,
    });
    for (const r of resources.resources)
      await cloudinary.uploader.destroy(r.public_id);
    await cloudinary.api.delete_folder(folder);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to delete album" });
  }
});

/* ========= START ========= */
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Server running on port ${PORT}`);
});
