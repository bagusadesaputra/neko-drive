const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
require("dotenv").config(); // Load env vars immediately

const uploadRoute = require("./routes/upload");
const filesRoute = require("./routes/files");
const downloadRoute = require("./routes/download");
const logger = require("./utils/logger");

// --- Env Validation ---
const REQUIRED_ENV = [
  "DISCORD_BOT_TOKEN",
  "DISCORD_CHANNEL_ID",
  "SUPABASE_URL",
  "SUPABASE_KEY",
  "ENCRYPTION_KEY",
  "APP_PASSWORD" // ✅ tambahkan APP_PASSWORD
];

const missing = REQUIRED_ENV.filter(k => !process.env[k]);
if (missing.length > 0) {
  console.error(`❌ [CRITICAL] Missing Env Vars: ${missing.join(", ")}`);
  process.exit(1);
}

const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const app = express();

// --- Proxy Trust (Crucial for Vercel Rate Limiting) ---
if (process.env.NODE_ENV === "production") {
  app.set("trust proxy", 1);
}

// --- Tracing & Logging Middleware ---
app.use((req, res, next) => {
  req.id = crypto.randomBytes(4).toString("hex"); // Short unique ID
  logger.log(`[${req.id}] ${req.method} ${req.url}`);
  next();
});

// --- Security & Middleware ---
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);

app.use(cors({
  origin: process.env.NODE_ENV === "production" ? process.env.ALLOWED_ORIGIN : "*",
  methods: ["GET", "POST", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "x-app-password"]
}));

// --- Rate Limiting ---
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 2000,
  message: { error: "Too many requests, please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

const sensitiveLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 50,
  message: { error: "Action limit reached. Please wait before trying again." },
  standardHeaders: true,
  legacyHeaders: false,
});

// Body parser
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: true, limit: "100kb" }));

// --- Password Protection Middleware (Level 1) ---
function checkPassword(req, res, next) {
  const pw = req.headers["x-app-password"];
  if (!process.env.APP_PASSWORD) {
    console.warn("[WARNING] APP_PASSWORD env variable is not set.");
    return res.status(500).json({ error: "Server misconfiguration" });
  }
  if (!pw || pw !== process.env.APP_PASSWORD) {
    return res.status(401).json({ error: "Unauthorized: Invalid password" });
  }
  next();
}

// Apply password middleware to all routes except `/` and `/status`
app.use((req, res, next) => {
  if (req.path === "/" || req.path === "/status") return next();
  checkPassword(req, res, next);
});

// --- Routes ---
app.get("/", (req, res) => {
  res.json({
    status: "online",
    message: "Neko Drive Backend is Running 🐱☁️",
    version: "1.0.0",
  });
});

app.get("/status", (req, res) => {
  res.json({
    status: "online",
    storage: "supabase",
    serverTime: Date.now()
  });
});

// Apply sensitive limiter to heavy paths
app.use("/upload/finalize", sensitiveLimiter);
app.use("/upload/cancel", sensitiveLimiter);
app.use("/upload", uploadRoute);
app.use("/files/folder", sensitiveLimiter);
app.use("/files", filesRoute);
app.use("/download", downloadRoute);

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// Global Error Handler
app.use((err, req, res, next) => {
  logger.error(err.stack);
  res.status(500).json({ error: "Internal Server Error" });
});

const PORT = process.env.PORT || 3000;
const { storage } = require("./services/storage");

logger.log("[Startup] Initializing Neko Drive (Supabase Mode)...");

if (process.env.NODE_ENV !== "test") {
  storage.init().then(() => {
    app.listen(PORT, () => {
      logger.log(`Neko Drive backend running on http://localhost:${PORT}`);
    });
  });
}

module.exports = app;
