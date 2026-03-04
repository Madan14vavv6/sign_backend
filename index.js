import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import crypto from "crypto";
import { z } from "zod";
import { initDb, dbEnabled, findUserByEmail, insertUser } from "./db.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;
const isProd = process.env.NODE_ENV === "production";
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  if (isProd) {
    throw new Error("JWT_SECRET is required in production");
  }
  JWT_SECRET = crypto.randomBytes(32).toString("hex");
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "10kb" }));

const corsOrigin = process.env.CORS_ORIGIN || "http://localhost:5173";
app.use(
  cors({
    origin: corsOrigin,
    methods: ["GET", "POST"],
    credentials: true,
  })
);

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: "draft-7",
  legacyHeaders: false,
});
app.use("/api/", limiter);

const users = new Map();

const signupSchema = z.object({
  username: z.string().min(1).max(50),
  email: z.string().email(),
  phone: z.string().regex(/^\d{10}$/),
  password: z.string().min(6).max(128),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6).max(128),
});

app.post("/api/signup", async (req, res) => {
  const parse = signupSchema.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: "Invalid input", details: parse.error.flatten() });
  }
  const { username, email, phone, password } = parse.data;
  if (dbEnabled()) {
    const existing = await findUserByEmail(email);
    if (existing) {
      return res.status(409).json({ error: "Email already registered" });
    }
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    await insertUser({ username, email, phone, passwordHash });
    return res.status(201).json({ message: "Signup successful", user: { username, email, phone } });
  } else {
    if (users.has(email)) {
      return res.status(409).json({ error: "Email already registered" });
    }
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    const user = { username, email, phone, passwordHash };
    users.set(email, user);
    return res.status(201).json({ message: "Signup successful", user: { username, email, phone } });
  }
});

app.post("/api/login", async (req, res) => {
  const parse = loginSchema.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: "Invalid input", details: parse.error.flatten() });
  }
  const { email, password } = parse.data;
  if (dbEnabled()) {
    const user = await findUserByEmail(email);
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const token = jwt.sign({ sub: user.email }, JWT_SECRET, { expiresIn: "1h" });
    return res.json({
      message: "Login successful",
      token,
      user: { username: user.username, email: user.email, phone: user.phone },
    });
  } else {
    const user = users.get(email);
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const token = jwt.sign({ sub: user.email }, JWT_SECRET, { expiresIn: "1h" });
    return res.json({
      message: "Login successful",
      token,
      user: { username: user.username, email: user.email, phone: user.phone },
    });
  }
});

app.get("/api/health", (_req, res) => {
  res.json({ status: "ok" });
});

const start = async () => {
  try {
    await initDb();
  } catch {}
  app.listen(PORT, () => {
    console.log(`API server listening on http://localhost:${PORT}`);
  });
};
start();
