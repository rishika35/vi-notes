import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import cookieParser from "cookie-parser";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import fs from "fs/promises";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const JWT_SECRET = process.env.JWT_SECRET || "default-secret-key-for-dev";
const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const SESSIONS_FILE = path.join(DATA_DIR, "sessions.json");

// Ensure data directory exists
async function ensureDataDir() {
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
    try { await fs.access(USERS_FILE); } catch { await fs.writeFile(USERS_FILE, "[]"); }
    try { await fs.access(SESSIONS_FILE); } catch { await fs.writeFile(SESSIONS_FILE, "[]"); }
  } catch (err) {
    console.error("Error ensuring data directory:", err);
  }
}

async function startServer() {
  await ensureDataDir();
  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: '50mb' }));
  app.use(cookieParser());
  app.use(cors());

  // --- API Routes ---

  // Auth Middleware
  const authenticate = async (req: any, res: any, next: any) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as { userId: string };
      req.userId = decoded.userId;
      next();
    } catch (err) {
      res.status(401).json({ error: "Invalid token" });
    }
  };

  // Register
  app.post("/api/auth/register", async (req, res) => {
    const { email, password, displayName } = req.body;
    const users = JSON.parse(await fs.readFile(USERS_FILE, "utf-8"));
    if (users.find((u: any) => u.email === email)) {
      return res.status(400).json({ error: "User already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: Math.random().toString(36).substring(2, 15),
      email,
      password: hashedPassword,
      displayName: displayName || email.split("@")[0],
      createdAt: Date.now(),
    };
    users.push(newUser);
    await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
    
    const token = jwt.sign({ userId: newUser.id }, JWT_SECRET, { expiresIn: "7d" });
    res.cookie("token", token, { httpOnly: true, sameSite: "none", secure: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.json({ user: { id: newUser.id, email: newUser.email, displayName: newUser.displayName } });
  });

  // Login
  app.post("/api/auth/login", async (req, res) => {
    const { email, password } = req.body;
    const users = JSON.parse(await fs.readFile(USERS_FILE, "utf-8"));
    const user = users.find((u: any) => u.email === email);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ error: "Invalid credentials" });
    }
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "7d" });
    res.cookie("token", token, { httpOnly: true, sameSite: "none", secure: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.json({ user: { id: user.id, email: user.email, displayName: user.displayName } });
  });

  // Logout
  app.post("/api/auth/logout", (req, res) => {
    res.clearCookie("token", { httpOnly: true, sameSite: "none", secure: true });
    res.json({ success: true });
  });

  // Get Current User
  app.get("/api/auth/me", async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: "Not logged in" });
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as { userId: string };
      const users = JSON.parse(await fs.readFile(USERS_FILE, "utf-8"));
      const user = users.find((u: any) => u.id === decoded.userId);
      if (!user) return res.status(404).json({ error: "User not found" });
      res.json({ user: { id: user.id, email: user.email, displayName: user.displayName } });
    } catch (err) {
      res.status(401).json({ error: "Invalid token" });
    }
  });

  // Sessions API
  app.get("/api/sessions", authenticate, async (req: any, res) => {
    const sessions = JSON.parse(await fs.readFile(SESSIONS_FILE, "utf-8"));
    const userSessions = sessions.filter((s: any) => s.userId === req.userId);
    res.json(userSessions);
  });

  app.post("/api/sessions", authenticate, async (req: any, res) => {
    try {
      const sessionData = req.body;
      console.log("Saving session for user:", req.userId);
      const sessions = JSON.parse(await fs.readFile(SESSIONS_FILE, "utf-8"));
      const newSession = {
        ...sessionData,
        id: Math.random().toString(36).substring(2, 15),
        userId: req.userId,
        createdAt: Date.now(),
        updatedAt: Date.now(),
      };
      sessions.push(newSession);
      await fs.writeFile(SESSIONS_FILE, JSON.stringify(sessions, null, 2));
      console.log("Session saved successfully:", newSession.id);
      res.json(newSession);
    } catch (err) {
      console.error("Error saving session:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get("/api/sessions/:id", authenticate, async (req: any, res) => {
    const sessions = JSON.parse(await fs.readFile(SESSIONS_FILE, "utf-8"));
    const session = sessions.find((s: any) => s.id === req.params.id && s.userId === req.userId);
    if (!session) return res.status(404).json({ error: "Session not found" });
    res.json(session);
  });

  app.patch("/api/sessions/:id", authenticate, async (req: any, res) => {
    try {
      const { title } = req.body;
      const sessions = JSON.parse(await fs.readFile(SESSIONS_FILE, "utf-8"));
      const sessionIndex = sessions.findIndex((s: any) => s.id === req.params.id && s.userId === req.userId);
      
      if (sessionIndex === -1) return res.status(404).json({ error: "Session not found" });
      
      sessions[sessionIndex] = {
        ...sessions[sessionIndex],
        title: title || sessions[sessionIndex].title,
        updatedAt: Date.now(),
      };
      
      await fs.writeFile(SESSIONS_FILE, JSON.stringify(sessions, null, 2));
      res.json(sessions[sessionIndex]);
    } catch (err) {
      console.error("Error updating session:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  });
  
  app.delete("/api/sessions/:id", authenticate, async (req: any, res) => {
    try {
      const sessions = JSON.parse(await fs.readFile(SESSIONS_FILE, "utf-8"));
      const filteredSessions = sessions.filter((s: any) => !(s.id === req.params.id && s.userId === req.userId));
      
      if (filteredSessions.length === sessions.length) {
        return res.status(404).json({ error: "Session not found or unauthorized" });
      }
      
      await fs.writeFile(SESSIONS_FILE, JSON.stringify(filteredSessions, null, 2));
      res.json({ success: true });
    } catch (err) {
      console.error("Error deleting session:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // --- Vite Integration ---
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
