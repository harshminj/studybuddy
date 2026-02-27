// ============================================================
// StudyBuddy Backend — Node.js + Express + Socket.io + JWT
// ============================================================
// Install: npm install express socket.io jsonwebtoken bcryptjs cors nodemailer mongoose dotenv
// Run: node server.js

const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
require("dotenv").config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "studybuddy_secret_key";
const PORT = process.env.PORT || 5000;

// ============================================================
// IN-MEMORY STORE (replace with MongoDB in production)
// ============================================================
const db = {
  users: [],           // { id, name, email, passwordHash, college, subjects, style, location, otp, otpExpiry }
  likes: [],           // { fromId, toId }
  matches: [],         // { user1Id, user2Id, createdAt }
  messages: [],        // { id, matchId, senderId, text, timestamp }
  ratings: [],         // { fromId, toId, punctuality, helpfulness, focus, feedback }
};
let nextId = 1;

// ============================================================
// HELPERS
// ============================================================
const sign = (payload) => jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });

const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: "Invalid token" }); }
};

const generateOtp = () => String(Math.floor(10000 + Math.random() * 90000));

const getMatch = (u1, u2) => db.matches.find(m =>
  (m.user1Id === u1 && m.user2Id === u2) || (m.user1Id === u2 && m.user2Id === u1)
);

// ============================================================
// AUTH ROUTES
// ============================================================

// POST /api/auth/send-otp
// Sends OTP to email (for signup)
app.post("/api/auth/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });

  const otp = generateOtp();
  const otpExpiry = Date.now() + 10 * 60 * 1000; // 10 minutes

  let user = db.users.find(u => u.email === email);
  if (!user) {
    user = { id: nextId++, email, otp, otpExpiry, verified: false };
    db.users.push(user);
  } else {
    user.otp = otp; user.otpExpiry = otpExpiry;
  }

  // In production: send email via nodemailer / SendGrid
  console.log(`OTP for ${email}: ${otp}`);

  res.json({ message: "OTP sent to email", ...(process.env.NODE_ENV === "development" && { otp }) });
});

// POST /api/auth/verify-otp
app.post("/api/auth/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  const user = db.users.find(u => u.email === email);
  if (!user) return res.status(400).json({ error: "User not found" });
  if (user.otp !== otp) return res.status(400).json({ error: "Invalid OTP" });
  if (Date.now() > user.otpExpiry) return res.status(400).json({ error: "OTP expired" });
  user.verified = true;
  res.json({ message: "OTP verified", token: sign({ id: user.id, email }) });
});

// POST /api/auth/signup
// Called after OTP verified to set password & profile
app.post("/api/auth/signup", auth, async (req, res) => {
  const { password, name, college, subjects, style, location } = req.body;
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  if (!user.verified) return res.status(403).json({ error: "Email not verified" });

  user.passwordHash = await bcrypt.hash(password, 10);
  user.name = name;
  user.college = college;
  user.subjects = subjects || [];
  user.style = style;
  user.location = location;
  user.initials = name.split(" ").map(w => w[0]).join("").slice(0, 2).toUpperCase();

  res.json({ message: "Account created", token: sign({ id: user.id, email: user.email }), user: safeUser(user) });
});

// POST /api/auth/login
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const user = db.users.find(u => u.email === email);
  if (!user || !user.passwordHash) return res.status(401).json({ error: "Invalid credentials" });
  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: "Invalid credentials" });
  res.json({ token: sign({ id: user.id, email }), user: safeUser(user) });
});

const safeUser = (u) => ({
  id: u.id, name: u.name, email: u.email, college: u.college,
  subjects: u.subjects, style: u.style, location: u.location, initials: u.initials,
});

// ============================================================
// PROFILE ROUTES
// ============================================================

// GET /api/profile/me
app.get("/api/profile/me", auth, (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "Not found" });
  res.json(safeUser(user));
});

// PUT /api/profile/me
app.put("/api/profile/me", auth, (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "Not found" });
  const { name, college, subjects, style, location } = req.body;
  if (name) { user.name = name; user.initials = name.split(" ").map(w=>w[0]).join("").slice(0,2).toUpperCase(); }
  if (college) user.college = college;
  if (subjects) user.subjects = subjects;
  if (style) user.style = style;
  if (location) user.location = location;
  res.json(safeUser(user));
});

// ============================================================
// DISCOVERY & MATCHING
// ============================================================

// GET /api/discover?style=Collaborative&subject=React
// Returns users that current user hasn't liked yet
app.get("/api/discover", auth, (req, res) => {
  const { style, subject } = req.query;
  const myId = req.user.id;
  const likedIds = db.likes.filter(l => l.fromId === myId).map(l => l.toId);

  let candidates = db.users.filter(u =>
    u.id !== myId &&
    !likedIds.includes(u.id) &&
    u.name // must have completed profile
  );

  if (style) candidates = candidates.filter(u => u.style === style);
  if (subject) candidates = candidates.filter(u => u.subjects?.includes(subject));

  res.json(candidates.map(safeUser));
});

// POST /api/like/:targetId
// Like a user; if mutual → create match
app.post("/api/like/:targetId", auth, (req, res) => {
  const myId = req.user.id;
  const targetId = parseInt(req.params.targetId);
  if (myId === targetId) return res.status(400).json({ error: "Cannot like yourself" });

  const alreadyLiked = db.likes.find(l => l.fromId === myId && l.toId === targetId);
  if (alreadyLiked) return res.status(400).json({ error: "Already liked" });

  db.likes.push({ fromId: myId, toId: targetId });

  // Check if mutual
  const theyLikedMe = db.likes.find(l => l.fromId === targetId && l.toId === myId);
  if (theyLikedMe && !getMatch(myId, targetId)) {
    const match = { id: nextId++, user1Id: myId, user2Id: targetId, createdAt: new Date().toISOString() };
    db.matches.push(match);

    // Notify via socket
    io.to(`user_${targetId}`).emit("new_match", { matchId: match.id, withUser: safeUser(db.users.find(u=>u.id===myId)) });
    io.to(`user_${myId}`).emit("new_match", { matchId: match.id, withUser: safeUser(db.users.find(u=>u.id===targetId)) });

    return res.json({ liked: true, matched: true, matchId: match.id });
  }

  res.json({ liked: true, matched: false });
});

// GET /api/matches
app.get("/api/matches", auth, (req, res) => {
  const myId = req.user.id;
  const myMatches = db.matches.filter(m => m.user1Id === myId || m.user2Id === myId);
  const result = myMatches.map(m => {
    const otherId = m.user1Id === myId ? m.user2Id : m.user1Id;
    const other = db.users.find(u => u.id === otherId);
    const lastMsg = db.messages.filter(msg => msg.matchId === m.id).slice(-1)[0];
    return { matchId: m.id, user: safeUser(other), lastMessage: lastMsg?.text, createdAt: m.createdAt };
  });
  res.json(result);
});

// ============================================================
// MESSAGES
// ============================================================

// GET /api/messages/:matchId
app.get("/api/messages/:matchId", auth, (req, res) => {
  const matchId = parseInt(req.params.matchId);
  const match = db.matches.find(m => m.id === matchId);
  if (!match) return res.status(404).json({ error: "Match not found" });
  const myId = req.user.id;
  if (match.user1Id !== myId && match.user2Id !== myId) return res.status(403).json({ error: "Not your match" });
  const msgs = db.messages.filter(m => m.matchId === matchId);
  res.json(msgs);
});

// ============================================================
// RATINGS
// ============================================================

// POST /api/ratings
app.post("/api/ratings", auth, (req, res) => {
  const { toId, punctuality, helpfulness, focus, feedback } = req.body;
  if (!toId || !getMatch(req.user.id, toId)) return res.status(400).json({ error: "You haven't matched with this user" });
  const existing = db.ratings.find(r => r.fromId === req.user.id && r.toId === toId);
  if (existing) return res.status(400).json({ error: "Already rated" });
  db.ratings.push({ fromId: req.user.id, toId, punctuality, helpfulness, focus, feedback, createdAt: new Date().toISOString() });
  res.json({ message: "Rating submitted" });
});

// GET /api/ratings/:userId
app.get("/api/ratings/:userId", auth, (req, res) => {
  const userId = parseInt(req.params.userId);
  const userRatings = db.ratings.filter(r => r.toId === userId);
  if (!userRatings.length) return res.json({ avg: null, count: 0 });
  const avg = {
    punctuality: userRatings.reduce((s,r) => s+r.punctuality, 0) / userRatings.length,
    helpfulness: userRatings.reduce((s,r) => s+r.helpfulness, 0) / userRatings.length,
    focus: userRatings.reduce((s,r) => s+r.focus, 0) / userRatings.length,
  };
  res.json({ avg, count: userRatings.length });
});

// ============================================================
// ADMIN ROUTES
// ============================================================
const adminAuth = (req, res, next) => {
  // In production, check user.role === 'admin'
  auth(req, res, () => {
    const user = db.users.find(u => u.id === req.user.id);
    if (!user?.isAdmin) return res.status(403).json({ error: "Admin only" });
    next();
  });
};

app.get("/api/admin/stats", adminAuth, (req, res) => {
  res.json({
    totalUsers: db.users.length,
    totalMatches: db.matches.length,
    totalMessages: db.messages.length,
    totalRatings: db.ratings.length,
  });
});

app.get("/api/admin/users", adminAuth, (req, res) => {
  res.json(db.users.map(u => ({ ...safeUser(u), isAdmin: u.isAdmin })));
});

app.delete("/api/admin/users/:id", adminAuth, (req, res) => {
  const id = parseInt(req.params.id);
  const idx = db.users.findIndex(u => u.id === id);
  if (idx === -1) return res.status(404).json({ error: "User not found" });
  db.users.splice(idx, 1);
  res.json({ message: "User removed" });
});

// ============================================================
// SOCKET.IO — Real-time Chat
// ============================================================
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error("Authentication error"));
  try {
    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    next(new Error("Authentication error"));
  }
});

io.on("connection", (socket) => {
  const userId = socket.user.id;
  socket.join(`user_${userId}`);
  console.log(`User ${userId} connected`);

  // Join a match room
  socket.on("join_match", (matchId) => {
    const match = db.matches.find(m => m.id === matchId);
    if (!match) return;
    if (match.user1Id !== userId && match.user2Id !== userId) return;
    socket.join(`match_${matchId}`);
  });

  // Send message
  socket.on("send_message", ({ matchId, text }) => {
    const match = db.matches.find(m => m.id === matchId);
    if (!match || (match.user1Id !== userId && match.user2Id !== userId)) return;
    if (!text?.trim()) return;

    const message = {
      id: nextId++,
      matchId,
      senderId: userId,
      text: text.trim(),
      timestamp: new Date().toISOString(),
    };
    db.messages.push(message);

    // Broadcast to both users in the match
    io.to(`match_${matchId}`).emit("new_message", message);
  });

  // Typing indicator
  socket.on("typing", ({ matchId }) => {
    socket.to(`match_${matchId}`).emit("user_typing", { userId });
  });

  socket.on("disconnect", () => {
    console.log(`User ${userId} disconnected`);
  });
});

// ============================================================
// START
// ============================================================
server.listen(PORT, () => {
  console.log(`
  ╔══════════════════════════════════════╗
  ║   StudyBuddy Backend Running        ║
  ║   http://localhost:${PORT}               ║
  ╚══════════════════════════════════════╝
  `);
});

/*
=================================================================
MONGODB INTEGRATION (replace in-memory db with mongoose models)
=================================================================

const mongoose = require("mongoose");
mongoose.connect(process.env.MONGO_URI);

const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  passwordHash: String,
  name: String, college: String, subjects: [String],
  style: String, location: String, initials: String,
  otp: String, otpExpiry: Date, verified: Boolean, isAdmin: Boolean,
}, { timestamps: true });

const LikeSchema = new mongoose.Schema({ fromId: mongoose.Types.ObjectId, toId: mongoose.Types.ObjectId }, { timestamps: true });
const MatchSchema = new mongoose.Schema({ user1Id: mongoose.Types.ObjectId, user2Id: mongoose.Types.ObjectId }, { timestamps: true });
const MessageSchema = new mongoose.Schema({ matchId: mongoose.Types.ObjectId, senderId: mongoose.Types.ObjectId, text: String }, { timestamps: true });
const RatingSchema = new mongoose.Schema({ fromId: mongoose.Types.ObjectId, toId: mongoose.Types.ObjectId, punctuality: Number, helpfulness: Number, focus: Number, feedback: String }, { timestamps: true });

=================================================================
.env file
=================================================================
JWT_SECRET=your_super_secret_key_here
MONGO_URI=mongodb://localhost:27017/studybuddy
PORT=5000
NODE_ENV=development

=================================================================
API SUMMARY
=================================================================
POST   /api/auth/send-otp       → Send OTP to email
POST   /api/auth/verify-otp     → Verify OTP, get temp token
POST   /api/auth/signup         → Complete profile, get full token
POST   /api/auth/login          → Login with email + password

GET    /api/profile/me          → Get my profile
PUT    /api/profile/me          → Update my profile

GET    /api/discover            → Get candidate profiles (with filters)
POST   /api/like/:targetId      → Like a user (auto-matches if mutual)
GET    /api/matches             → Get all my matches

GET    /api/messages/:matchId   → Get chat history
                                 (real-time via Socket.io)

POST   /api/ratings             → Submit session rating
GET    /api/ratings/:userId     → Get user's average rating

GET    /api/admin/stats         → Platform statistics
GET    /api/admin/users         → All users
DELETE /api/admin/users/:id     → Remove a user

=================================================================
SOCKET EVENTS
=================================================================
CLIENT → SERVER:
  join_match   { matchId }                Join a chat room
  send_message { matchId, text }          Send a chat message
  typing       { matchId }                Typing indicator

SERVER → CLIENT:
  new_message  { id, matchId, senderId, text, timestamp }
  new_match    { matchId, withUser }      Real-time match notification
  user_typing  { userId }                 Typing indicator
*/
