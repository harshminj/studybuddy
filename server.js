const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "studybuddy_secret_key";
const PORT = process.env.PORT || 3000;

const db = {
  users: [],
  likes: [],
  matches: [],
  messages: [],
  ratings: [],
};
let nextId = 1;

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

const safeUser = (u) => u ? ({
  id: u.id, name: u.name, email: u.email, college: u.college,
  subjects: u.subjects, style: u.style, location: u.location,
  initials: u.initials, is_admin: u.isAdmin
}) : null;

// Seed admin user
db.users.push({
  id: nextId++, email: "admin@studybuddy.com",
  passwordHash: "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi",
  name: "Admin", college: "StudyBuddy HQ", subjects: [],
  style: "Collaborative", location: "Online",
  initials: "AD", verified: true, isAdmin: true
});

// AUTH
app.post("/api/auth/send-otp", (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });
  const otp = generateOtp();
  const otpExpiry = Date.now() + 10 * 60 * 1000;
  let user = db.users.find(u => u.email === email);
  if (!user) {
    user = { id: nextId++, email, otp, otpExpiry, verified: false };
    db.users.push(user);
  } else {
    user.otp = otp;
    user.otpExpiry = otpExpiry;
  }
  console.log(`OTP for ${email}: ${otp}`);
  res.json({ message: "OTP sent", otp: otp });
});

app.post("/api/auth/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  const user = db.users.find(u => u.email === email);
  if (!user) return res.status(400).json({ error: "User not found" });
  if (user.otp !== otp) return res.status(400).json({ error: "Invalid OTP" });
  if (Date.now() > user.otpExpiry) return res.status(400).json({ error: "OTP expired" });
  user.verified = true;
  res.json({ message: "OTP verified", token: sign({ id: user.id, email }) });
});

app.post("/api/auth/signup", auth, async (req, res) => {
  const { password, name, college, subjects, style, location } = req.body;
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  user.passwordHash = await bcrypt.hash(password, 10);
  user.name = name;
  user.college = college;
  user.subjects = subjects || [];
  user.style = style;
  user.location = location;
  user.initials = name.split(" ").map(w => w[0]).join("").slice(0, 2).toUpperCase();
  res.json({ message: "Account created", token: sign({ id: user.id, email: user.email }), user: safeUser(user) });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const user = db.users.find(u => u.email === email);
  if (!user || !user.passwordHash) return res.status(401).json({ error: "Invalid credentials" });
  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: "Invalid credentials" });
  if (!user.verified) return res.status(403).json({ error: "Email not verified" });
  res.json({ token: sign({ id: user.id, email }), user: safeUser(user) });
});

// PROFILE
app.get("/api/profile/me", auth, (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "Not found" });
  res.json(safeUser(user));
});

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

// DISCOVER
app.get("/api/discover", auth, (req, res) => {
  const { style, subject } = req.query;
  const myId = req.user.id;
  const likedIds = db.likes.filter(l => l.fromId === myId).map(l => l.toId);
  let candidates = db.users.filter(u => u.id !== myId && !likedIds.includes(u.id) && u.name && u.verified);
  if (style) candidates = candidates.filter(u => u.style === style);
  if (subject) candidates = candidates.filter(u => u.subjects?.includes(subject));
  res.json(candidates.map(safeUser));
});

// LIKE
app.post("/api/like/:targetId", auth, (req, res) => {
  const myId = req.user.id;
  const targetId = parseInt(req.params.targetId);
  if (myId === targetId) return res.status(400).json({ error: "Cannot like yourself" });
  if (db.likes.find(l => l.fromId === myId && l.toId === targetId))
    return res.status(400).json({ error: "Already liked" });
  db.likes.push({ fromId: myId, toId: targetId });
  const theyLikedMe = db.likes.find(l => l.fromId === targetId && l.toId === myId);
  if (theyLikedMe && !getMatch(myId, targetId)) {
    const match = { id: nextId++, user1Id: myId, user2Id: targetId, createdAt: new Date().toISOString() };
    db.matches.push(match);
    io.to(`user_${targetId}`).emit("new_match", { matchId: match.id, withUser: safeUser(db.users.find(u=>u.id===myId)) });
    io.to(`user_${myId}`).emit("new_match", { matchId: match.id, withUser: safeUser(db.users.find(u=>u.id===targetId)) });
    return res.json({ liked: true, matched: true, matchId: match.id });
  }
  res.json({ liked: true, matched: false });
});

// MATCHES
app.get("/api/matches", auth, (req, res) => {
  const myId = req.user.id;
  const myMatches = db.matches.filter(m => m.user1Id === myId || m.user2Id === myId);
  const result = myMatches.map(m => {
    const otherId = m.user1Id === myId ? m.user2Id : m.user1Id;
    const other = db.users.find(u => u.id === otherId);
    const msgs = db.messages.filter(msg => msg.matchId === m.id);
    const lastMsg = msgs[msgs.length - 1];
    return {
      match_id: m.id, id: otherId, name: other?.name, college: other?.college,
      initials: other?.initials, last_message: lastMsg?.text, unread_count: 0
    };
  });
  res.json(result);
});

// MESSAGES
app.get("/api/messages/:matchId", auth, (req, res) => {
  const matchId = parseInt(req.params.matchId);
  const match = db.matches.find(m => m.id === matchId);
  if (!match) return res.status(404).json({ error: "Match not found" });
  const msgs = db.messages.filter(m => m.matchId === matchId).map(m => ({
    id: m.id, match_id: m.matchId, sender_id: m.senderId,
    text: m.text, created_at: m.timestamp
  }));
  res.json(msgs);
});

app.post("/api/messages/:matchId", auth, (req, res) => {
  const matchId = parseInt(req.params.matchId);
  const match = db.matches.find(m => m.id === matchId);
  if (!match) return res.status(404).json({ error: "Match not found" });
  const { text } = req.body;
  if (!text?.trim()) return res.status(400).json({ error: "Text required" });
  const msg = { id: nextId++, matchId, senderId: req.user.id, text: text.trim(), timestamp: new Date().toISOString() };
  db.messages.push(msg);
  io.to(`match_${matchId}`).emit("new_message", msg);
  res.json({ id: msg.id, match_id: msg.matchId, sender_id: msg.senderId, text: msg.text, created_at: msg.timestamp });
});

// RATINGS
app.post("/api/ratings", auth, (req, res) => {
  const { toId, punctuality, helpfulness, focus, feedback } = req.body;
  db.ratings.push({ fromId: req.user.id, toId, punctuality, helpfulness, focus, feedback });
  res.json({ message: "Rating submitted" });
});

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

// ADMIN
app.get("/api/admin/stats", auth, (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  if (!user?.isAdmin) return res.status(403).json({ error: "Admin only" });
  res.json({ totalUsers: db.users.length, totalMatches: db.matches.length, totalMessages: db.messages.length, todaySignups: 0 });
});

app.get("/api/admin/users", auth, (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  if (!user?.isAdmin) return res.status(403).json({ error: "Admin only" });
  res.json({ users: db.users.map(safeUser) });
});

app.delete("/api/admin/users/:id", auth, (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  if (!user?.isAdmin) return res.status(403).json({ error: "Admin only" });
  const id = parseInt(req.params.id);
  const idx = db.users.findIndex(u => u.id === id);
  if (idx !== -1) db.users.splice(idx, 1);
  res.json({ message: "User removed" });
});

// SOCKET
io.use((socket, next) => {
  try { socket.user = jwt.verify(socket.handshake.auth?.token, JWT_SECRET); next(); }
  catch { next(new Error("Auth error")); }
});

io.on("connection", (socket) => {
  socket.join(`user_${socket.user.id}`);
  socket.on("join_match", (matchId) => socket.join(`match_${matchId}`));
  socket.on("send_message", ({ matchId, text }) => {
    const msg = { id: nextId++, matchId, senderId: socket.user.id, text, timestamp: new Date().toISOString() };
    db.messages.push(msg);
    io.to(`match_${matchId}`).emit("new_message", msg);
  });
  socket.on("disconnect", () => console.log(`User ${socket.user.id} disconnected`));
});

// ROOT ROUTES
app.get("/", (req, res) => res.json({ message: "StudyBuddy API is running! 🎓", version: "1.0" }));
app.get("/api", (req, res) => res.json({ message: "StudyBuddy API is running! 🎓", version: "1.0" }));

// Keep-alive ping every 14 minutes to prevent Render from sleeping
setInterval(() => {
  const http = require("http");
  http.get(`http://localhost:${PORT}/api`, () => {}).on("error", () => {});
}, 14 * 60 * 1000);

server.listen(PORT, () => console.log(`StudyBuddy API running on port ${PORT}`));
