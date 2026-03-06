const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const mongoose = require("mongoose");
require("dotenv").config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "studybuddy_secret_key";
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

// ============================================================
// MONGODB SCHEMAS
// ============================================================
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  passwordHash: String,
  name: String,
  college: String,
  subjects: [String],
  style: String,
  location: String,
  initials: String,
  photo: String,
  otp: String,
  otpExpiry: Date,
  verified: { type: Boolean, default: false },
  isAdmin: { type: Boolean, default: false },
}, { timestamps: true });

const LikeSchema = new mongoose.Schema({
  fromId: mongoose.Schema.Types.ObjectId,
  toId: mongoose.Schema.Types.ObjectId,
}, { timestamps: true });

const MatchSchema = new mongoose.Schema({
  user1Id: mongoose.Schema.Types.ObjectId,
  user2Id: mongoose.Schema.Types.ObjectId,
}, { timestamps: true });

const MessageSchema = new mongoose.Schema({
  matchId: mongoose.Schema.Types.ObjectId,
  senderId: mongoose.Schema.Types.ObjectId,
  text: String,
}, { timestamps: true });

const RatingSchema = new mongoose.Schema({
  fromId: mongoose.Schema.Types.ObjectId,
  toId: mongoose.Schema.Types.ObjectId,
  punctuality: Number,
  helpfulness: Number,
  focus: Number,
  feedback: String,
}, { timestamps: true });

const User = mongoose.model("User", UserSchema);
const Like = mongoose.model("Like", LikeSchema);
const Match = mongoose.model("Match", MatchSchema);
const Message = mongoose.model("Message", MessageSchema);
const Rating = mongoose.model("Rating", RatingSchema);

// ============================================================
// CONNECT TO MONGODB
// ============================================================
mongoose.connect(MONGO_URI).then(async () => {
  console.log("✅ MongoDB connected!");
  // Seed admin if not exists
  const admin = await User.findOne({ email: "admin@studybuddy.com" });
  if (!admin) {
    const hash = await bcrypt.hash("admin123", 10);
    await User.create({
      email: "admin@studybuddy.com",
      passwordHash: hash,
      name: "Admin",
      college: "StudyBuddy HQ",
      subjects: [],
      style: "Collaborative",
      location: "Online",
      initials: "AD",
      verified: true,
      isAdmin: true,
    });
    console.log("✅ Admin seeded");
  }
}).catch(err => console.error("MongoDB error:", err));

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

const safeUser = (u) => u ? ({
  id: u._id.toString(),
  name: u.name,
  email: u.email,
  college: u.college,
  subjects: u.subjects,
  style: u.style,
  location: u.location,
  initials: u.initials,
  photo: u.photo,
  is_admin: u.isAdmin,
}) : null;

const getMatch = async (u1, u2) => Match.findOne({
  $or: [
    { user1Id: u1, user2Id: u2 },
    { user1Id: u2, user2Id: u1 }
  ]
});

// ============================================================
// AUTH ROUTES
// ============================================================

// POST /api/auth/send-otp
app.post("/api/auth/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });
  const otp = generateOtp();
  const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);
  let user = await User.findOne({ email });
  if (!user) {
    user = await User.create({ email, otp, otpExpiry, verified: false });
  } else {
    user.otp = otp; user.otpExpiry = otpExpiry;
    await user.save();
  }
  console.log(`OTP for ${email}: ${otp}`);
  res.json({ message: "OTP sent", otp });
});

// POST /api/auth/verify-otp
app.post("/api/auth/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: "User not found" });
  if (user.otp !== otp) return res.status(400).json({ error: "Invalid OTP" });
  if (new Date() > user.otpExpiry) return res.status(400).json({ error: "OTP expired" });
  user.verified = true;
  await user.save();
  res.json({ message: "OTP verified", token: sign({ id: user._id.toString(), email }) });
});

// POST /api/auth/signup
app.post("/api/auth/signup", auth, async (req, res) => {
  const { password, name, college, subjects, style, location } = req.body;
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  user.passwordHash = await bcrypt.hash(password, 10);
  user.name = name;
  user.college = college;
  user.subjects = subjects || [];
  user.style = style;
  user.location = location;
  user.initials = name.split(" ").map(w => w[0]).join("").slice(0, 2).toUpperCase();
  await user.save();
  res.json({ message: "Account created", token: sign({ id: user._id.toString(), email: user.email }), user: safeUser(user) });
});

// POST /api/auth/login
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !user.passwordHash) return res.status(401).json({ error: "Invalid credentials" });
  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: "Invalid credentials" });
  res.json({ token: sign({ id: user._id.toString(), email }), user: safeUser(user) });
});

// ============================================================
// PROFILE
// ============================================================
app.get("/api/profile/me", auth, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ error: "Not found" });
  res.json(safeUser(user));
});

app.put("/api/profile/me", auth, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ error: "Not found" });
  const { name, college, subjects, style, location, photo } = req.body;
  if (name) { user.name = name; user.initials = name.split(" ").map(w=>w[0]).join("").slice(0,2).toUpperCase(); }
  if (college) user.college = college;
  if (subjects) user.subjects = subjects;
  if (style) user.style = style;
  if (location) user.location = location;
  if (photo !== undefined) user.photo = photo;
  await user.save();
  res.json(safeUser(user));
});

// ============================================================
// DISCOVER — show ALL users except self (including matched ones)
// ============================================================
app.get("/api/discover", auth, async (req, res) => {
  const { style, subject } = req.query;
  const myId = new mongoose.Types.ObjectId(req.user.id);

  // Only exclude people already liked (not matched)
  const likedIds = (await Like.find({ fromId: myId })).map(l => l.toId);

  let query = {
    _id: { $ne: myId, $nin: likedIds },
    name: { $exists: true, $ne: null },
    verified: true,
    isAdmin: { $ne: true },
  };
  if (style) query.style = style;
  if (subject) query.subjects = subject;

  const users = await User.find(query);
  res.json(users.map(safeUser));
});

// ============================================================
// LIKE — mutual like = match, but profiles stay visible
// ============================================================
app.post("/api/like/:targetId", auth, async (req, res) => {
  const myId = new mongoose.Types.ObjectId(req.user.id);
  const targetId = new mongoose.Types.ObjectId(req.params.targetId);

  if (myId.equals(targetId)) return res.status(400).json({ error: "Cannot like yourself" });

  const alreadyLiked = await Like.findOne({ fromId: myId, toId: targetId });
  if (alreadyLiked) return res.status(400).json({ error: "Already liked" });

  await Like.create({ fromId: myId, toId: targetId });

  const theyLikedMe = await Like.findOne({ fromId: targetId, toId: myId });
  const existingMatch = await getMatch(myId, targetId);

  if (theyLikedMe && !existingMatch) {
    const match = await Match.create({ user1Id: myId, user2Id: targetId });
    const myUser = await User.findById(myId);
    const theirUser = await User.findById(targetId);
    io.to(`user_${targetId}`).emit("new_match", { matchId: match._id, withUser: safeUser(myUser) });
    io.to(`user_${myId}`).emit("new_match", { matchId: match._id, withUser: safeUser(theirUser) });
    return res.json({ liked: true, matched: true, matchId: match._id });
  }

  res.json({ liked: true, matched: false });
});

// ============================================================
// MATCHES
// ============================================================
app.get("/api/matches", auth, async (req, res) => {
  const myId = new mongoose.Types.ObjectId(req.user.id);
  const myMatches = await Match.find({
    $or: [{ user1Id: myId }, { user2Id: myId }]
  });

  const result = await Promise.all(myMatches.map(async m => {
    const otherId = m.user1Id.equals(myId) ? m.user2Id : m.user1Id;
    const other = await User.findById(otherId);
    const lastMsg = await Message.findOne({ matchId: m._id }).sort({ createdAt: -1 });
    return {
      match_id: m._id.toString(),
      id: otherId.toString(),
      name: other?.name,
      college: other?.college,
      initials: other?.initials,
      photo: other?.photo,
      style: other?.style,
      subjects: other?.subjects || [],
      location: other?.location,
      last_message: lastMsg?.text,
      unread_count: 0,
    };
  }));
  res.json(result);
});

// ============================================================
// MESSAGES
// ============================================================
app.get("/api/messages/:matchId", auth, async (req, res) => {
  const msgs = await Message.find({ matchId: req.params.matchId }).sort({ createdAt: 1 });
  res.json(msgs.map(m => ({
    id: m._id.toString(),
    match_id: m.matchId.toString(),
    sender_id: m.senderId.toString(),
    text: m.text,
    created_at: m.createdAt,
  })));
});

app.post("/api/messages/:matchId", auth, async (req, res) => {
  const { text } = req.body;
  if (!text?.trim()) return res.status(400).json({ error: "Text required" });
  const msg = await Message.create({
    matchId: req.params.matchId,
    senderId: req.user.id,
    text: text.trim(),
  });
  const out = { id: msg._id.toString(), match_id: msg.matchId.toString(), sender_id: msg.senderId.toString(), text: msg.text, created_at: msg.createdAt };
  io.to(`match_${req.params.matchId}`).emit("new_message", out);
  res.json(out);
});

// ============================================================
// RATINGS
// ============================================================
app.post("/api/ratings", auth, async (req, res) => {
  const { toId, punctuality, helpfulness, focus, feedback } = req.body;
  await Rating.create({ fromId: req.user.id, toId, punctuality, helpfulness, focus, feedback });
  res.json({ message: "Rating submitted" });
});

app.get("/api/ratings/:userId", auth, async (req, res) => {
  const userRatings = await Rating.find({ toId: req.params.userId });
  if (!userRatings.length) return res.json({ avg: null, count: 0 });
  const avg = {
    punctuality: userRatings.reduce((s,r) => s+r.punctuality, 0) / userRatings.length,
    helpfulness: userRatings.reduce((s,r) => s+r.helpfulness, 0) / userRatings.length,
    focus: userRatings.reduce((s,r) => s+r.focus, 0) / userRatings.length,
  };
  res.json({ avg, count: userRatings.length });
});

// ============================================================
// ADMIN
// ============================================================
app.get("/api/admin/stats", auth, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user?.isAdmin) return res.status(403).json({ error: "Admin only" });
  const today = new Date(); today.setHours(0,0,0,0);
  res.json({
    totalUsers: await User.countDocuments(),
    totalMatches: await Match.countDocuments(),
    totalMessages: await Message.countDocuments(),
    todaySignups: await User.countDocuments({ createdAt: { $gte: today } }),
  });
});

app.get("/api/admin/users", auth, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user?.isAdmin) return res.status(403).json({ error: "Admin only" });
  const users = await User.find();
  res.json({ users: users.map(safeUser) });
});

app.delete("/api/admin/users/:id", auth, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user?.isAdmin) return res.status(403).json({ error: "Admin only" });
  await User.findByIdAndDelete(req.params.id);
  res.json({ message: "User removed" });
});

// ============================================================
// SOCKET.IO
// ============================================================
io.use((socket, next) => {
  try { socket.user = jwt.verify(socket.handshake.auth?.token, JWT_SECRET); next(); }
  catch { next(new Error("Auth error")); }
});

io.on("connection", (socket) => {
  socket.join(`user_${socket.user.id}`);
  socket.on("join_match", (matchId) => socket.join(`match_${matchId}`));
  socket.on("send_message", async ({ matchId, text }) => {
    const msg = await Message.create({ matchId, senderId: socket.user.id, text });
    io.to(`match_${matchId}`).emit("new_message", {
      id: msg._id.toString(), match_id: matchId,
      sender_id: socket.user.id, text, created_at: msg.createdAt
    });
  });
  socket.on("disconnect", () => console.log(`User ${socket.user.id} disconnected`));
});

// ROOT
app.get("/", (req, res) => res.json({ message: "StudyBuddy API is running! 🎓" }));
app.get("/api", (req, res) => res.json({ message: "StudyBuddy API is running! 🎓" }));

server.listen(PORT, () => console.log(`StudyBuddy running on port ${PORT}`));
