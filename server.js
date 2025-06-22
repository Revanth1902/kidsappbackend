require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cloudinary = require("cloudinary").v2;

// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const app = express();
app.use(express.json());

// --- MongoDB Models ---

const { Schema, model } = require("mongoose");

const userSchema = new Schema({
  name: String,
  age: Number,
  class: String,
  email: { type: String, unique: true },
  password: String,
  avatarUrl: String,
});

userSchema.pre("save", async function () {
  if (this.isModified("password")) {
    this.password = await bcrypt.hash(this.password, 10);
  }
});

userSchema.methods.comparePassword = function (pw) {
  return bcrypt.compare(pw, this.password);
};

const User = model("User", userSchema);

const scoreSchema = new Schema(
  {
    user: { type: Schema.Types.ObjectId, ref: "User" },
    score: Number,
  },
  { timestamps: true }
);

const Score = model("Score", scoreSchema);

// --- Auth Middleware ---
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id).select("-password");
    if (!req.user) throw new Error();
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
};

// --- Routes ---

// Register
app.post("/api/auth/register", async (req, res) => {
  const { name, age, class: cls, email, password, avatar } = req.body;

  if (!name || !age || !cls || !email || !password)
    return res.status(400).json({ message: "Missing fields" });

  if (await User.findOne({ email }))
    return res.status(400).json({ message: "Email already exists" });

  let avatarUrl = "";
  if (avatar) {
    const upload = await cloudinary.uploader.upload(avatar, {
      folder: "avatars",
    });
    avatarUrl = upload.secure_url;
  }

  const user = new User({ name, age, class: cls, email, password, avatarUrl });
  await user.save();

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });
  res.status(201).json({ token, user });
});

// Login
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user || !(await user.comparePassword(password)))
    return res.status(401).json({ message: "Invalid credentials" });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });
  res.json({ token, user });
});

// Submit score
app.post("/api/scores", authenticate, async (req, res) => {
  const { score } = req.body;
  if (!score) return res.status(400).json({ message: "Score required" });

  const record = await Score.create({ user: req.user._id, score });
  res.status(201).json(record);
});

// Leaderboard
app.get("/api/leaderboard", async (req, res) => {
  const top = await Score.aggregate([
    { $group: { _id: "$user", total: { $sum: "$score" } } },
    { $sort: { total: -1 } },
    { $limit: 10 },
    {
      $lookup: {
        from: "users",
        localField: "_id",
        foreignField: "_id",
        as: "user",
      },
    },
    { $unwind: "$user" },
    {
      $project: {
        name: "$user.name",
        avatarUrl: "$user.avatarUrl",
        totalScore: "$total",
      },
    },
  ]);

  res.json(top);
});

// --- Connect and Start Server ---
const PORT = process.env.PORT || 5000;

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("✅ MongoDB connected successfully");
    app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
  });
