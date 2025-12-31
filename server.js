const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const cookieParser = require("cookie-parser");

dotenv.config();

const app = express();

// ================== MIDDLEWARE ==================
app.use(cors({
  origin: "https://teligramlogin.vercel.app", // change in dev
  credentials: true
}));

app.use(express.json());
app.use(cookieParser());

// logger
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} | ${req.method} ${req.url}`);
  next();
});

// ================== TELEGRAM VERIFY ==================
function verifyTelegramLogin(data) {
  const secretKey = crypto
    .createHash("sha256")
    .update(process.env.BOT_TOKEN)
    .digest();

  const checkString = Object.keys(data)
    .filter(key => key !== "hash")
    .sort()
    .map(key => `${key}=${data[key]}`)
    .join("\n");

  const calculatedHash = crypto
    .createHmac("sha256", secretKey)
    .update(checkString)
    .digest("hex");

  return calculatedHash === data.hash;
}

// ================== AUTH ROUTE ==================
app.get("/api/auth/telegram", (req, res) => {
  const data = req.query;

  if (!data.hash || !data.id) {
    return res.status(400).send("Invalid Telegram payload");
  }

  // auth expiry check (24h)
  const now = Math.floor(Date.now() / 1000);
  if (now - Number(data.auth_date) > 86400) {
    return res.status(401).send("Telegram auth expired");
  }

  if (!verifyTelegramLogin(data)) {
    return res.status(401).send("Telegram verification failed");
  }

  // user object
  const user = {
    telegramId: Number(data.id),
    name: `${data.first_name || ""} ${data.last_name || ""}`.trim(),
    username: data.username || null,
    photo: data.photo_url || null
  };

  // JWT
  const token = jwt.sign(user, process.env.JWT_SECRET, {
    expiresIn: "7d"
  });

  // secure cookie
  res.cookie("token", token, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge: 7 * 24 * 60 * 60 * 1000
  });

  // redirect to frontend
  res.redirect("https://teligramlogin.vercel.app/dashboard");
});

// ================== CHECK LOGIN ==================
app.get("/api/me", (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ loggedIn: false });

    const user = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ loggedIn: true, user });
  } catch {
    res.status(401).json({ loggedIn: false });
  }
});

// ================== LOGOUT ==================
app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ success: true });
});

// ================== SERVER ==================
app.get("/", (req, res) => {
  res.send("🚀 Telegram Auth Backend Running");
});

app.listen(process.env.PORT || 5000, () => {
  console.log("🔥 Server started");
});
