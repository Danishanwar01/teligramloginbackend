const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

dotenv.config();

const app = express();

// ✅ CORS (frontend domain allow)
app.use(cors({
  origin: "https://teligramlogin.vercel.app",
  methods: ["GET", "POST"],
  credentials: true
}));

app.use(express.json());

// ✅ Telegram verification function
function verifyTelegramLogin(data) {
  const botToken = process.env.BOT_TOKEN;
  if (!botToken) return false;

  const secretKey = crypto
    .createHash("sha256")
    .update(botToken)
    .digest();

  const checkString = Object.keys(data)
    .filter(key => key !== "hash")
    .sort()
    .map(key => `${key}=${data[key]}`)
    .join("\n");

  const hmac = crypto
    .createHmac("sha256", secretKey)
    .update(checkString)
    .digest("hex");

  return hmac === data.hash;
}

// ✅ Telegram auth route
app.post("/api/auth/telegram", (req, res) => {
  const data = req.body;

  if (!data || !data.hash) {
    return res.status(400).json({ message: "Invalid payload" });
  }

  const now = Math.floor(Date.now() / 1000);
  if (now - data.auth_date > 86400) {
    return res.status(401).json({ message: "Auth expired" });
  }

  if (!verifyTelegramLogin(data)) {
    return res.status(401).json({ message: "Invalid Telegram data" });
  }

  const user = {
    telegramId: data.id,
    name: data.first_name,
    username: data.username || null,
    photo: data.photo_url || null
  };

  const token = jwt.sign(user, process.env.JWT_SECRET, {
    expiresIn: "7d"
  });

  return res.json({
    success: true,
    token,
    user
  });
});

// ✅ HEALTH CHECK (VERY IMPORTANT FOR RENDER)
app.get("/", (req, res) => {
  res.send("Telegram Auth Backend is running 🚀");
});

// ✅ PORT FIX (THIS WAS THE REAL BUG)
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
