const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

dotenv.config();

const app = express();

// ================== MIDDLEWARE ==================
app.use(cors({
  origin: "https://teligramlogin.vercel.app",
}));

app.use(express.json());

// ================== TELEGRAM VERIFY ==================
function verifyTelegramLogin(data) {
  const secretKey = crypto
    .createHash("sha256")
    .update(process.env.BOT_TOKEN)
    .digest();

  const checkString = Object.keys(data)
    .filter(k => k !== "hash")
    .sort()
    .map(k => `${k}=${data[k]}`)
    .join("\n");

  const hash = crypto
    .createHmac("sha256", secretKey)
    .update(checkString)
    .digest("hex");

  return hash === data.hash;
}

// ================== AUTH ROUTE ==================
app.get("/api/auth/telegram", (req, res) => {
  const data = req.query;
  if (!data.hash || !data.id) return res.status(400).send("Invalid payload");

  const now = Math.floor(Date.now() / 1000);
  if (now - Number(data.auth_date) > 86400) return res.status(401).send("Expired");

  if (!verifyTelegramLogin(data)) return res.status(401).send("Telegram verification failed");

  const user = {
    telegramId: Number(data.id),
    name: `${data.first_name || ""} ${data.last_name || ""}`.trim(),
    username: data.username || null,
    photo: data.photo_url || null
  };

  const token = jwt.sign(user, process.env.JWT_SECRET, { expiresIn: "7d" });

  // Redirect with token
  res.redirect(`https://teligramlogin.vercel.app/?token=${token}`);
});

// ================== PROTECTED ROUTE ==================
app.get("/api/me", (req, res) => {
  try {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ loggedIn: false });

    const token = auth.split(" ")[1];
    const user = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ loggedIn: true, user });
  } catch {
    res.status(401).json({ loggedIn: false });
  }
});

// ================== SERVER ==================
app.listen(process.env.PORT || 5000, () => {
  console.log("🔥 Server started");
});
