const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

dotenv.config();

const app = express();

app.use(cors({
  origin: "*",
  methods: ["GET"],
}));

// logger
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

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

// ✅ TELEGRAM CALLBACK (GET ONLY)
app.get("/api/auth/telegram", (req, res) => {
  console.log("✅ Telegram callback hit");
  console.log("Query:", req.query);

  const data = req.query;

  if (!data.hash) {
    return res.status(400).send("Invalid Telegram payload");
  }

  const now = Math.floor(Date.now() / 1000);
  if (now - data.auth_date > 86400) {
    return res.status(401).send("Auth expired");
  }

  if (!verifyTelegramLogin(data)) {
    return res.status(401).send("Telegram verification failed");
  }

  const user = {
    telegramId: data.id,
    name: data.first_name + (data.last_name ? ` ${data.last_name}` : ""),
    username: data.username,
    photo: data.photo_url
  };

  const token = jwt.sign(user, process.env.JWT_SECRET, {
    expiresIn: "7d"
  });

  // 🔁 redirect BACK to frontend with token
  res.redirect(
    `https://teligramlogin.vercel.app/?token=${token}`
  );
});

app.get("/", (req, res) => {
  res.send("Telegram Auth Backend Running");
});

app.listen(process.env.PORT || 5000, () => {
  console.log("🚀 Server running");
});
