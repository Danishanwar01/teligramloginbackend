const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Telegram verification
function verifyTelegramLogin(data) {
  const botToken = process.env.BOT_TOKEN;

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

app.post("/api/auth/telegram", (req, res) => {
  const data = req.body;

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
    username: data.username,
    photo: data.photo_url
  };

  const token = jwt.sign(user, process.env.JWT_SECRET, {
    expiresIn: "7d"
  });

  res.json({ success: true, token, user });
});

app.listen(process.env.PORT || 5000, () => {
  console.log(`🚀 Server running on http://localhost:5000`);
});
