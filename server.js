const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

dotenv.config();

const app = express();

// ✅ CORS - Allow all origins for debugging
app.use(cors({
  origin: "*", // Temporarily allow all for testing
  methods: ["GET", "POST", "OPTIONS"],
  credentials: true
}));

app.use(express.json());

// Log all requests
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

function verifyTelegramLogin(data) {
  const botToken = process.env.BOT_TOKEN;
  console.log("Bot Token exists:", !!botToken);
  
  if (!botToken) {
    console.error("BOT_TOKEN not found in environment");
    return false;
  }

  const secretKey = crypto
    .createHash("sha256")
    .update(botToken)
    .digest();

  // Create check string
  const checkString = Object.keys(data)
    .filter(key => key !== "hash")
    .sort()
    .map(key => `${key}=${data[key]}`)
    .join("\n");

  console.log("Check String:", checkString);

  const hmac = crypto
    .createHmac("sha256", secretKey)
    .update(checkString)
    .digest("hex");

  console.log("Calculated Hash:", hmac);
  console.log("Received Hash:", data.hash);

  return hmac === data.hash;
}

app.post("/api/auth/telegram", (req, res) => {
  console.log("🔵 Telegram Auth Request Received");
  console.log("Request Body:", req.body);

  const data = req.body;

  if (!data || !data.hash) {
    console.error("❌ No hash in request");
    return res.status(400).json({ 
      message: "Invalid payload",
      received: data 
    });
  }

  // Check auth date
  const now = Math.floor(Date.now() / 1000);
  if (now - data.auth_date > 86400) {
    console.error("❌ Auth expired");
    return res.status(401).json({ 
      message: "Auth expired",
      auth_date: data.auth_date,
      current_time: now 
    });
  }

  // Verify Telegram data
  const isValid = verifyTelegramLogin(data);
  console.log("Verification Result:", isValid);

  if (!isValid) {
    console.error("❌ Invalid Telegram data");
    return res.status(401).json({ 
      message: "Invalid Telegram data",
      verification_failed: true 
    });
  }

  // Create user object
  const user = {
    telegramId: data.id,
    name: data.first_name + (data.last_name ? ' ' + data.last_name : ''),
    username: data.username || null,
    photo: data.photo_url || null
  };

  console.log("✅ User authenticated:", user);

  // Create JWT token
  const token = jwt.sign(user, process.env.JWT_SECRET, {
    expiresIn: "7d"
  });

  // Send success response
  return res.json({
    success: true,
    message: "Login successful",
    token,
    user,
    timestamp: new Date().toISOString()
  });
});

// Test endpoint
app.get("/api/test", (req, res) => {
  res.json({
    status: "Backend is running",
    bot_token_set: !!process.env.BOT_TOKEN,
    timestamp: new Date().toISOString()
  });
});

app.get("/", (req, res) => {
  res.send(`
    <html>
      <head><title>Telegram Auth Backend</title></head>
      <body>
        <h1>🚀 Telegram Auth Backend is running</h1>
        <p>Endpoints:</p>
        <ul>
          <li><a href="/api/test">/api/test</a> - Test endpoint</li>
          <li>POST /api/auth/telegram - Telegram auth</li>
        </ul>
        <p>Bot Token: ${process.env.BOT_TOKEN ? 'Set ✅' : 'Not Set ❌'}</p>
        <p>JWT Secret: ${process.env.JWT_SECRET ? 'Set ✅' : 'Not Set ❌'}</p>
      </body>
    </html>
  `);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`
  ==========================================
  🚀 Server running on port ${PORT}
  ==========================================
  Bot Token: ${process.env.BOT_TOKEN ? 'Loaded' : 'NOT LOADED!'}
  JWT Secret: ${process.env.JWT_SECRET ? 'Loaded' : 'NOT LOADED!'}
  ==========================================
  `);
});