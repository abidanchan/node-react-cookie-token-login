require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cookieParser());

// Allow frontend requests
// app.use(
//   cors({
//     origin: "http://localhost:3000",
//     credentials: true,
//   })
// );

app.use(
  cors({
    origin: "http://localhost:3000", // ✅ No trailing slash
    credentials: true, // ✅ Allow cookies
    methods: ["GET", "POST", "PUT", "DELETE"], // ✅ Allow these methods
    allowedHeaders: ["Content-Type", "Authorization"], // ✅ Allow necessary headers
  })
);
// **Connect to MySQL**
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) console.error("Database connection failed:", err);
  else console.log("Connected to MySQL");
});

// **Generate JWT**
const generateToken = (user) => jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "25m" });
const generateRefreshToken = (user) => jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "7d" });



// **Register**
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.query("INSERT INTO users (email, password) VALUES (?, ?)", [email, hashedPassword], (err) => {
    if (err) return res.status(400).json({ message: "User already exists" });
    res.json({ message: "User registered successfully" });
  });
});

// **Login**
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
    if (err || results.length === 0) return res.status(401).json({ message: "Invalid credentials" });

    const user = results[0];
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) return res.status(401).json({ message: "Invalid credentials" });

    const token = generateToken(user);
    const refreshToken = generateRefreshToken(user);

    res.cookie("access_token", token, { httpOnly: true, secure: false });
    res.cookie("refresh_token", refreshToken, { httpOnly: true, secure: false });

    res.json({ message: `${token} Login successful` });
  });
});

// **Middleware to verify JWT**
const authenticateUser = (req, res, next) => {
  const token = req.cookies.access_token;
  if (!token) return res.status(401).json({ message: "Unauthorized" });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
};

// **Fetch User**
app.get("/user", authenticateUser, (req, res) => {

  // db.query("SELECT id, email FROM users WHERE id = ?", [req.user.id], (err, results) => {
  //   if (err) return res.status(500).json({ message: "Error fetching user" });
  //   res.json(results[0]);
   db.query("SELECT * FROM users" ,(err, results) => {
    if (err) return res.status(500).json({ message: "Error fetching user" });
    res.json(results[0]);
  });

});

// **Refresh Token**
app.post("/refresh", (req, res) => {
  const refreshToken = req.cookies.refresh_token;
  if (!refreshToken) return res.status(401).json({ message: "No refresh token" });

  jwt.verify(refreshToken, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid refresh token" });

    const newToken = generateToken(user);
    res.cookie("access_token", newToken, { httpOnly: true, secure: false });
    res.json({ message: "Token refreshed" });
  });
});

// **Logout**
app.post("/logout", (req, res) => {
  res.clearCookie("access_token");
  res.clearCookie("refresh_token");
  res.json({ message: "Logged out" });
});

// **Root Route (Now placed after middleware definition)**
app.get("/", (req, res) => {
  res.json({ message: "Server running" });
});

// **Start Server**
app.listen(process.env.PORT, () => console.log(`Server running on port ${process.env.PORT}`));