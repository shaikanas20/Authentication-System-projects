const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(bodyParser.json());

// 🔐 Secret key for signing JWT
const SECRET_KEY = "supersecretkey";

// 👥 Sample user data with roles
const users = [
  { id: 1, username: "adminuser", password: "admin123", role: "Admin" },
  { id: 2, username: "moduser", password: "mod123", role: "Moderator" },
  { id: 3, username: "normaluser", password: "user123", role: "User" }
];

/**
 * @route   POST /login
 * @desc    Authenticate user & return JWT token
 * @access  Public
 */
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);

  if (!user) return res.status(401).json({ message: "Invalid credentials" });

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    SECRET_KEY,
    { expiresIn: "1h" }
  );

  res.json({
    message: "Login successful",
    username: user.username,
    role: user.role,
    token
  });
});

// 🧩 Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Token missing" });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid or expired token" });
    req.user = user;
    next();
  });
};

// 🧩 Middleware to authorize user roles
const authorizeRoles = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: "Access denied: insufficient role" });
    }
    next();
  };
};

/**
 * @route   GET /admin-dashboard
 * @desc    Access restricted to Admin users only
 * @access  Private (Admin)
 */
app.get("/admin-dashboard", verifyToken, authorizeRoles("Admin"), (req, res) => {
  res.json({
    message: "Welcome to the Admin dashboard.",
    user: req.user
  });
});

/**
 * @route   GET /moderator-panel
 * @desc    Access restricted to Moderators only
 * @access  Private (Moderator)
 */
app.get("/moderator-panel", verifyToken, authorizeRoles("Moderator"), (req, res) => {
  res.json({
    message: "Welcome to the Moderator panel.",
    user: req.user
  });
});

/**
 * @route   GET /user-profile
 * @desc    Accessible by all logged-in users
 * @access  Private (Admin, Moderator, User)
 */
app.get("/user-profile", verifyToken, authorizeRoles("Admin", "Moderator", "User"), (req, res) => {
  res.json({
    message: "Welcome to your profile.",
    user: req.user
  });
});

app.listen(3000, () => console.log("✅ Server running on http://localhost:3000"));
