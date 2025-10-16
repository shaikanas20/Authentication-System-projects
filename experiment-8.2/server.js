// Import dependencies
const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require("cors");
const morgan = require("morgan"); // For logging requests

// Initialize the app
const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(morgan("dev")); // Logs request details to console

// Secret key for JWT
const SECRET_KEY = "mysecretkey123";

// Sample user data (can be replaced with database)
const user = {
  id: 1,
  username: "anas",
  password: "anas123",
  email: "anas@gmail.com",
  role: "admin"
};

// ------------------ LOGIN ROUTE ------------------
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // Basic input validation
  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required" });
  }

  // Check credentials
  if (username === user.username && password === user.password) {
    // Create a JWT token
    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        role: user.role,
        email: user.email
      },
      SECRET_KEY,
      { expiresIn: "1h" } // Token expires in 1 hour
    );

    return res.status(200).json({
      message: "Login successful",
      token,
      user: { id: user.id, username: user.username, role: user.role }
    });
  }

  return res.status(401).json({ message: "Invalid credentials" });
});

// ------------------ TOKEN VERIFICATION MIDDLEWARE ------------------
const verifyToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Extract token

  if (!token) {
    return res.status(401).json({ message: "Token missing. Please provide a valid JWT token." });
  }

  jwt.verify(token, SECRET_KEY, (err, decodedUser) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }
    req.user = decodedUser; // Store user info in request
    next();
  });
};

// ------------------ PROTECTED ROUTE ------------------
app.get("/protected", verifyToken, (req, res) => {
  res.json({
    message: "You have accessed a protected route successfully!",
    user: req.user,
    timestamp: new Date()
  });
});

// ------------------ ROLE-BASED PROTECTED ROUTE ------------------
app.get("/admin", verifyToken, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Access denied. Admins only." });
  }

  res.json({
    message: "Welcome Admin!",
    adminData: {
      totalUsers: 15,
      serverStatus: "Running",
      lastLogin: "2025-10-14T18:30:00Z"
    }
  });
});

// ------------------ LOGOUT (Client-side simulation) ------------------
app.post("/logout", (req, res) => {
  res.json({
    message: "Logout successful. Please discard your JWT token manually on the client."
  });
});

// ------------------ SERVER ------------------
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
