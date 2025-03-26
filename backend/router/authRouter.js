const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("../dataBase/db");
const router = express.Router();


router.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.query(
    "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
    [name, email, hashedPassword],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "User registered successfully!" });
    }
  );
});

router.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(401).json({ message: "User not found!" });

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user.id }, process.env.JWT, { expiresIn: "1h" });
    res.json({ message: "Login successful!", token });
  });
});

const verifyToken = (req, res, next) => {
  var token = req.headers["authorization"];
  if (!token) return res.status(403).json({ message: "No token provided" });
  if (token.startsWith("Bearer ")) {
    token = token.slice(7, token.length);
  }
  console.log(token);
  jwt.verify(token, process.env.JWT, (err, decoded) => {
    
    if (err) return res.status(401).json({ message: "Unauthorized",error: err });
    req.userId = decoded.id;
    next();
  });
};

router.get("/profile", verifyToken, (req, res) => {
  db.query("SELECT id, name, email FROM users WHERE id = ?", [req.userId], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(result[0]);
  });
});



module.exports = router;
