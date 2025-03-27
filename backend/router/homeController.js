const express = require("express");
const db = require("../dataBase/db");
const verifyToken = require("../middleware/verifyJWT");
const router = express.Router();

router.get("/profile", verifyToken, (req, res) => {
  db.query("SELECT id, name, email FROM users WHERE id = ?", [req.userId], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(result[0]);
  });
});

module.exports = router;