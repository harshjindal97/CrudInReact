const mysql = require("mysql2");
const dotenv = require("dotenv");

dotenv.config();

const db = mysql.createConnection({
    host: process.env.LocalHost,
    user: process.env.UserName,
    password: process.env.PasswordDb,
    database: process.env.NameDb,
  });

db.connect((err) => {
  if (err) {
    console.error("Database connection failed:", err);
    process.exit(1);
  }
  console.log("MySQL Database Connected!");
});

module.exports = db;