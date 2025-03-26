const dotenv = require('dotenv');
const jwt = require("jsonwebtoken");
dotenv.config();

const verifyToken = (req, res, next) => {
  var token = req.headers["authorization"];
  if (!token) return res.status(403).json({ message: "No token provided" });
  if (token.startsWith("Bearer ")) {
    token = token.slice(7, token.length);
  }
  console.log(token);
//   console.log(process.env.JWT);
  jwt.verify(token, process.env.JWT, (err, decoded) => {
    
    if (err) return res.status(401).json({ message: "Unauthorized",error: err });
    req.userId = decoded.id;
    next();
  });
};

module.exports = verifyToken;