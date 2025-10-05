const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const JWT_SECRET = process.env.JWT_SECRET;

// ✅ নতুন পাসওয়ার্ড তৈরি
app.post("/set_password", async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: "Missing password" });

  const hash = await bcrypt.hash(password, 10);
  const result = await pool.query(
    "INSERT INTO password_keys (pwd_hash) VALUES ($1) RETURNING id",
    [hash]
  );
  res.json({ success: true, id: result.rows[0].id });
});

// ✅ লগইন সিস্টেম
app.post("/login", async (req, res) => {
  const { password, device_id } = req.body;
  if (!password || !device_id)
    return res.status(400).json({ error: "Missing fields" });

  const result = await pool.query("SELECT * FROM password_keys");
  let found = null;
  for (const row of result.rows) {
    const match = await bcrypt.compare(password, row.pwd_hash);
    if (match) {
      found = row;
      break;
    }
  }

  if (!found) return res.status(401).json({ error: "Invalid password" });

  if (!found.assigned_device_id) {
    await pool.query(
      "UPDATE password_keys SET assigned_device_id = $1 WHERE id = $2",
      [device_id, found.id]
    );
  } else if (found.assigned_device_id !== device_id) {
    return res
      .status(403)
      .json({ error: "Password already used on another device" });
  }

  const token = jwt.sign({ id: found.id, device_id }, JWT_SECRET, {
    expiresIn: "1h",
  });
  res.json({ token });
});

app.listen(process.env.PORT || 3000, () =>
  console.log("✅ Server running...")
);
