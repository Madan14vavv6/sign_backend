import mysql from "mysql2/promise";
import dotenv from "dotenv";

dotenv.config();

let pool = null;

function buildConfigFromUrl(urlStr) {
  const u = new URL(urlStr);
  const cfg = {
    host: u.hostname,
    port: u.port ? Number(u.port) : 3306,
    user: decodeURIComponent(u.username),
    password: decodeURIComponent(u.password),
    database: decodeURIComponent(u.pathname.replace(/^\//, "")) || "defaultdb",
    waitForConnections: true,
    connectionLimit: 10,
  };
  const sslMode = u.searchParams.get("ssl-mode");
  if (sslMode && sslMode.toUpperCase().includes("REQUIRED")) {
    cfg.ssl = {};
  }
  return cfg;
}

export async function initDb() {
  const url = process.env.DATABASE_URL;
  if (!url) return false;
  const cfg = buildConfigFromUrl(url);
  pool = mysql.createPool(cfg);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT NOT NULL AUTO_INCREMENT,
      username VARCHAR(100) NOT NULL,
      email VARCHAR(255) NOT NULL UNIQUE,
      phone VARCHAR(20) NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);
  return true;
}

export function dbEnabled() {
  return Boolean(pool);
}

export async function findUserByEmail(email) {
  if (!pool) return null;
  const [rows] = await pool.query(
    "SELECT id, username, email, phone, password_hash FROM users WHERE email=? LIMIT 1",
    [email]
  );
  return rows[0] || null;
}

export async function insertUser({ username, email, phone, passwordHash }) {
  if (!pool) return null;
  await pool.query(
    "INSERT INTO users (username, email, phone, password_hash) VALUES (?, ?, ?, ?)",
    [username, email, phone, passwordHash]
  );
  return true;
}
