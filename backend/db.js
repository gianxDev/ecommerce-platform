import { Pool } from "pg";
import dotenv from "dotenv";
dotenv.config(); //allow us to run environment variables using process.env

const { DB_USER, DB_HOST, DB_NAME, DB_PASSWORD, DB_PORT } = process.env;

if (!DB_USER || !DB_HOST || !DB_NAME || !DB_PASSWORD || !DB_PORT) {
  throw new Error("Missing database environment variables");
}

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: Number(process.env.DB_PORT),
  max: 10, //max 10 connections in the pool
  idleTimeoutMillis: 30_000, //close connection if unused for 30 seconds
  connectionTimeoutMillis: 5_000, //give up trying to connect after 5 seconds
});

pool.on("error", (err) => {
  console.error("db pool error:", err);
});

export default pool;
