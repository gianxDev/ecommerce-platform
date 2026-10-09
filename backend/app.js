import express from "express";
import { body, validationResult } from "express-validator";
import bcrypt from "bcryptjs";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import pool from "./db.js";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cookieParser());

app.post(
  "/register",

  [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("Enter your email")
      .bail()
      .isEmail()
      .withMessage("Invalid email")
      .normalizeEmail(),

    body("password")
      .notEmpty()
      .withMessage("Enter a password")
      .bail()
      .isLength({ min: 8, max: 72 })
      .withMessage("Password must be 8 - 72 characters"),
  ],
  async (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array(),
      });
    }

    const { email, password } = req.body;

    const findUser = await pool.query(
      `SELECT 1 
         FROM users 
         WHERE email = $1
        `,
      [email],
    );

    if (findUser.rows.length > 0) {
      return res.status(409).json({
        message: "This email is already registered",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const createUser = await client.query(
        `INSERT INTO users 
         (email, password_hash,) 
         VALUES ($1, $2)
         RETURNING id, role
        `,
        [email, hashedPassword],
      );

      const user = createUser.rows[0];

      const accessToken = jwt.sign(
        { id: user.id, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: "15m" },
      );

      const refreshToken = jwt.sign(
        { id: user.id, role: user.role },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: "7d" },
      );

      const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

      const expiration = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

      await client.query(
        `INSERT INTO session 
      (user_id, refresh_token_hash, expires_at) 
      VALUES ($1, $2, $3)`,
        [user.id, hashedRefreshToken, expiration],
      );

      await client.query("COMMIT");

      res.cookie("accessToken", accessToken, {
        maxAge: 15 * 60 * 1000,
        httpOnly: true,
        secure: false,
        sameSite: "strict",
      });

      res.cookie("refreshToken", refreshToken, {
        maxAge: 7 * 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: false,
        sameSite: "strict",
      });
    } catch (error) {
      await client.query("ROLLBACK");

      console.error(error);

      return res.status(500).json({
        message: "Something went wrong",
      });
    } finally {
      client.release();
    }

    return res.status(201).json({
      message: "Registration successful. You are now logged in.",
    });
  },
);

app.post(
  "/login",

  [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("Enter your email")
      .bail()
      .isEmail()
      .withMessage("Invalid email")
      .normalizeEmail(),

    body("password").trim().notEmpty().withMessage("Enter your password"),
  ],
  async (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array(),
      });
    }

    const { email, password } = req.body;

    const findUser = await pool.query(
      `SELECT *
         FROM users 
         WHERE email = $1
        `,
      [email],
    );

    if (findUser.rows.length === 0) {
      return res.status(401).json({
        message: "Invalid credentials",
      });
    }

    const user = findUser.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).json({
        message: "Invalid credentials",
      });
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      const accessToken = jwt.sign(
        { id: user.id, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: "15m" },
      );

      const refreshToken = jwt.sign(
        { id: user.id, role: user.role },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: "7d" },
      );

      const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

      const expiration = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

      await client.query(
        `INSERT INTO session 
      (user_id, refresh_token_hash, expires_at) 
      VALUES ($1, $2, $3)`,
        [user.id, hashedRefreshToken, expiration],
      );

      await client.query("COMMIT");

      res.cookie("accessToken", accessToken, {
        maxAge: 15 * 60 * 1000,
        httpOnly: true,
        secure: false,
        sameSite: "strict",
      });

      res.cookie("refreshToken", refreshToken, {
        maxAge: 7 * 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: false,
        sameSite: "strict",
      });
    } catch (error) {
      await client.query("ROLLBACK");
      console.error("from login transac error: ", error);
      return res.status(500).json({
        message: "Something went wrong",
      });
    } finally {
      client.release();
    }

    return res.status(200).json({
      message: "Login successfull",
    });
  },
);

app.listen(PORT, () => {
  console.log(`Server is running on port: ${PORT}`);
});
