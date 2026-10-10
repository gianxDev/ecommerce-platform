import express from "express";
import { body, validationResult } from "express-validator";
import bcrypt from "bcryptjs";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import pool from "./db.js";
import dotenv from "dotenv";
import { rateLimit } from "express-rate-limit";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cookieParser());

const rateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  message: {
    message: "Too many login attempts. Try again later.",
  },
  standardHeaders: "draft-8",
  legacyHeaders: false,
});

function authenticate(req, res, next) {
  const { accessToken } = req.cookies;

  if (!accessToken) {
    return res.status(401).json({
      message: "Authentication required",
    });
  }

  let decoded;

  try {
    decoded = jwt.verify(accessToken, process.env.JWT_SECRET);

    req.user = decoded;

    next();
  } catch (error) {
    console.error(error);
    return res.status(401).json({
      message: "Invalid or expired token",
    });
  }
}

app.post(
  "/register",
  rateLimiter,

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
         (email, password_hash) 
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
  rateLimiter,

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

app.post("/logout", async (req, res) => {
  const { refreshToken } = req.cookies;

  let decoded;

  try {
    decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
  } catch (error) {
    console.error("verifying token error: ", error);
    return res.status(401).json({
      message: "Invalid or expired token",
    });
  }

  await pool.query(
    `UPDATE session 
     SET revoke_at = NOW() 
     WHERE user_id = $1 AND 
     revoke_at IS NULL
    `,
    [decoded.id],
  );

  res.clearCookie("accessToken", {
    httpOnly: true,
    secure: false,
    sameSite: "strict",
  });

  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: false,
    sameSite: "strict",
  });

  return res.sendStatus(204);
});

app.post("/refresh-token", async (req, res) => {
  const { refreshToken } = req.cookies;

  if (!refreshToken) {
    return res.status(401).json({
      message: "Refresh token required",
    });
  }

  let decoded;

  try {
    decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
  } catch (error) {
    console.error("refresh token error: ", error);
    return res.status(401).json({
      message: "Invalid or expired token",
    });
  }

  const findUserSession = await pool.query(
    `SELECT user_id, expires_at, refresh_token_hash, created_at, revoke_at
     FROM session 
     WHERE user_id = $1 AND revoke_at IS NULL
    `,
    [decoded.id],
  );

  if (findUserSession.rows.length === 0) {
    return res.status(401).json({
      message: "Invalid session",
    });
  }

  const userSession = findUserSession.rows[0];

  if (new Date(userSession.expires_at) <= new Date()) {
    return res.status(401).json({
      message: "Session has expired",
    });
  }

  const isMatch = await bcrypt.compare(
    refreshToken,
    userSession.refresh_token_hash,
  );

  if (!isMatch) {
    return res.status(401).json({
      message: "Invalid refresh token",
    });
  }

  const checkUser = await pool.query(
    `SELECT id, role, is_active 
         FROM users 
         WHERE id = $1
        `,
    [decoded.id],
  );

  const user = checkUser.rows[0];

  if (!user.is_active) {
    return res.status(401).json({
      message: "User is inactive",
    });
  }

  const newAccessToken = jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "15m" },
  );

  const newRefreshToken = jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: "7d" },
  );

  const hashedNewRefreshToken = await bcrypt.hash(newRefreshToken, 10);
  const expiration = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  await pool.query(
    `UPDATE session 
     SET refresh_token_hash = $1, 
         expires_at = $2 
     WHERE id = $3 AND revoke_at IS NULL
    `,
    [hashedNewRefreshToken, expiration, userSession.id],
  );

  res.cookie("accessToken", newAccessToken, {
    maxAge: 15 * 60 * 1000,
    httpOnly: true,
    secure: false,
    sameSite: "strict",
  });

  res.cookie("refreshToken", newRefreshToken, {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: false,
    sameSite: "strict",
  });

  return res.status(200).json({
    message: "Access token refreshed",
  });
});

app.get("/me", authenticate, async (req, res) => {
  const { id } = req.user;

  const findUser = await pool.query(
    `SELECT id, email, name, role, created_at 
     FROM users 
     WHERE id = $1
    `,
    [id],
  );

  return res.status(200).json({
    user: findUser.rows[0],
  });
});

app.listen(PORT, () => {
  console.log(`Server is running on port: ${PORT}`);
});
