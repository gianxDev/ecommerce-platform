import express from "express";
import { param, query, body, validationResult } from "express-validator";
import bcrypt from "bcryptjs";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import pool from "./db.js";
import dotenv from "dotenv";
import { rateLimit } from "express-rate-limit";
import helmet from "helmet";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(express.json());
app.use(cookieParser());

pool
  .query("SELECT 1")
  .then(() => console.log("database connected ✅"))
  .catch((err) => console.log("disconnected database ❌", err));

const rateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  message: {
    message: "Too many attempts. Try again later.",
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

function authorize(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        message: "Forbidden",
      });
    }
    next();
  };
}

function authTokenCreation(user) {
  const payload = {
    id: user.id,
    role: user.role,
  };

  const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: "15m",
  });

  const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
    expiresIn: "7d",
  });

  return { accessToken, refreshToken };
}

function authSetCookies(res, accessToken, refreshToken) {
  res.cookie("accessToken", accessToken, {
    maxAge: 15 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
  });

  res.cookie("refreshToken", refreshToken, {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
  });
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
      [ email ],
    );

    if (findUser.rows.length > 0) {
      return res.status(409).json({
        message: "User already exists!",
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
        [ email, hashedPassword ],
      );

      const user = createUser.rows[ 0 ];

      const { accessToken, refreshToken } = authTokenCreation(user);

      const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

      const expiration = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

      await client.query(
        `INSERT INTO session 
      (user_id, refresh_token_hash, expires_at) 
      VALUES ($1, $2, $3)`,
        [ user.id, hashedRefreshToken, expiration ],
      );

      await client.query("COMMIT");

      authSetCookies(res, accessToken, refreshToken);
    } catch (error) {
      await client.query("ROLLBACK");

      console.error(error);

      return res.status(500).json({
        message: "Internal server error",
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
      [ email ],
    );

    if (findUser.rows.length === 0) {
      return res.status(401).json({
        message: "Invalid credentials",
      });
    }

    const user = findUser.rows[ 0 ];
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).json({
        message: "Invalid credentials",
      });
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      const { accessToken, refreshToken } = authTokenCreation(user);

      const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

      const expiration = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

      await client.query(
        `INSERT INTO session 
      (user_id, refresh_token_hash, expires_at) 
      VALUES ($1, $2, $3)`,
        [ user.id, hashedRefreshToken, expiration ],
      );

      await client.query("COMMIT");

      authSetCookies(res, accessToken, refreshToken);
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
    console.error("verifying token", error);
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
    [ decoded.id ],
  );

  res.clearCookie("accessToken", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
  });

  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
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
    `SELECT id, user_id, expires_at, refresh_token_hash, created_at, revoke_at
     FROM session 
     WHERE user_id = $1 AND revoke_at IS NULL
    `,
    [ decoded.id ],
  );

  if (findUserSession.rows.length === 0) {
    return res.status(401).json({
      message: "Invalid session",
    });
  }

  const userSession = findUserSession.rows[ 0 ];

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
    [ decoded.id ],
  );

  if (checkUser.rows.length === 0) {
    return res.status(404).json({
      message: "User not found",
    });
  }

  const user = checkUser.rows[ 0 ];

  if (!user.is_active) {
    return res.status(401).json({
      message: "User is inactive",
    });
  }

  const { accessToken: newAccessToken, refreshToken: newRefreshToken } =
    authTokenCreation(user);

  const hashedNewRefreshToken = await bcrypt.hash(newRefreshToken, 10);
  const expiration = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  await pool.query(
    `UPDATE session 
     SET refresh_token_hash = $1, 
         expires_at = $2 
     WHERE id = $3 AND revoke_at IS NULL
    `,
    [ hashedNewRefreshToken, expiration, userSession.id ],
  );

  authSetCookies(res, newAccessToken, newRefreshToken);

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
    [ id ],
  );

  return res.status(200).json({
    user: findUser.rows[ 0 ],
  });
});

app.get(
  "/products",
  [
    query("page").optional().isInt({ min: 1 }),

    query("limit").optional().isInt({ min: 5, max: 100 }),

    query("sort").optional().isInt([ "name", "price", "stock" ]),

    query("category").optional().trim().isLength({ min: 1, max: 100 }),

    query("search").optional().trim().isLength({ min: 1, max: 100 }),
  ],
  async (req, res) => {
    const { category, sort, search, page = "1", limit = "20" } = req.query;

    const pageNumber = Number(page);
    const limitNumber = Number(limit);
    const offset = (pageNumber - 1) * limitNumber;

    let sql = `SELECT * FROM products `;
    const values = []; //container of values for query placeholders

    if (category && search) {
      sql += `
        WHERE 
        category = $1 
        AND 
        name ILIKE $2 `;

      values.push(category, `%${search}%`);
    } else if (category) {
      sql += `WHERE category = $1 `;
      values.push(category);
    } else if (search) {
      sql += `WHERE name ILIKE $1 `;
      values.push(`%${search}%`);
    }

    let sortColumn;

    switch (sort) {
      case "name":
        sortColumn = "name";
        break;

      case "price":
        sortColumn = "price";
        break;

      case "stock":
        sortColumn = "stock";
        break;

      default:
        sortColumn = "id";
    }

    if (sort) {
      sql += `ORDER BY ${sortColumn}`;
    }

    sql += `
  LIMIT $${values.length + 1}
  OFFSET $${values.length + 2}
  `;

    values.push(limitNumber, offset);

    const requestedProducts = await pool.query(sql, values);

    if (requestedProducts.rows.length === 0) {
      return res.status(404).json({
        message: "Product not found"
      })
    }

    return res.status(200).json({
      page: pageNumber,
      limit: limitNumber,
      products: requestedProducts.rows,
    });
  },
);

app.get("/products/:id",
  [
    param("productId").notEmpty().isInt({ min: 1 })
  ],
  async (req, res) => {
    const productId = req.params.id;

    const product = await pool.query(
      `SELECT * 
    FROM products 
    WHERE id = $1
    `,
      [ productId ],
    );

    if (product.rows.length === 0) {
      return res.status(404).json({
        message: "This item is no longer available",
      });
    }

    return res.status(200).json({
      product: product.rows[ 0 ],
    });
  });

app.post(
  "/products",
  authenticate,
  authorize("admin"),
  [
    body("name")
      .trim()
      .notEmpty()
      .withMessage("Name must not be empty")
      .bail()
      .isLength({ min: 1, max: 100 })
      .withMessage("Name must be between  1 - 100 characters"),

    body("price")
      .notEmpty()
      .withMessage("Price must not be empty")
      .bail()
      .isFloat({ min: 0 })
      .withMessage("Price must be decimal"),

    body("stock")
      .notEmpty()
      .withMessage("Stock must not be empty")
      .bail()
      .isInt({ min: 0 })
      .withMessage("Stock must be integer and cannot be negative"),

    body("category")
      .trim()
      .notEmpty()
      .withMessage("Category must not be empty")
      .bail()
      .isLength({ min: 1, max: 100 })
      .withMessage("Category must be between 1 - 100 characters"),
  ],
  async (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array(),
      });
    }

    const { name, price, stock, description, category } = req.body;

    const findProducts = await pool.query(
      `SELECT * 
       FROM products 
       WHERE name = $1 AND
             price = $2 AND
             stock = $3 AND
             description = $4 AND
             category = $5
      `,
      [ name, price, stock, description, category ],
    );

    if (findProducts.rows.length > 0) {
      return res.status(409).json({
        message: "Product already exists",
      });
    }

    const result = await pool.query(
      `INSERT INTO products 
       (name, price, stock, description, category) 
       VALUES ($1, $2, $3, $4, $5)
       RETURNING name, price, stock, description, category
      `,
      [ name, price, stock, description, category ],
    );

    return res.status(201).json({
      message: "Successfully created",
      product: result.rows[ 0 ],
    });
  },
);

app.delete(
  "/products/:id",
  authenticate,
  authorize("admin"),
  async (req, res) => {
    const productId = req.params.id;
    const deletedProduct = await pool.query(
      `
       DELETE FROM 
       products WHERE id = $1
       RETURNING *
      `,
      [ productId ],
    );

    if (deletedProduct.rows.length === 0) {
      return res.status(404).json({
        message: "Product not found",
      });
    }

    return res.status(200).json({
      message: "product deleted",
      deletedProduct,
    });
  }
);

app.listen(PORT, () => {
  console.log(`Server is running on port: ${PORT}`);
});
