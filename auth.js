// ============================================================================
// IMPORTS
// ============================================================================

import express from "express";
import mongoose from "mongoose";
import crypto from "crypto";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import Redis from "ioredis";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
// ============================================================================
// APP INITIALIZATION
// ============================================================================

const app = express();

dotenv.config({ quiet: true });

// ============================================================================
// DATABASE CONNECTIONS
// ============================================================================

const connectdb = async () => {
  try {
    console.log("trying to connect to sealinedb ......");
    await mongoose.connect(process.env.CLOUDDB_URL);
    console.log("DB sealinedb connected");
  } catch (err) {
    console.log(err);
  }
};

const redis = new Redis({
  host: "localhost",
  port: 6379,
});

// ============================================================================
// USER SCHEMA & MODEL
// ============================================================================

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
  },

  password: {
    type: String,
    required: true,
  },

  typed: {
    type: String,
    enum: ["s", "d"],
    required: true,
  },

  created_at: {
    type: Date,
    default: Date.now,
  },
});

const User = mongoose.model("User", userSchema);

// ============================================================================
// REFRESH TOKEN SCHEMA & MODEL
// ============================================================================

const refershTokenSchema = new mongoose.Schema({
  token_hash: {
    type: String,
    required: true,
    unique: true,
  },

  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
  },

  role: {
    type: String,
    required: true,
  },

  revoked: {
    type: Boolean,
    default: false,
  },

  revoked_at: {
    type: Date,
  },

  expires_at: {
    type: Date,
    required: true,
  },

  created_at: {
    type: Date,
    default: Date.now,
  },
});

const refreshTokenModel = mongoose.model("RefreshToken", refershTokenSchema);

// ============================================================================
// AUTH HANDLERS
// ============================================================================

// ---------------------------------------------------------------------------
// LOGIN
// ---------------------------------------------------------------------------

const login = async (req, res) => {
  const { username, password } = req.body;

  try {
    console.log("user try to login ....");
    console.log(`username : ${username} , password : ${password}`);

    const user = await User.findOne({ username });

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid password" });
    }
    const existingTokens = await refreshTokenModel.find({
      user_id: user._id,
      revoked: false,
    });

    if (existingTokens.length > 0) {
      return res.status(409).json({
        success: false,
        message: "User already loggedii in",
      });
    }
    console.log("Login successful");

    const rawRefreshToken = crypto.randomBytes(32).toString("hex");

    console.log(`Refresh Token ${rawRefreshToken}`);

    const hashedRefreshToken = crypto
      .createHash("sha256")
      .update(rawRefreshToken)
      .digest("hex");

    console.log(`Hashed Refresh Token : ${hashedRefreshToken}`);

    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    const dbEntry = await refreshTokenModel.create({
      token_hash: hashedRefreshToken,
      user_id: user._id,
      typed: user.typed,
      role: "user",
      revoked: false,
      expires_at: expiresAt,
    });

    console.log(`Mongodb entry : ${dbEntry}`);

    await redis.set(
      `session:${hashedRefreshToken}`,
      JSON.stringify({
        user_id: user._id,
        typed: user.typed,
        role: "user",
      }),
      "EX",
      60 * 60 * 24 * 7,
    );

    const accessToken = jwt.sign(
      {
        uuid: user._id,
        typed: user.typed,
        role: "user",
      },
      process.env.jwt_key,
      {
        expiresIn: "15m",
      },
    );

    res.cookie("refreshToken", rawRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      path: "/auth",
      domain: "aquavern.com",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({
      success: true,
      data: {
        username: user.username,
        role: "user",
        created_at: user.created_at,
      },
      accessToken: accessToken,
    });
  } catch (err) {
    if (err?.code == 11000) {
      console.log("user already logged in");

      return res.status(409).json({
        success: false,
        message: "user already logged in",
      });
    }

    console.log(err);

    return res.status(500).json({
      success: false,
      message: "internal server error",
    });
  }
};

// ---------------------------------------------------------------------------
// REFRESH ACCESS TOKEN
// ---------------------------------------------------------------------------

const refresh = async (req, res) => {
  const rawRefreshToken = req.cookies.refreshToken;

  const { user_id } = req.body;

  try {
    if (!rawRefreshToken) {
      return res.status(401).json({ sucess: false, message: "no token" });
    }

    const hashedRefreshToken = crypto
      .createHash("sha256")
      .update(rawRefreshToken)
      .digest("hex");

    let storedSessionData = await redis.get(`session:${hashedRefreshToken}`);

    if (!storedSessionData) {
      console.log("CACHE miss");

      storedSessionData = await refreshTokenModel.findOne({
        user_id: user_id,
        token_hash: hashedRefreshToken,
      });

      if (!storedSessionData) {
        return res.status(401).json({
          success: false,
          message: "Invalid rtoken",
        });
      }

      if (
        storedSessionData.revoked ||
        storedSessionData.expires_at < new Date()
      ) {
        await refreshTokenModel.findOneAndUpdate(
          {
            token_hash: hashedRefreshToken,
          },
          {
            $set: {
              revoked: true,
              revoked_at: new Date(),
            },
          },
        );

        return res.status(401).json({
          message: "Token revoked or expired",
        });
      }

      const remainingTtl = Math.floor(
        (storedSessionData.expires_at - new Date()) / 1000,
      );

      await redis.set(
        `session:${hashedRefreshToken}`,
        JSON.stringify({
          user_id: storedSessionData.user_id,
          role: "user",
        }),
        "EX",
        remainingTtl,
      );
    } else {
      storedSessionData = JSON.parse(storedSessionData);
    }

    const accessToken = jwt.sign(
      {
        uuid: storedSessionData.user_id,
        role: "user",
        typed: storedSessionData.typed,
      },
      process.env.jwt_key,
      {
        expiresIn: "15m",
      },
    );

    res.json({
      accessToken: accessToken,
    });
  } catch (err) {
    console.log(err);

    res.status(500).json("Internal server error.");
  }
};

// ---------------------------------------------------------------------------
// VERIFY ACCESS TOKEN
// ---------------------------------------------------------------------------

const verify = async (req, res) => {
  const accessToken = req.headers.authorization.split(" ")[1];
  try {
    if (!accessToken) {
      return res.status(401).json({ message: "No token" });
    }

    const decoded = jwt.verify(accessToken, process.env.jwt_key);

    console.log(decoded);

    return res.status(200).json({
      valid: true,
      uuid: decoded.uuid,
      role: decoded.role,
    });
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({
        valid: false,
        message: "Token expired",
      });
    }

    if (err.name === "JsonWebTokenError") {
      return res.status(401).json({
        valid: false,
        message: "Invalid token",
      });
    }

    res.status(500).json({
      message: "Internal server error",
    });
  }
};

// ---------------------------------------------------------------------------
// LOGOUT
// ---------------------------------------------------------------------------

const logout = async (req, res) => {
  const rawRefreshToken = req.cookies.refreshToken;

  try {
    if (!rawRefreshToken) {
      return res.status(401).json({
        success: false,
        message: "no session found",
      });
    }

    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      path: "/auth",
      domain: "aquavern.com",
    });

    const hashedRefreshToken = crypto
      .createHash("sha256")
      .update(rawRefreshToken)
      .digest("hex");
    //check if the refresh Token exist
    await redis.del(`session:${hashedRefreshToken}`);

    await refreshTokenModel.updateOne(
      {
        token_hash: hashedRefreshToken,
      },
      {
        $set: {
          revoked: true,
          revoked_at: new Date(),
        },
      },
    );

    return res.status(200).json({
      success: true,
      message: "logged out successfully",
    });
  } catch (err) {
    console.log(err);

    return res.status(500).json({
      success: false,
      message: "internal server error",
    });
  }
};

// ============================================================================
// MIDDLEWARE
// ============================================================================

app.use(express.json());
app.use(cookieParser());
// ============================================================================
// ROUTES
// ============================================================================

app.post(
  "/login",
  (req, res, next) => {
    console.log("here");
    next();
  },
  login,
);
app.post("/logout", logout);
app.post("/refresh", refresh);
app.post("/verify", verify);

// ============================================================================
// SERVER STARTUP
// ============================================================================

await connectdb();

app.listen(3001, () => {
  console.log("auth online");
});
