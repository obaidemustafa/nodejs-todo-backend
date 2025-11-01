// ===============================
// Secure Authentication Controller
// ===============================
require("dotenv").config();
const db = require("../models");
const User = db.user;

const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { validationResult } = require("express-validator");
const logger = require("../utils/logger"); // (Use Winston or console fallback)

// -------------------------------
// REGISTER USER
// -------------------------------
exports.register = async (req, res, next) => {
  try {
    // Validate request data
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: "Invalid input", errors: errors.array() });
    }

    const { username, email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "Email already registered" });
    }

    // Strong password hashing
    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    const newUser = new User({
      username: username.trim(),
      email: email.toLowerCase().trim(),
      password: hashedPassword,
      role: "user",
    });

    await newUser.save();

    logger.info(`New user registered: ${email}`);
    return res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    logger.error(`Registration Error: ${err.message}`);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

// -------------------------------
// LOGIN USER
// -------------------------------
exports.login = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: "Invalid input", errors: errors.array() });
    }

    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Validate password
    const passwordIsValid = await bcrypt.compare(password, user.password);
    if (!passwordIsValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Generate JWT
    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h", algorithm: "HS256" }
    );

    // Send token in HttpOnly cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 60 * 60 * 1000, // 1 hour
    });

    logger.info(`User logged in: ${email}`);
    return res.status(200).json({
      message: "Login successful",
      user: { id: user._id, username: user.username, email: user.email, role: user.role },
    });
  } catch (err) {
    logger.error(`Login Error: ${err.message}`);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

// -------------------------------
// GET USER DATA (Protected Route)
// -------------------------------
exports.getUserData = async (req, res, next) => {
  try {
    const user = await User.findById(req.userId).select("-password").exec();
    if (!user) return res.status(404).json({ message: "User not found" });
    res.status(200).json({ user });
  } catch (err) {
    logger.error(`GetUserData Error: ${err.message}`);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

// -------------------------------
// LOGOUT USER
// -------------------------------
exports.logout = async (req, res) => {
  try {
    res.clearCookie("token");
    return res.status(200).json({ message: "Logout successful" });
  } catch (err) {
    logger.error(`Logout Error: ${err.message}`);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};
