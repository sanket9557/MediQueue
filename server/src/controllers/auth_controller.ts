
import { Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { UserModel } from "../models/user_model";
import { UserRole } from "../types/system.types";

const JWT_SECRET = process.env.JWT_SECRET || "default_jwt_secret_mediqueue_2026";
const TOKEN_EXPIRATION = "24h";

export const register = async (req: Request, res: Response): Promise<void> => {
  try {
    const { name, email, password, phone } = req.body;

    if (!name || !email || !password || !phone) {
      res.status(400).json({ message: "Please provide all required fields." });
      return;
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      res.status(400).json({ message: "Please provide a valid email address." });
      return;
    }

    // Password validation
    if (password.length < 6) {
      res.status(400).json({
        message: "Password must be at least 6 characters long.",
      });
      return;
    }

    // Phone number validation
    const phoneRegex = /^\d{10}$/;
    if (!phoneRegex.test(phone)) {
      res.status(400).json({
        message: "Phone number must be exactly 10 digits.",
      });
      return;
    }

    // Public registration always creates a PATIENT account.
    // Admin and Doctor roles cannot be assigned through public registration.
    const requestedRole = UserRole.PATIENT;

    const existingUser = await UserModel.findOne({ email });

    if (existingUser) {
      res.status(409).json({
        message: "An account with this email already exists.",
      });
      return;
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const newUserPayload = {
      name,
      email,
      phone,
      passwordHash,
      role: requestedRole,
    };

    const user = await UserModel.create(newUserPayload);

    // Filter out password from response
    const userToReturn = {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      specialty: user.specialization,
    };

    const token = jwt.sign(
      { id: user._id, role: user.role },
      JWT_SECRET,
      { expiresIn: TOKEN_EXPIRATION }
    );

    res.status(201).json({
      message: "User registered successfully",
      user: userToReturn,
      token,
    });
  } catch (error: any) {
    console.error("Register error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

export const login = async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password, role } = req.body;

    if (!email || !password) {
      res.status(400).json({
        message: "Email and password are required.",
      });
      return;
    }

    const user = await UserModel.findOne({ email }).select("+passwordHash");

    if (!user) {
      res.status(401).json({ message: "Invalid credentials." });
      return;
    }

    if (!user.isActive) {
      res.status(403).json({
        message: "Your account has been deactivated.",
      });
      return;
    }

    // Verify the selected login role against the actual database role
    if (role && user.role !== role.toUpperCase()) {
      res.status(401).json({
        message: `No ${role} account found with that email.`,
      });
      return;
    }

    const isMatch = await bcrypt.compare(
      password,
      user.passwordHash || ""
    );

    if (!isMatch) {
      res.status(401).json({ message: "Invalid credentials." });
      return;
    }

    const token = jwt.sign(
      { id: user._id, role: user.role },
      JWT_SECRET,
      { expiresIn: TOKEN_EXPIRATION }
    );

    const userToReturn = {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      specialization: user.specialization,
    };

    res.status(200).json({
      message: "Login successful",
      user: userToReturn,
      token,
    });
  } catch (error: any) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

export const getMe = async (req: any, res: Response): Promise<void> => {
  try {
    if (!req.user || !req.user._id) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    const user = await UserModel.findById(req.user._id).select(
      "-passwordHash"
    );

    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    res.status(200).json({
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      specialization: user.specialization,
    });
  } catch (error: any) {
    console.error("getMe error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};
