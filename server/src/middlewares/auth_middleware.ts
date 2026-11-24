
import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { UserDocument, UserModel } from "../models/user_model";

// JWT secret must be configured in environment variables.
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is not configured");
}

interface AuthRequest extends Request {
  user?: Pick<UserDocument, "_id" | "role">;
}

export const authenticate = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      res.status(401).json({
        message: "Authentication required",
      });
      return;
    }

    const token = authHeader.split(" ")[1];

    if (!token) {
      res.status(401).json({
        message: "Authentication token missing",
      });
      return;
    }

    const decoded = jwt.verify(token, JWT_SECRET) as {
      id: string;
      role: string;
    };

    // Always fetch the current role from the database.
    // Never trust the role supplied inside the JWT.
    const user = await UserModel.findById(decoded.id).select(
      "_id role isActive"
    );

    if (!user || !user.isActive) {
      res.status(401).json({
        message: "Invalid or inactive account",
      });
      return;
    }

    req.user = {
      _id: user._id,
      role: user.role,
    };

    next();
  } catch (error) {
    res.status(401).json({
      message: "Invalid or expired token",
    });
  }
};

export const authorizeRole = (...allowedRoles: string[]) => {
  return (
    req: AuthRequest,
    res: Response,
    next: NextFunction
  ): void => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      res.status(403).json({
        message: "Access forbidden: insufficient role",
      });
      return;
    }

    next();
  };
};
