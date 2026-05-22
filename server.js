const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const https = require("https");
require("dotenv").config();

const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");

const User = require("./models/User");
const Document = require("./models/Document");
const auth = require("./middleware/auth");
const role = require("./middleware/role");

const app = express();

/* ================= SECURITY MIDDLEWARE ================= */

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  cors({
    origin: [
      "http://127.0.0.1:5500",
      "http://localhost:5500",
      "http://127.0.0.1:5173",
      "http://localhost:5173"
    ],
    credentials: true
  })
);

app.use(helmet());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200
});

app.use(limiter);

/* ================= ENV CHECK ================= */

if (!process.env.JWT_SECRET || process.env.JWT_SECRET === "put_a_strong_generated_secret_here") {
  throw new Error("JWT_SECRET is missing or still using the default placeholder");
}

if (!process.env.MONGO_URI) {
  throw new Error("MONGO_URI is missing in .env file");
}

if (!process.env.FILE_SECRET_KEY || !process.env.FILE_IV) {
  throw new Error("FILE_SECRET_KEY or FILE_IV is missing in .env file");
}

/* ================= DATABASE ================= */

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("DB Connected"))
  .catch((err) => console.log("DB Error:", err));

/* ================= TEST ROUTE ================= */

app.get("/", (req, res) => {
  res.send("Server is running 🚀");
});

/* ================= REGISTER ================= */

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body || {};

  if (!name || !email || !password) {
    return res.status(400).json({
      message: "Name, email, and password are required"
    });
  }

  const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;

  if (!regex.test(password)) {
    return res.status(400).json({
      message: "Weak password"
    });
  }

  try {
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({
        message: "User already exists"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name,
      email,
      password: hashedPassword,
      role: "user"
    });

    await user.save();

    res.json({
      message: "User registered successfully"
    });
  } catch (err) {
    console.log("REGISTER ERROR:", err);

    res.status(500).json({
      message: "Server error",
      error: err.message
    });
  }
});

/* ================= LOGIN ================= */

app.post("/login", async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({
      message: "Email and password are required"
    });
  }

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({
        message: "User not found"
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({
        message: "Wrong password"
      });
    }

    if (user.twoFactorEnabled) {
      return res.json({
        message: "MFA required",
        requiresMFA: true,
        userId: user._id
      });
    }

    const token = jwt.sign(
      {
        id: user._id,
        role: user.role
      },
      process.env.JWT_SECRET,
      {
        expiresIn: process.env.JWT_EXPIRES_IN || "1h"
      }
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        twoFactorEnabled: user.twoFactorEnabled
      }
    });
  } catch (err) {
    console.log("LOGIN ERROR:", err);

    res.status(500).json({
      message: "Server error",
      error: err.message
    });
  }
});

/* ================= MFA ROUTES ================= */

app.post("/mfa/setup", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({
        message: "User not found"
      });
    }

    if (user.twoFactorEnabled) {
      return res.status(400).json({
        message: "MFA is already enabled"
      });
    }

    const secret = speakeasy.generateSecret({
      name: `Secure Vault (${user.email})`
    });

    user.twoFactorSecret = secret.base32;
    await user.save();

    const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);

    res.json({
      message: "MFA setup started",
      qrCodeUrl,
      secret: secret.base32
    });
  } catch (err) {
    res.status(500).json({
      message: "MFA setup failed",
      error: err.message
    });
  }
});

app.post("/mfa/enable", auth, async (req, res) => {
  const { token } = req.body || {};

  if (!token) {
    return res.status(400).json({
      message: "OTP token is required"
    });
  }

  try {
    const user = await User.findById(req.user.id);

    if (!user || !user.twoFactorSecret) {
      return res.status(400).json({
        message: "MFA setup not found"
      });
    }

    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: "base32",
      token,
      window: 1
    });

    if (!verified) {
      return res.status(400).json({
        message: "Invalid OTP"
      });
    }

    user.twoFactorEnabled = true;
    await user.save();

    res.json({
      message: "MFA enabled successfully",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        twoFactorEnabled: user.twoFactorEnabled
      }
    });
  } catch (err) {
    res.status(500).json({
      message: "MFA enable failed",
      error: err.message
    });
  }
});

app.post("/mfa/verify-login", async (req, res) => {
  const { userId, token } = req.body || {};

  if (!userId || !token) {
    return res.status(400).json({
      message: "User ID and OTP are required"
    });
  }

  try {
    const user = await User.findById(userId);

    if (!user || !user.twoFactorSecret || !user.twoFactorEnabled) {
      return res.status(400).json({
        message: "MFA is not enabled for this user"
      });
    }

    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: "base32",
      token,
      window: 1
    });

    if (!verified) {
      return res.status(400).json({
        message: "Invalid or expired OTP"
      });
    }

    const jwtToken = jwt.sign(
      {
        id: user._id,
        role: user.role
      },
      process.env.JWT_SECRET,
      {
        expiresIn: process.env.JWT_EXPIRES_IN || "1h"
      }
    );

    res.json({
      message: "MFA verified. Login successful",
      token: jwtToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        twoFactorEnabled: user.twoFactorEnabled
      }
    });
  } catch (err) {
    res.status(500).json({
      message: "MFA verification failed",
      error: err.message
    });
  }
});

app.post("/mfa/disable", auth, async (req, res) => {
  const { token } = req.body || {};

  if (!token) {
    return res.status(400).json({
      message: "OTP token is required"
    });
  }

  try {
    const user = await User.findById(req.user.id);

    if (!user || !user.twoFactorEnabled) {
      return res.status(400).json({
        message: "MFA is not enabled"
      });
    }

    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: "base32",
      token,
      window: 1
    });

    if (!verified) {
      return res.status(400).json({
        message: "Invalid OTP"
      });
    }

    user.twoFactorEnabled = false;
    user.twoFactorSecret = null;
    await user.save();

    res.json({
      message: "MFA disabled successfully",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        twoFactorEnabled: user.twoFactorEnabled
      }
    });
  } catch (err) {
    res.status(500).json({
      message: "MFA disable failed",
      error: err.message
    });
  }
});

/* ================= DASHBOARD ================= */

app.get("/dashboard", auth, (req, res) => {
  res.json({
    message: "Welcome to dashboard",
    user: req.user
  });
});

/* ================= ADMIN ROUTES ================= */

app.get("/admin/users", auth, role("admin"), async (req, res) => {
  try {
    const users = await User.find()
      .select("-password")
      .sort({ createdAt: -1 });

    res.json(users);
  } catch (err) {
    res.status(500).json({
      message: "Server error",
      error: err.message
    });
  }
});

app.patch("/admin/users/:id/role", auth, role("admin"), async (req, res) => {
  const { role: newRole } = req.body || {};

  const allowedRoles = ["admin", "manager", "user"];

  if (!allowedRoles.includes(newRole)) {
    return res.status(400).json({
      message: "Invalid role"
    });
  }

  try {
    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      { role: newRole },
      { new: true }
    ).select("-password");

    if (!updatedUser) {
      return res.status(404).json({
        message: "User not found"
      });
    }

    res.json({
      message: "User role updated successfully",
      user: updatedUser
    });
  } catch (err) {
    res.status(500).json({
      message: "Server error",
      error: err.message
    });
  }
});

/* ================= FILE UPLOAD SETUP ================= */

if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  }
});

const allowedTypes = [
  "application/pdf",
  "image/png",
  "image/jpeg",
  "text/plain",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
];

const upload = multer({
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error("Invalid file type"), false);
    }

    cb(null, true);
  }
});

/* ================= ENCRYPTION + HASH + SIGNATURE ================= */

const algorithm = "aes-256-ctr";

const secretKey = Buffer.from(process.env.FILE_SECRET_KEY, "hex");
const iv = Buffer.from(process.env.FILE_IV, "hex");

function encryptFile(buffer) {
  const cipher = crypto.createCipheriv(algorithm, secretKey, iv);

  return Buffer.concat([
    cipher.update(buffer),
    cipher.final()
  ]);
}

function decryptFile(buffer) {
  const decipher = crypto.createDecipheriv(algorithm, secretKey, iv);

  return Buffer.concat([
    decipher.update(buffer),
    decipher.final()
  ]);
}

function signHash(hash) {
  return crypto
    .createHmac("sha256", process.env.JWT_SECRET)
    .update(hash)
    .digest("hex");
}

function verifyHashSignature(hash, signature) {
  const expectedSignature = signHash(hash);
  return expectedSignature === signature;
}

/* ================= DOCUMENT ROUTES ================= */

app.post("/upload", auth, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        message: "No file uploaded"
      });
    }

    const fileBuffer = fs.readFileSync(req.file.path);

    const encryptedData = encryptFile(fileBuffer);

    const hash = crypto
      .createHash("sha256")
      .update(encryptedData)
      .digest("hex");

    const signature = signHash(hash);

    fs.writeFileSync(req.file.path, encryptedData);

    const doc = new Document({
      filename: req.file.filename,
      originalName: req.file.originalname,
      path: req.file.path,
      hash,
      signature,
      encrypted: true,
      uploadedBy: req.user.id
    });

    await doc.save();

    res.json({
      message: "File uploaded, encrypted, hashed, and signed successfully",
      documentId: doc._id,
      hash,
      signature
    });
  } catch (err) {
    res.status(500).json({
      message: "Upload failed",
      error: err.message
    });
  }
});

app.get("/documents", auth, async (req, res) => {
  try {
    let documents;

    if (req.user.role === "admin" || req.user.role === "manager") {
      documents = await Document.find()
        .populate("uploadedBy", "name email role")
        .sort({ createdAt: -1 });
    } else {
      documents = await Document.find({ uploadedBy: req.user.id })
        .sort({ createdAt: -1 });
    }

    res.json(documents);
  } catch (err) {
    res.status(500).json({
      message: "Server error",
      error: err.message
    });
  }
});

app.get("/documents/:id/verify", auth, async (req, res) => {
  try {
    const document = await Document.findById(req.params.id);

    if (!document) {
      return res.status(404).json({
        message: "Document not found"
      });
    }

    if (
      req.user.role === "user" &&
      document.uploadedBy.toString() !== req.user.id
    ) {
      return res.status(403).json({
        message: "Access denied"
      });
    }

    if (!fs.existsSync(document.path)) {
      return res.status(404).json({
        message: "File not found on server"
      });
    }

    const encryptedBuffer = fs.readFileSync(document.path);

    const currentHash = crypto
      .createHash("sha256")
      .update(encryptedBuffer)
      .digest("hex");

    const hashMatches = currentHash === document.hash;
    const signatureValid = verifyHashSignature(document.hash, document.signature);

    const result =
      hashMatches && signatureValid ? "Valid" : "Modified or Invalid";

    res.json({
      document: document.originalName,
      storedHash: document.hash,
      currentHash,
      hashMatches,
      signatureValid,
      result
    });
  } catch (err) {
    res.status(500).json({
      message: "Verification failed",
      error: err.message
    });
  }
});

app.get("/documents/:id/download", auth, async (req, res) => {
  try {
    const document = await Document.findById(req.params.id);

    if (!document) {
      return res.status(404).json({
        message: "Document not found"
      });
    }

    if (
      req.user.role === "user" &&
      document.uploadedBy.toString() !== req.user.id
    ) {
      return res.status(403).json({
        message: "Access denied"
      });
    }

    if (!fs.existsSync(document.path)) {
      return res.status(404).json({
        message: "File not found on server"
      });
    }

    const encryptedBuffer = fs.readFileSync(document.path);
    const decryptedBuffer = decryptFile(encryptedBuffer);

    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${document.originalName}"`
    );

    res.send(decryptedBuffer);
  } catch (err) {
    res.status(500).json({
      message: "Download failed",
      error: err.message
    });
  }
});

app.delete("/documents/:id", auth, async (req, res) => {
  try {
    const document = await Document.findById(req.params.id);

    if (!document) {
      return res.status(404).json({
        message: "Document not found"
      });
    }

    if (
      req.user.role === "user" &&
      document.uploadedBy.toString() !== req.user.id
    ) {
      return res.status(403).json({
        message: "Access denied"
      });
    }

    if (fs.existsSync(document.path)) {
      fs.unlinkSync(document.path);
    }

    await Document.findByIdAndDelete(req.params.id);

    res.json({
      message: "Document deleted successfully"
    });
  } catch (err) {
    res.status(500).json({
      message: "Delete failed",
      error: err.message
    });
  }
});

/* ================= START SERVER ================= */

const PORT = process.env.PORT || 3000;

const keyPath = path.join(__dirname, "certs", "server.key");
const certPath = path.join(__dirname, "certs", "server.cert");

if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
  const httpsOptions = {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath)
  };

  https.createServer(httpsOptions, app).listen(PORT, () => {
    console.log(`HTTPS Server running on port ${PORT}`);
  });
} else {
  app.listen(PORT, () => {
    console.log(`HTTP Server running on port ${PORT}`);
  });
}