const express = require("express");
const app = express();
const port = process.env.PORT || 3000;
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const passport = require("passport");
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;

app.use(express.json());
app.use(passport.initialize());

const JWT_SECRET = "your-secret-key";

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: JWT_SECRET,
};

passport.use(
  new JwtStrategy(jwtOptions, (jwt_payload, done) => {
    const user = users.find((u) => u.userHandle === jwt_payload.userHandle);
    if (user) {
      return done(null, user);
    }
    return done(null, false);
  })
);

const authenticateToken = passport.authenticate("jwt", { session: false });

// In-memory storage (use a database like postgres or mongodb in production)
let users = [];
let highScores = [];

// Reset function for testing
app.resetData = () => {
  users = [];
  highScores = [];
};

// Helper function for password hashing
const hashPassword = (password) => {
  return crypto.createHash("sha256").update(password).digest("hex");
};

// Signup endpoint
app.post("/signup", async (req, res) => {
  try {
    const { userHandle, password } = req.body;

    // Basic validation for necessary fields first
    if (!userHandle || !password) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // Type validation only if values exist
    if (typeof userHandle !== "string" || typeof password !== "string") {
      return res.status(400).json({ error: "Invalid input types" });
    }

    // Length validation
    if (userHandle.length < 6 || password.length < 6) {
      return res
        .status(400)
        .json({ error: "Invalid userHandle or password length" });
    }

    const hashedPassword = hashPassword(password);
    users.push({ userHandle, password: hashedPassword });

    res.status(201).send();
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ error: "Server error" });
  }
});
// Login endpoint
app.post("/login", async (req, res) => {
  try {
    // Check for additional fields
    const allowedFields = ["userHandle", "password"];
    const receivedFields = Object.keys(req.body);
    if (
      receivedFields.length > allowedFields.length ||
      !receivedFields.every((field) => allowedFields.includes(field))
    ) {
      return res.status(400).json({ error: "Invalid request body" });
    }

    const { userHandle, password } = req.body;

    // Basic validation for necessary fields
    if (!userHandle || !password) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // Type validation
    if (typeof userHandle !== "string" || typeof password !== "string") {
      return res.status(400).json({ error: "Invalid input types" });
    }

    // Empty string validation
    if (userHandle.trim() === "" || password.trim() === "") {
      return res.status(400).json({ error: "Invalid input" });
    }

    // Find user
    const user = users.find((u) => u.userHandle === userHandle);
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Verify password
    const hashedPassword = hashPassword(password);
    if (hashedPassword !== user.password) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Generate JWT
    const token = jwt.sign({ userHandle }, JWT_SECRET);
    res.json({ jsonWebToken: token });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Post high score endpoint
app.post("/high-scores", authenticateToken, (req, res) => {
  const { level, score, userHandle, timestamp } = req.body;

  // Validate all required fields from the request body
  if (!level || typeof score !== "number" || !userHandle || !timestamp) {
    return res.status(400).json({ error: "Invalid request body" });
  }

  // Validate timestamp format (ISO 8601)
  if (!Date.parse(timestamp)) {
    return res.status(400).json({ error: "Invalid timestamp format" });
  }

  // Verify that the userHandle matches the one in the JWT token
  if (userHandle !== req.user.userHandle) {
    return res.status(400).json({ error: "Invalid userHandle" });
  }

  const highScore = {
    level,
    userHandle,
    score,
    timestamp,
  };

  highScores.push(highScore);
  res.status(201).send();
});
// Get high scores endpoint
app.get("/high-scores", (req, res) => {
  const { level, page = 1 } = req.query;

  if (!level) {
    return res.status(400).json({ error: "Level parameter is required" });
  }

  const pageSize = 20;
  const filteredScores = highScores
    .filter((score) => score.level === level)
    .sort((a, b) => b.score - a.score);

  const startIndex = (page - 1) * pageSize;
  const paginatedScores = filteredScores.slice(
    startIndex,
    startIndex + pageSize
  );

  res.json(paginatedScores);
});

//------ WRITE YOUR SOLUTION ABOVE THIS LINE ------//

let serverInstance = null;
module.exports = {
  start: function () {
    serverInstance = app.listen(port, () => {
      console.log(`Example app listening at http://localhost:${port}`);
    });
  },
  close: function () {
    serverInstance.close();
  },
};
