
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const jwt = require("jsonwebtoken");
const OpenAI = require("openai");

const app = express();
const PORT = process.env.PORT || 5000;

// Set these in Render's environment settings and your local .env.
// Never put secret values directly in this file.
const JWT_SECRET = process.env.JWT_SECRET;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
    console.error("JWT_SECRET is missing or too short. Configure a strong secret.");
    process.exit(1);
}

// Security middleware
app.use(helmet());

const allowedOrigins = [
    "https://jdzimbo.github.io",
    "https://lessonai-qoqr.onrender.com",
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "http://localhost:5000"
];
app.use(cors({
    origin: function (origin, callback) {
        // Allow requests without an Origin header, such as health checks.
        if (!origin || allowedOrigins.includes(origin)) {
            return callback(null, true);
        }
        return callback(new Error("Origin not allowed by CORS"));
    }
}));

app.use(express.json({ limit: "20kb" }));
app.use(express.static(__dirname + "/.."));
app.use(express.static(__dirname + "/../public"));

// Database
const db = new Database("lessonai.db");

db.pragma("journal_mode = WAL");

db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fullname TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT,
        accountType TEXT NOT NULL,
        password TEXT NOT NULL,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`).run();

console.log("Database connected successfully.");

const openai = OPENAI_API_KEY
    ? new OpenAI({ apiKey: OPENAI_API_KEY })
    : null;



// Serve the landing page at the root
app.get("/", (req, res) => {
    res.sendFile(__dirname + "/../index.html");
});

// Health check endpoint (moved off root)
app.get("/health", (req, res) => {
    res.json({
        success: true,
        message: "LessonAI backend is running."
    });
});


// Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({
            success: false,
            message: "Access denied. Please log in."
        });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({
                success: false,
                message: "Invalid or expired token."
            });
        }

        req.user = decoded;
        next();
    });
}

// Register
app.post("/api/register", async (req, res) => {
    try {
        const fullname = typeof req.body.fullname === "string"
            ? req.body.fullname.trim()
            : "";
        const email = typeof req.body.email === "string"
            ? req.body.email.trim().toLowerCase()
            : "";
        const phone = typeof req.body.phone === "string"
            ? req.body.phone.trim()
            : "";
        const accountType = req.body.accountType;
        const password = req.body.password;

        if (!fullname || !email || !accountType || !password) {
            return res.status(400).json({
                success: false,
                message: "Please fill in all required fields."
            });
        }

        if (fullname.length > 100 || email.length > 254 || phone.length > 30) {
            return res.status(400).json({
                success: false,
                message: "One or more fields are too long."
            });
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({
                success: false,
                message: "Please enter a valid email address."
            });
        }

        if (!["teacher", "school"].includes(accountType)) {
            return res.status(400).json({
                success: false,
                message: "Please select a valid account type."
            });
        }

        if (typeof password !== "string" ||
            password.length < 8 ||
            password.length > 72) {
            return res.status(400).json({
                success: false,
                message: "Password must be at least 8 characters and no more than 72 characters."
            });
        }

        const existingUser = db.prepare(
            "SELECT id FROM users WHERE email = ?"
        ).get(email);

        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: "An account with this email already exists."
            });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const result = db.prepare(`
            INSERT INTO users
            (fullname, email, phone, accountType, password)
            VALUES (?, ?, ?, ?, ?)
        `).run(fullname, email, phone, accountType, hashedPassword);

        return res.status(201).json({
            success: true,
            message: "Account created successfully!",
            userId: result.lastInsertRowid
        });
    } catch (error) {
        if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
            return res.status(409).json({
                success: false,
                message: "An account with this email already exists."
            });
        }

        console.error("Registration error:", error.message);
        return res.status(500).json({
            success: false,
            message: "Registration failed. Please try again."
        });
    }
});

// Login
app.post("/api/login", async (req, res) => {
    try {
        const email = typeof req.body.email === "string"
            ? req.body.email.trim().toLowerCase()
            : "";
        const password = req.body.password;

        if (!email || typeof password !== "string" || !password) {
            return res.status(400).json({
                success: false,
                message: "Email and password are required."
            });
        }

        const user = db.prepare(
            "SELECT * FROM users WHERE email = ?"
        ).get(email);

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password."
            });
        }

        const passwordMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!passwordMatch) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password."
            });
        }

        const token = jwt.sign(
            {
                userId: user.id,
                email: user.email,
                accountType: user.accountType
            },
            JWT_SECRET,
            { expiresIn: "2h" }
        );

        return res.json({
            success: true,
            message: "Login successful!",
            token: token,
            user: {
                id: user.id,
                fullname: user.fullname,
                email: user.email,
                accountType: user.accountType
            }
        });
    } catch (error) {
        console.error("Login error:", error.message);
        return res.status(500).json({
            success: false,
            message: "Login failed. Please try again."
        });
    }
});

// Generate lesson note
app.post("/api/generate-lesson", authenticateToken, async (req, res) => {
    try {
        if (!openai) {
            return res.status(503).json({
                success: false,
                message: "AI service is not configured."
            });
        }

        const {
            subject,
            className,
            topic,
            term,
            duration,
            objectives,
            instructions
        } = req.body;

        if (
            typeof subject !== "string" || !subject.trim() ||
            typeof className !== "string" || !className.trim() ||
            typeof topic !== "string" || !topic.trim()
        ) {
            return res.status(400).json({
                success: false,
                message: "Subject, class and lesson topic are required."
            });
        }

        const fields = [
            subject, className, topic, term, duration,
            objectives, instructions
        ];

        if (fields.some(value =>
            value != null && (typeof value !== "string" || value.length > 5000)
        )) {
            return res.status(400).json({
                success: false,
                message: "One or more lesson fields are invalid or too long."
            });
        }

        const prompt = `
You are an expert Nigerian school teacher and professional lesson-note writer.

Create a complete lesson note suitable for a Nigerian classroom.

Subject: ${subject}
Class: ${className}
Topic: ${topic}
Term: ${term || "Not specified"}
Duration: ${duration || "Not specified"}

Learning Objectives:
${objectives || "Create suitable learning objectives."}

Additional Instructions:
${instructions || "Use simple explanations, examples and classroom activities."}

Use this structure:
1. Lesson Topic
2. Subject
3. Class
4. Term
5. Duration
6. Learning Objectives
7. Previous Knowledge
8. Instructional Materials
9. Introduction
10. Lesson Presentation
11. Teacher's Activities
12. Students' Activities
13. Evaluation
14. Assignment
15. Conclusion

Use clear language and relevant examples. Return only the lesson note.
`;

        const response = await openai.responses.create({
            // Use a model available to your OpenAI API account.
            model: process.env.OPENAI_MODEL || "gpt-4.1-mini",
            input: prompt
        });

        const lesson = response.output_text;

        if (!lesson) {
            return res.status(502).json({
                success: false,
                message: "The AI did not return a lesson note."
            });
        }

        return res.json({
            success: true,
            lesson: lesson
        });
    } catch (error) {
        console.error("Lesson generation error:", error.message);
        return res.status(500).json({
            success: false,
            message: "Failed to generate lesson note. Please try again."
        });
    }
});

// Handle unexpected errors without exposing internal details
app.use((err, req, res, next) => {
    if (err.message === "Origin not allowed by CORS") {
        return res.status(403).json({
            success: false,
            message: "This website is not allowed to access the server."
        });
    }

    console.error("Request error:", err.message);
    return res.status(500).json({
        success: false,
        message: "An unexpected server error occurred."
    });
});

app.listen(PORT, "0.0.0.0", () => {
    console.log(`LessonAI server running on port ${PORT}`);
});
