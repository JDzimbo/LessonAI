const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");

const app = express();
const PORT = 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Create/open database
const db = new Database("lessonai.db");

// Create users table
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

// Test route
app.get("/", (req, res) => {
    res.json({
        message: "LessonAI Backend is running successfully!"
    });
});

// REGISTER USER
app.post("/api/register", async (req, res) => {
    try {
        const {
            fullname,
            email,
            phone,
            accountType,
            password
        } = req.body;

        // Check required fields
        if (!fullname || !email || !accountType || !password) {
            return res.status(400).json({
                success: false,
                message: "Please fill in all required fields."
            });
        }

        // Check if email already exists
        const existingUser = db
            .prepare("SELECT id FROM users WHERE email = ?")
            .get(email);

        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: "An account with this email already exists."
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save user
        const result = db.prepare(`
            INSERT INTO users
            (fullname, email, phone, accountType, password)
            VALUES (?, ?, ?, ?, ?)
        `).run(
            fullname,
            email,
            phone || "",
            accountType,
            hashedPassword
        );

        res.status(201).json({
            success: true,
            message: "Account created successfully!",
            userId: result.lastInsertRowid
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            success: false,
            message: "Server error. Please try again."
        });
    }
});

// LOGIN USER
app.post("/api/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "Email and password are required."
            });
        }

        // Find user
        const user = db
            .prepare("SELECT * FROM users WHERE email = ?")
            .get(email);

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password."
            });
        }

        // Compare password
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

        res.json({
            success: true,
            message: "Login successful!",
            user: {
                id: user.id,
                fullname: user.fullname,
                email: user.email,
                accountType: user.accountType
            }
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            success: false,
            message: "Server error. Please try again."
        });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`LessonAI server running at http://localhost:${PORT}`);
});