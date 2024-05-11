import { db } from "../db.js";
import bcrypt from "bcryptjs";

export const register = (req, res) => {
    // Check existing user
    const q = "SELECT * FROM users WHERE email = ? OR username = ?";
    db.query(q, [req.body.email, req.body.name], (err, data) => {
        if (err) return res.json(err);
        if (data.length) return res.status(409).json("User already exists");

        // Hash the password
        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(req.body.password, salt);

        // Insert user with hashed password
        const sql = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
        db.query(sql, [req.body.username, req.body.email, hash], (err, data) => {
            if (err) {
                console.error('Error while signing up: ', err);
                return res.status(500).json({ error: 'An error occurred while signing up' });
            }
            console.log('Signup successful:', data);
            return res.status(200).json("User has been created successfully!");
        });
    });
};

export const login = (req, res) => {};

export const logout = (req, res) => {};
