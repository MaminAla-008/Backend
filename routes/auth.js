const express = require("express");
const router = express.Router();
const db = require("../db");

// =========================
// REGISTER
// =========================
router.post("/register", async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({
            message: "Tous les champs sont requis"
        });
    }

    try {
        const result = await db.query(
            `INSERT INTO users (username, email, password)
             VALUES ($1, $2, $3)
             RETURNING id`,
            [username, email, password]
        );

        res.json({
            message: "Compte créé avec succès",
            id: result.rows[0].id
        });

    } catch (err) {
        res.status(400).json({
            message: "Erreur : " + err.message
        });
    }
});


// =========================
// LOGIN
// =========================
router.post("/login", async (req, res) => {
    const { email, password, username, identifier } = req.body;

    const loginIdentifier = identifier || email || username;

    if (!loginIdentifier || !password) {
        return res.status(400).json({
            message: "Identifiant et mot de passe requis"
        });
    }

    try {
        const result = await db.query(
            `SELECT *
             FROM users
             WHERE (email = $1 OR username = $2)
             AND password = $3`,
            [loginIdentifier, loginIdentifier, password]
        );

        const user = result.rows[0];

        if (!user) {
            return res.status(401).json({
                message: "Identifiant ou mot de passe incorrect"
            });
        }

        res.json({
            message: "Connexion réussie",
            user
        });

    } catch (err) {
        res.status(500).json({
            message: err.message
        });
    }
});


// =========================
// ADMIN LOGIN
// =========================
router.post("/admin/login", (req, res) => {
    const { username, password } = req.body;

    if (username === "admin" && password === "admin123") {
        return res.json({
            message: "Connexion administrateur réussie",
            admin: true
        });
    }

    return res.status(401).json({
        message: "Identifiants administrateur incorrects"
    });
});


// =========================
// GET USERS
// =========================
router.get("/users", async (req, res) => {
    try {
        const result = await db.query(
            "SELECT id, username, email FROM users ORDER BY id DESC"
        );

        res.json(result.rows);

    } catch (err) {
        res.status(500).json({
            message: err.message
        });
    }
});


// =========================
// CREATE ORDER
// =========================
router.post("/orders", async (req, res) => {
    const { client, reference, total, items } = req.body;

    if (!client || !reference || !items) {
        return res.status(400).json({
            message: "Données de commande incomplètes"
        });
    }

    try {
        const result = await db.query(
            `INSERT INTO orders
             (client, reference, total, items)
             VALUES ($1, $2, $3, $4)
             RETURNING id`,
            [
                client,
                reference,
                total,
                JSON.stringify(items)
            ]
        );

        res.json({
            message: "Commande enregistrée",
            id: result.rows[0].id,
            reference
        });

    } catch (err) {
        res.status(500).json({
            message: err.message
        });
    }
});


// =========================
// GET ORDERS
// =========================
router.get("/orders", async (req, res) => {
    try {
        const result = await db.query(
            `SELECT id, client, reference, total, items, created_at
             FROM orders
             ORDER BY id DESC`
        );

        const orders = result.rows.map((row) => ({
            ...row,
            items: JSON.parse(row.items)
        }));

        res.json(orders);

    } catch (err) {
        res.status(500).json({
            message: err.message
        });
    }
});


module.exports = router;