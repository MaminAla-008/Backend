const express = require("express");
const router = express.Router();

const db = require("../db");

// =====================================================
// REGISTER
// =====================================================

router.post("/register", async (req, res) => {

    console.log("📥 REGISTER :", req.body);

    const {
        username,
        email,
        password
    } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({
            message: "Tous les champs sont requis"
        });
    }

    try {

        const existingUser = await db.query(
            `
            SELECT id
            FROM users
            WHERE email = $1
            `,
            [email]
        );

        if (existingUser.rows.length > 0) {
            return res.status(400).json({
                message: "Cette adresse existe déjà"
            });
        }

        const result = await db.query(
            `
            INSERT INTO users
            (
                username,
                email,
                password
            )
            VALUES
            (
                $1,
                $2,
                $3
            )
            RETURNING id, username, email
            `,
            [
                username,
                email,
                password
            ]
        );

        console.log("✅ Compte créé :", result.rows[0]);

        res.status(201).json({
            message: "Compte créé avec succès",
            user: result.rows[0]
        });

    } catch (err) {

        console.error(
            "❌ Erreur inscription :",
            err
        );

        res.status(500).json({
            message: "Erreur serveur lors de la création du compte"
        });
    }
});


// =====================================================
// LOGIN
// =====================================================

router.post("/login", async (req, res) => {

    console.log("📥 LOGIN :", req.body);

    const {
        identifier,
        username,
        email,
        password
    } = req.body;

    const loginIdentifier =
        identifier ||
        username ||
        email;

    if (!loginIdentifier || !password) {
        return res.status(400).json({
            message: "Identifiant et mot de passe requis"
        });
    }

    try {

        const result = await db.query(
            `
            SELECT
                id,
                username,
                email
            FROM users
            WHERE
                (
                    username = $1
                    OR email = $1
                )
                AND password = $2
            `,
            [
                loginIdentifier,
                password
            ]
        );

        const user = result.rows[0];

        if (!user) {
            return res.status(401).json({
                message: "Identifiant ou mot de passe incorrect"
            });
        }

        console.log("✅ Connexion réussie :", user);

        res.json({
            message: "Connexion réussie",
            user
        });

    } catch (err) {

        console.error(
            "❌ Erreur connexion :",
            err
        );

        res.status(500).json({
            message: "Erreur serveur"
        });
    }
});


// =====================================================
// ADMIN LOGIN
// =====================================================

router.post("/admin/login", (req, res) => {

    const {
        username,
        password
    } = req.body;

    if (
        username === "admin" &&
        password === "admin123"
    ) {
        return res.json({
            message: "Connexion administrateur réussie",
            admin: true
        });
    }

    return res.status(401).json({
        message: "Identifiants administrateur incorrects"
    });
});


// =====================================================
// GET USERS
// =====================================================

router.get("/users", async (req, res) => {

    try {

        const result = await db.query(
            `
            SELECT
                id,
                username,
                email
            FROM users
            ORDER BY id DESC
            `
        );

        res.json(result.rows);

    } catch (err) {

        console.error(
            "❌ Erreur utilisateurs :",
            err
        );

        res.status(500).json({
            message: "Erreur serveur"
        });
    }
});


// =====================================================
// CREATE ORDER
// =====================================================

router.post("/orders", async (req, res) => {

    const {
        client,
        reference,
        total,
        items
    } = req.body;

    if (!client || !reference || items === undefined) {
        return res.status(400).json({
            message: "Données de commande incomplètes"
        });
    }

    try {

        const result = await db.query(
            `
            INSERT INTO orders
            (
                client,
                reference,
                total,
                items
            )
            VALUES
            (
                $1,
                $2,
                $3,
                $4
            )
            RETURNING id
            `,
            [
                client,
                reference,
                total || 0,
                JSON.stringify(items)
            ]
        );

        res.status(201).json({
            message: "Commande enregistrée",
            id: result.rows[0].id,
            reference
        });

    } catch (err) {

        console.error(
            "❌ Erreur commande :",
            err
        );

        res.status(500).json({
            message: "Erreur serveur"
        });
    }
});


// =====================================================
// GET ORDERS
// =====================================================

router.get("/orders", async (req, res) => {

    try {

        const result = await db.query(
            `
            SELECT
                id,
                client,
                reference,
                total,
                items,
                created_at
            FROM orders
            ORDER BY id DESC
            `
        );

        const orders = result.rows.map((row) => {

            let items = [];

            try {
                items = JSON.parse(row.items);
            } catch {
                items = [];
            }

            return {
                ...row,
                items
            };
        });

        res.json(orders);

    } catch (err) {

        console.error(
            "❌ Erreur commandes :",
            err
        );

        res.status(500).json({
            message: "Erreur serveur"
        });
    }
});


module.exports = router;