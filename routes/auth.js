const express = require("express");
const router = express.Router();
const db = require("../db");

router.post("/register", (req, res) => {
    const { username, email, password } = req.body;

    db.run(
        "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
        [username, email, password],
        function (err) {
            if(err) {
                return res.status(400).json({message : "Erreur : " + err.message});
            }

            res.json({
                message: "Compte créé avec succès",
                id: this.lastID,
            });
        }
    );
});

router.post("/login", (req, res) => {
    const { email, password, username, identifier } = req.body;
    const loginIdentifier = identifier || email || username;

    if (!loginIdentifier || !password) {
        return res.status(400).json({message: "Identifiant et mot de passe requis"});
    }

    db.get(
        "SELECT * FROM users WHERE (email = ? OR username = ?) AND password = ?",
        [loginIdentifier, loginIdentifier, password],
        (err, user) => {
            if (err || !user) {
                return res.status(401).json({message: "Identifiant ou mot de passe incorrect"});
            }
            res.json({
                message: "Connexion reussite",
                user,
            });
        }
    );
});

router.post("/admin/login", (req, res) => {
    const { username, password } = req.body;

    if (username === "admin" && password === "admin123") {
        return res.json({
            message: "Connexion administrateur réussie",
            admin: true,
        });
    }

    return res.status(401).json({ message: "Identifiants administrateur incorrects" });
});

router.get("/users", (req, res) => {
    db.all("SELECT id, username, email FROM users", [], (err, rows) => {
        if (err) {
            return res.status(500).json({ message: err.message });
        }

        res.json(rows);
    });
});

router.post("/orders", (req, res) => {
    const { client, reference, total, items } = req.body;

    if (!client || !reference || !items) {
        return res.status(400).json({ message: "Données de commande incomplètes" });
    }

    db.run(
        "INSERT INTO orders (client, reference, total, items) VALUES (?, ?, ?, ?)",
        [client, reference, total, JSON.stringify(items)],
        function (err) {
            if (err) {
                return res.status(500).json({ message: err.message });
            }

            res.json({
                message: "Commande enregistrée",
                id: this.lastID,
                reference,
            });
        }
    );
});

router.get("/orders", (req, res) => {
    db.all("SELECT id, client, reference, total, items, created_at FROM orders ORDER BY id DESC", [], (err, rows) => {
        if (err) {
            return res.status(500).json({ message: err.message });
        }

        res.json(rows.map((row) => ({
            ...row,
            items: JSON.parse(row.items),
        })));
    });
});

module.exports = router;