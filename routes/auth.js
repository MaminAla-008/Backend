const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { timingSafeEqual } = require("node:crypto");
const router = express.Router();

const db = require("../db");
const { processDetectedPayment } = require("../services/mvolaPayments");
const isProduction =
    process.env.NODE_ENV === "production" ||
    process.env.RENDER === "true";
const jwtSecret =
    process.env.JWT_SECRET ||
    (isProduction ? "" : "shopix-local-admin-secret");

const requireAdmin = (req, res, next) => {
    if (!jwtSecret) {
        return res.status(503).json({
            message: "Le serveur doit être configuré avec JWT_SECRET."
        });
    }

    const authorization = req.get("authorization") || "";
    const [scheme, token] = authorization.split(" ");

    if (scheme !== "Bearer" || !token) {
        return res.status(401).json({
            message: "Authentification administrateur requise."
        });
    }

    try {
        const payload = jwt.verify(token, jwtSecret, {
            algorithms: ["HS256"]
        });

        if (typeof payload !== "object" || payload.role !== "admin") {
            return res.status(403).json({
                message: "Accès réservé à l’administrateur."
            });
        }

        return next();
    } catch (err) {
        return res.status(401).json({
            message: "Session administrateur invalide ou expirée."
        });
    }
};

const requireMvolaWebhook = (req, res, next) => {
    const expectedSecret = process.env.MVOLA_WEBHOOK_SECRET || "";
    const receivedSecret = req.get("x-mvola-webhook-secret") || "";
    const expected = Buffer.from(expectedSecret);
    const received = Buffer.from(receivedSecret);

    if (expected.length < 32) {
        return res.status(503).json({
            message: "La liaison avec le détecteur MVola nécessite un secret d’au moins 32 caractères."
        });
    }

    if (expected.length !== received.length || !timingSafeEqual(expected, received)) {
        return res.status(401).json({
            message: "Authentification du détecteur MVola invalide."
        });
    }

    return next();
};

// =====================================================
// REGISTER
// =====================================================

router.post("/register", async (req, res) => {
    const {
        username,
        phone,
        password
    } = req.body || {};
    const rawPhone = phone || username;
    const phoneInput = typeof rawPhone === "string" ? rawPhone.trim() : "";
    const normalizedPhone = phoneInput.replace(/\D/g, "");
    const accountPassword = typeof password === "string" ? password : "";

    if (!phoneInput || !accountPassword.trim()) {
        return res.status(400).json({
            message: "Le numéro de téléphone et le mot de passe sont obligatoires."
        });
    }

    if (!/^\+?[\d\s().-]+$/.test(phoneInput) || normalizedPhone.length < 7 || normalizedPhone.length > 15) {
        return res.status(400).json({
            message: "Veuillez saisir un numéro de téléphone valide."
        });
    }

    const accountEmail = `phone-${normalizedPhone}@accounts.shopix.invalid`;

    try {
        const existingUser = await db.query(
            `
            SELECT id
            FROM users
            WHERE username = $1 OR username = $2 OR email = $3
            `,
            [normalizedPhone, phoneInput, accountEmail]
        );

        if (existingUser.rows.length > 0) {
            return res.status(400).json({
                message: "Un compte existe déjà avec ce numéro de téléphone."
            });
        }

        const hashedPassword = await bcrypt.hash(accountPassword, 12);
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
                normalizedPhone,
                accountEmail,
                hashedPassword
            ]
        );

        return res.status(201).json({
            message: "Compte créé avec succès",
            user: {
                id: result.rows[0].id,
                username: result.rows[0].username
            }
        });
    } catch (err) {
        console.error("❌ Erreur inscription :", err);
        return res.status(500).json({
            message: "Erreur serveur lors de la création du compte."
        });
    }
});


// =====================================================
// LOGIN
// =====================================================

router.post("/login", async (req, res) => {

    const {
        identifier,
        username,
        email,
        password
    } = req.body || {};

    const loginIdentifier =
        identifier ||
        username ||
        email;

    if (
        typeof loginIdentifier !== "string" ||
        !loginIdentifier.trim() ||
        typeof password !== "string" ||
        !password
    ) {
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
                password
            FROM users
            WHERE
                (
                    username = $1
                    OR username = $2
                    OR email = $1
                )
            `,
            [
                loginIdentifier,
                loginIdentifier.replace(/\D/g, "")
            ]
        );

        const userRecord = result.rows[0];

        if (!userRecord) {
            return res.status(401).json({
                message: "Identifiant ou mot de passe incorrect"
            });
        }

        const isHashedPassword = /^\$2[aby]\$/.test(userRecord.password);
        const passwordMatches = isHashedPassword
            ? await bcrypt.compare(password, userRecord.password)
            : password === userRecord.password;

        if (!passwordMatches) {
            return res.status(401).json({
                message: "Identifiant ou mot de passe incorrect"
            });
        }

        if (!isHashedPassword) {
            const upgradedPassword = await bcrypt.hash(password, 12);
            await db.query(
                "UPDATE users SET password = $1 WHERE id = $2",
                [upgradedPassword, userRecord.id]
            );
        }

        return res.json({
            message: "Connexion réussie",
            user: {
                id: userRecord.id,
                username: userRecord.username
            }
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
    const adminUsername =
        process.env.ADMIN_USERNAME ||
        (isProduction ? "" : "admin");
    const adminPassword =
        process.env.ADMIN_PASSWORD ||
        (isProduction ? "" : "admin123");

    if (!jwtSecret || !adminUsername || !adminPassword) {
        return res.status(503).json({
            message: "L’authentification administrateur n’est pas configurée sur le serveur."
        });
    }

    if (username === adminUsername && password === adminPassword) {
        return res.json({
            message: "Connexion administrateur réussie",
            admin: true,
            token: jwt.sign({ role: "admin" }, jwtSecret, {
                algorithm: "HS256",
                expiresIn: "8h"
            })
        });
    }

    return res.status(401).json({
        message: "Identifiants administrateur incorrects"
    });
});


// =====================================================
// GET USERS
// =====================================================

router.get("/users", requireAdmin, async (req, res) => {

    try {

        const result = await db.query(
            `
            SELECT
                id,
                username
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
// DELETE USER
// =====================================================

router.delete("/users/:id", requireAdmin, async (req, res) => {
    const userId = Number(req.params.id);

    if (!Number.isSafeInteger(userId) || userId < 1) {
        return res.status(400).json({
            message: "Identifiant de compte invalide."
        });
    }

    try {
        const result = await db.query(
            "DELETE FROM users WHERE id = $1 RETURNING id",
            [userId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({
                message: "Ce compte n’existe plus."
            });
        }

        return res.json({
            message: "Compte supprimé. L’historique des commandes est conservé."
        });
    } catch (err) {
        console.error("❌ Erreur suppression compte :", err);
        return res.status(500).json({
            message: "Erreur serveur lors de la suppression du compte."
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
        items,
        paymentMethod,
        transactionReference
    } = req.body;

    if (!client || !reference || items === undefined) {
        return res.status(400).json({
            message: "Données de commande incomplètes"
        });
    }

    const normalizedTransactionReference =
        typeof transactionReference === "string"
            ? transactionReference.trim()
            : "";
    const normalizedPaymentMethod = paymentMethod || "MVola";
    const orderTotal = Number(total);

    if (
        normalizedPaymentMethod === "MVola" &&
        (normalizedTransactionReference.length < 4 ||
            normalizedTransactionReference.length > 100 ||
            !Number.isFinite(orderTotal) ||
            orderTotal <= 0)
    ) {
        return res.status(400).json({
            message: "Saisissez la référence exacte du transfert MVola et un montant de commande valide."
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
                items,
                payment_method,
                transaction_reference,
                payment_status
            )
            VALUES
            (
                $1,
                $2,
                $3,
                $4,
                $5,
                $6,
                'pending'
            )
            RETURNING id, reference, payment_method, transaction_reference, payment_status
            `,
            [
                client,
                reference,
                orderTotal || 0,
                JSON.stringify(items),
                normalizedPaymentMethod,
                normalizedTransactionReference || null
            ]
        );

        let paymentStatus = result.rows[0].payment_status;
        if (normalizedTransactionReference) {
            let detectedReceipt = await db.query(
                `
                SELECT transaction_reference, amount, sender_phone
                FROM payment_alerts
                WHERE transaction_reference = $1 AND resolved_at IS NULL
                `,
                [normalizedTransactionReference]
            );
            let referenceMatches = detectedReceipt.rowCount > 0;
            if (!referenceMatches) {
                const unmatchedReceipts = await db.query(
                    `
                    SELECT transaction_reference, amount, sender_phone, created_at
                    FROM payment_alerts
                    WHERE resolved_at IS NULL AND order_id IS NULL
                    ORDER BY created_at DESC
                    LIMIT 50
                    `
                );
                const clientPhone = normalizePhone(client);
                const recentMatches = unmatchedReceipts.rows.filter((receipt) => {
                    return clientPhone && normalizePhone(receipt.sender_phone) === clientPhone &&
                        withinOneDay(receipt.created_at, Date.now());
                });
                if (recentMatches.length === 1) {
                    detectedReceipt = { rows: recentMatches, rowCount: 1 };
                }
            }
            if (detectedReceipt.rowCount > 0) {
                paymentStatus = await applyDetectedPayment(
                    {
                        id: result.rows[0].id,
                        total: orderTotal || 0,
                        payment_status: "pending",
                        transaction_reference: normalizedTransactionReference
                    },
                    {
                        reference: detectedReceipt.rows[0].transaction_reference,
                        amount: Number(detectedReceipt.rows[0].amount),
                        senderPhone: detectedReceipt.rows[0].sender_phone
                    },
                    referenceMatches
                );
            }
        }

        return res.status(201).json({
            message: "Commande enregistrée",
            id: result.rows[0].id,
            reference: result.rows[0].reference,
            paymentMethod: result.rows[0].payment_method,
            transactionReference: result.rows[0].transaction_reference,
            paymentStatus
        });

    } catch (err) {

        if (
            err.code === "23505" ||
            err.code === "SQLITE_CONSTRAINT" ||
            /unique constraint failed/i.test(err.message || "")
        ) {
            return res.status(409).json({
                message: "Cette référence de commande ou de transaction a déjà été utilisée."
            });
        }

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

const listOrders = async (req, res) => {
    try {
        const result = await db.query(
            `
            SELECT
                id,
                client,
                reference,
                total,
                items,
                payment_method,
                transaction_reference,
                payment_status,
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

        return res.json(orders);
    } catch (err) {
        console.error("❌ Erreur commandes :", err);
        return res.status(500).json({
            message: "Erreur serveur"
        });
    }
};

router.get("/orders", listOrders);
router.get("/admin/orders", requireAdmin, listOrders);

router.get("/admin/payment-alerts", requireAdmin, async (_req, res) => {
    try {
        const result = await db.query(
            `
            SELECT id, order_id, transaction_reference, expected_reference, amount,
                   expected_amount, sender_phone, message, created_at
            FROM payment_alerts
            WHERE resolved_at IS NULL
            ORDER BY created_at DESC
            LIMIT 50
            `
        );
        return res.json(result.rows);
    } catch (err) {
        console.error("❌ Erreur alertes de paiement :", err);
        return res.status(500).json({
            message: "Impossible de charger les alertes de paiement."
        });
    }
});

router.post("/device/mvola-transactions", requireMvolaWebhook, async (req, res) => {
    const reference = typeof req.body?.reference === "string"
        ? req.body.reference.trim()
        : "";
    const amount = Number(req.body?.amount);
    const senderPhone = typeof req.body?.sender_phone === "string"
        ? req.body.sender_phone.trim().slice(0, 30)
        : "";
    const transactionType = String(req.body?.transaction_type || "").toLowerCase();
    const transactionDate = new Date(req.body?.transaction_date);

    if (transactionType !== "reception" || reference.length < 4 ||
        reference.length > 100 || !Number.isFinite(amount) || amount <= 0 ||
        !Number.isFinite(transactionDate.getTime())) {
        return res.status(400).json({
            message: "Le transfert reçu comporte des données invalides."
        });
    }

    try {
        const paymentStatus = await processDetectedPayment({
            reference,
            amount,
            senderPhone,
            transactionDate
        });
        return res.json({ payment_status: paymentStatus });
    } catch (err) {
        console.error("❌ Erreur de rapprochement MVola :", err);
        return res.status(500).json({
            message: "Impossible de rapprocher le transfert MVola avec une commande."
        });
    }
});

// =====================================================
// VERIFY MANUAL MVOLA PAYMENT
// =====================================================

router.patch("/admin/orders/:id/payment", requireAdmin, async (req, res) => {
    const orderId = Number(req.params.id);

    if (!Number.isSafeInteger(orderId) || orderId < 1) {
        return res.status(400).json({
            message: "Identifiant de commande invalide."
        });
    }

    try {
        const existingOrder = await db.query(
            `
            SELECT id, reference, transaction_reference
            FROM orders
            WHERE id = $1
                AND transaction_reference IS NOT NULL
                AND transaction_reference <> ''
            `,
            [orderId]
        );

        if (existingOrder.rowCount === 0) {
            const order = await db.query(
                "SELECT id FROM orders WHERE id = $1",
                [orderId]
            );
            return res.status(order.rowCount ? 409 : 404).json({
                message: order.rowCount
                    ? "Impossible de vérifier le paiement sans référence MVola enregistrée."
                    : "Cette commande n’existe plus."
            });
        }

        await db.query(
            "UPDATE orders SET payment_status = 'verified' WHERE id = $1",
            [orderId]
        );
        const result = await db.query(
            `
            SELECT id, reference, transaction_reference, payment_status
            FROM orders
            WHERE id = $1
            `,
            [orderId]
        );

        return res.json({
            message: "Paiement marqué comme vérifié.",
            order: result.rows[0]
        });
    } catch (err) {
        console.error("❌ Erreur vérification paiement :", err);
        return res.status(500).json({
            message: "Erreur serveur lors de la vérification du paiement."
        });
    }
});

// =====================================================
// DELETE ORDER
// =====================================================

router.delete("/admin/orders/:id", requireAdmin, async (req, res) => {
    const orderId = Number(req.params.id);

    if (!Number.isSafeInteger(orderId) || orderId < 1) {
        return res.status(400).json({
            message: "Identifiant de commande invalide."
        });
    }

    try {
        const result = await db.query(
            "DELETE FROM orders WHERE id = $1 RETURNING id",
            [orderId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({
                message: "Cette commande n’existe plus."
            });
        }

        return res.json({
            message: "Commande supprimée."
        });
    } catch (err) {
        console.error("❌ Erreur suppression commande :", err);
        return res.status(500).json({
            message: "Erreur serveur lors de la suppression de la commande."
        });
    }
});


module.exports = router;