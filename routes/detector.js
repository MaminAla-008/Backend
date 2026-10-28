const express = require("express");
const { createHash, randomBytes, randomInt } = require("node:crypto");
const db = require("../db");
const { processDetectedPayment } = require("../services/mvolaPayments");

const router = express.Router();
const PHONE_PATTERN = /^\+[1-9]\d{7,14}$/;
const hashSecret = (value) => createHash("sha256").update(value).digest("hex");
const databaseDate = (date) => db.isPostgres
    ? date
    : date.toISOString().replace("T", " ").replace("Z", "");

async function authenticateDevice(req, res, next) {
    const match = (req.get("authorization") || "").match(/^Bearer ([A-Za-z0-9_-]+)$/);
    if (!match) {
        return res.status(401).json({ message: "Association du téléphone requise." });
    }

    try {
        const result = await db.query(
            `SELECT phone_number, token_hash FROM device_tokens
             WHERE token_hash = $1 AND expires_at > CURRENT_TIMESTAMP`,
            [hashSecret(match[1])]
        );
        if (result.rows.length === 0) {
            return res.status(401).json({
                message: "Association expirée. Associez à nouveau le téléphone."
            });
        }

        req.devicePhone = result.rows[0].phone_number;
        req.deviceTokenHash = result.rows[0].token_hash;
        return next();
    } catch (error) {
        console.error("Erreur de vérification du téléphone :", error.message);
        return res.status(500).json({
            message: "Impossible de vérifier l’association du téléphone."
        });
    }
}

router.get("/test-db", async (_req, res) => {
    try {
        if (!db.isPostgres) {
            await db.query("SELECT 1");
            return res.json({
                success: true,
                message: "Connexion SQLite locale réussie",
                database: "SQLite"
            });
        }
        const result = await db.query("SELECT current_database() AS database_name");
        return res.json({
            success: true,
            message: "Connexion PostgreSQL réussie",
            database: result.rows[0].database_name,
            database_provider: db.databaseProvider || "PostgreSQL"
        });
    } catch (error) {
        console.error("Erreur de vérification PostgreSQL :", error.message);
        return res.status(500).json({
            success: false,
            message: "Erreur de connexion PostgreSQL"
        });
    }
});

router.post("/devices/pairing-codes", async (req, res) => {
    const phoneNumber = String(req.body?.phone_number || "").trim();
    if (!PHONE_PATTERN.test(phoneNumber)) {
        return res.status(400).json({
            message: "Entrez un numéro international valide, par exemple +261341234567."
        });
    }

    try {
        const code = String(randomInt(0, 1_000_000)).padStart(6, "0");
        await db.query(
            `INSERT INTO device_pairing_codes (phone_number, code_hash, expires_at)
             VALUES ($1, $2, $3)`,
            [phoneNumber, hashSecret(code), databaseDate(new Date(Date.now() + 10 * 60 * 1000))]
        );
        return res.status(201).json({ code, expires_in_seconds: 600 });
    } catch (error) {
        console.error("Erreur de création du code d’association :", error.message);
        return res.status(500).json({
            message: "Impossible de créer le code d’association."
        });
    }
});

router.post("/devices/claim", async (req, res) => {
    const phoneNumber = String(req.body?.phone_number || "").trim();
    const pairingCode = String(req.body?.pairing_code || "").trim();
    if (!PHONE_PATTERN.test(phoneNumber) || !/^\d{6}$/.test(pairingCode)) {
        return res.status(400).json({ message: "Numéro ou code d’association invalide." });
    }

    let connection;
    try {
        connection = await db.connect();
        await connection.query("BEGIN");
        const lockClause = db.isPostgres ? " FOR UPDATE" : "";
        const result = await connection.query(
            `SELECT id, phone_number FROM device_pairing_codes
             WHERE code_hash = $1 AND expires_at > CURRENT_TIMESTAMP
             ORDER BY id DESC LIMIT 1${lockClause}`,
            [hashSecret(pairingCode)]
        );
        if (result.rows.length === 0) {
            await connection.query("ROLLBACK");
            return res.status(401).json({ message: "Code invalide ou expiré." });
        }
        if (result.rows[0].phone_number !== phoneNumber) {
            await connection.query("ROLLBACK");
            return res.status(409).json({
                code: "PHONE_MISMATCH",
                message: "Le numéro de l’APK est différent de celui du tableau de bord."
            });
        }

        await connection.query(
            "DELETE FROM device_pairing_codes WHERE id = $1",
            [result.rows[0].id]
        );
        const token = randomBytes(32).toString("base64url");
        await connection.query(
            `INSERT INTO device_tokens (phone_number, token_hash, expires_at)
             VALUES ($1, $2, $3)`,
            [
                phoneNumber,
                hashSecret(token),
                databaseDate(new Date(Date.now() + 90 * 24 * 60 * 60 * 1000))
            ]
        );
        await connection.query("COMMIT");
        return res.status(201).json({ token, expires_in_seconds: 7_776_000 });
    } catch (error) {
        if (connection) await connection.query("ROLLBACK");
        console.error("Erreur d’association du téléphone :", error.message);
        return res.status(500).json({ message: "Impossible d’associer le téléphone." });
    } finally {
        connection?.release();
    }
});

router.get("/devices/status", async (req, res) => {
    const phoneNumber = String(req.query.phone_number || "").trim();
    if (!PHONE_PATTERN.test(phoneNumber)) {
        return res.status(400).json({ message: "Numéro de téléphone invalide." });
    }

    try {
        const result = await db.query(
            `SELECT COUNT(*) AS active_devices, MAX(expires_at) AS expires_at
             FROM device_tokens
             WHERE phone_number = $1 AND expires_at > CURRENT_TIMESTAMP`,
            [phoneNumber]
        );
        return res.json({
            connected: Number(result.rows[0].active_devices) > 0,
            phone_number: phoneNumber,
            expires_at: result.rows[0].expires_at
        });
    } catch (error) {
        console.error("Erreur de vérification de l’association :", error.message);
        return res.status(500).json({
            message: "Impossible de vérifier l’association du téléphone."
        });
    }
});

router.get("/devices/current", authenticateDevice, (req, res) =>
    res.json({ connected: true, phone_number: req.devicePhone })
);

router.delete("/devices/current", authenticateDevice, async (req, res) => {
    try {
        await db.query(
            "DELETE FROM device_tokens WHERE token_hash = $1",
            [req.deviceTokenHash]
        );
        return res.json({ connected: false });
    } catch (error) {
        console.error("Erreur de déconnexion du téléphone :", error.message);
        return res.status(500).json({ message: "Impossible de déconnecter le téléphone." });
    }
});

router.get("/transactions", async (req, res) => {
    const phoneNumber = String(req.query.phone_number || "").trim();
    if (!PHONE_PATTERN.test(phoneNumber)) {
        return res.status(400).json({ message: "Numéro de téléphone invalide." });
    }

    try {
        const result = await db.query(
            `SELECT * FROM transactions
             WHERE owner_phone = $1
             ORDER BY date_transaction DESC`,
            [phoneNumber]
        );
        return res.json(result.rows);
    } catch (error) {
        console.error("Erreur de récupération des transactions :", error.message);
        return res.status(500).json({
            message: "Impossible de récupérer les transactions."
        });
    }
});

router.post("/transactions", authenticateDevice, async (req, res) => {
    const reference = String(req.body?.reference || "").trim();
    const amount = Number(req.body?.montant ?? req.body?.amount);
    const transactionType = String(
        req.body?.type_transaction ?? req.body?.transaction_type ?? "reception"
    ).toLowerCase();
    const source = req.body?.source === "android_sms" ? "android_sms" : "manual";
    const dateValue = req.body?.date_transaction ?? req.body?.transaction_date;
    const transactionDate = dateValue ? new Date(dateValue) : new Date();
    const senderName = String(req.body?.sender_name || "").trim().slice(0, 100) || null;
    const senderPhone = String(req.body?.sender_phone || "").trim().slice(0, 30) || null;
    const recipientName = String(req.body?.recipient_name || "").trim().slice(0, 100) || null;
    const recipientPhone = String(req.body?.recipient_phone || "").trim() || null;
    const smsSender = String(req.body?.sms_sender || "").trim().slice(0, 30) || null;

    if (!reference || reference.length > 100 || !Number.isFinite(amount) || amount <= 0 ||
        !["reception", "envoi"].includes(transactionType) ||
        !Number.isFinite(transactionDate.getTime())) {
        return res.status(400).json({
            message: "Une référence, un montant positif, une date et un type valides sont obligatoires."
        });
    }

    try {
        const result = await db.query(
            `INSERT INTO transactions
             (reference, montant, expediteur, destinataire, nom_expediteur,
              nom_destinataire, numero_emetteur_sms, type_transaction,
              date_transaction, source, owner_phone)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             RETURNING id`,
            [
                reference,
                amount,
                transactionType === "envoi" ? req.devicePhone : senderPhone,
                transactionType === "envoi" ? recipientPhone : req.devicePhone,
                senderName,
                transactionType === "envoi" ? recipientName : null,
                smsSender,
                transactionType,
                databaseDate(transactionDate),
                source,
                req.devicePhone
            ]
        );
        let paymentStatus = "not_applicable";
        if (source === "android_sms" && transactionType === "reception") {
            try {
                paymentStatus = await processDetectedPayment({
                    reference,
                    amount,
                    senderPhone,
                    transactionDate
                });
            } catch (error) {
                console.error("Erreur de rapprochement MVola :", error.message);
                return res.status(502).json({
                    message: "Transaction enregistrée ; son rapprochement avec la commande a échoué."
                });
            }
        }

        return res.status(201).json({
            message: "Transaction enregistrée avec succès",
            id: result.rows[0].id,
            payment_status: paymentStatus
        });
    } catch (error) {
        if (error.code === "23505" || error.code?.startsWith("SQLITE_CONSTRAINT")) {
            try {
                const existing = await db.query(
                    `SELECT reference, montant, type_transaction, date_transaction, source, owner_phone
                     FROM transactions
                     WHERE reference = $1 AND owner_phone = $2
                     LIMIT 1`,
                    [reference, req.devicePhone]
                );
                const transaction = existing.rows[0];
                if (transaction?.source === "android_sms" &&
                    transaction.type_transaction === "reception") {
                    const paymentStatus = await processDetectedPayment({
                        reference: transaction.reference,
                        amount: Number(transaction.montant),
                        senderPhone,
                        transactionDate: new Date(transaction.date_transaction)
                    });
                    return res.status(200).json({
                        message: "Transaction déjà enregistrée.",
                        payment_status: paymentStatus
                    });
                }
            } catch (retryError) {
                console.error("Erreur de nouvelle tentative de rapprochement :", retryError.message);
                return res.status(502).json({
                    message: "Transaction déjà enregistrée ; son rapprochement doit être réessayé."
                });
            }
            return res.status(409).json({ message: "Cette référence de transaction existe déjà." });
        }
        console.error("Erreur d'enregistrement de transaction :", error.message);
        return res.status(500).json({
            message: "Impossible d'enregistrer la transaction."
        });
    }
});

router.post("/device-notifications", authenticateDevice, async (req, res) => {
    const eventType = String(req.body?.event_type || "").trim();
    const eventDate = new Date(req.body?.event_at);
    if (eventType !== "sms_ignored" || !Number.isFinite(eventDate.getTime())) {
        return res.status(400).json({ message: "Notification SMS invalide." });
    }

    try {
        const result = await db.query(
            `INSERT INTO device_notifications (owner_phone, event_type, event_at)
             VALUES ($1, $2, $3)
             RETURNING id`,
            [req.devicePhone, eventType, databaseDate(eventDate)]
        );
        return res.status(201).json({ id: result.rows[0].id });
    } catch (error) {
        console.error("Erreur d’enregistrement de la notification SMS :", error.message);
        return res.status(500).json({
            message: "Impossible d’enregistrer la notification SMS."
        });
    }
});

router.get("/notifications", async (req, res) => {
    const phoneNumber = String(req.query.phone_number || "").trim();
    if (!PHONE_PATTERN.test(phoneNumber)) {
        return res.status(400).json({ message: "Numéro de téléphone invalide." });
    }

    try {
        const result = await db.query(
            `SELECT id, event_type, event_at
             FROM device_notifications
             WHERE owner_phone = $1
             ORDER BY event_at DESC
             LIMIT 20`,
            [phoneNumber]
        );
        return res.json(result.rows);
    } catch (error) {
        console.error("Erreur de récupération des notifications :", error.message);
        return res.status(500).json({
            message: "Impossible de récupérer les notifications."
        });
    }
});

module.exports = router;
