const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { timingSafeEqual, randomBytes } = require("node:crypto");
const { OAuth2Client } = require("google-auth-library");
const router = express.Router();
const googleOAuthClient = new OAuth2Client();

const db = require("../db");
const {
    applyDetectedPayment,
    processDetectedPayment,
    settleVerifiedOrder
} = require("../services/mvolaPayments");
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

const requireUser = (req, res, next) => {
    if (!jwtSecret) {
        return res.status(503).json({
            message: "Le serveur doit être configuré avec JWT_SECRET."
        });
    }

    const authorization = req.get("authorization") || "";
    const [scheme, token] = authorization.split(" ");

    if (scheme !== "Bearer" || !token) {
        return res.status(401).json({
            message: "Connectez-vous pour accéder à votre compte."
        });
    }

    try {
        const payload = jwt.verify(token, jwtSecret, {
            algorithms: ["HS256"]
        });

        if (
            typeof payload !== "object" ||
            payload.role !== "customer" ||
            !payload.sub ||
            !payload.username
        ) {
            return res.status(403).json({
                message: "Accès réservé à un compte client."
            });
        }

        req.user = {
            id: payload.sub,
            username: payload.username
        };
        return next();
    } catch (err) {
        return res.status(401).json({
            message: "Votre session a expiré. Veuillez vous reconnecter."
        });
    }
};

const createUserToken = (user) =>
    jwt.sign(
        {
            role: "customer",
            username: user.username
        },
        jwtSecret,
        {
            algorithm: "HS256",
            subject: String(user.id),
            expiresIn: "30d"
        }
    );

const getPhoneDetails = (phone) => {
    if (typeof phone !== "string" || !/^\+?[\d\s().-]+$/.test(phone.trim())) {
        return null;
    }

    const digits = phone.replace(/\D/g, "");
    if (digits.length < 7 || digits.length > 15) {
        return null;
    }

    const variants = new Set([digits]);
    if (digits.startsWith("261")) {
        variants.add(`0${digits.slice(3)}`);
    } else if (digits.startsWith("0")) {
        variants.add(`261${digits.slice(1)}`);
    }

    let e164;
    if (phone.trim().startsWith("+")) {
        e164 = `+${digits}`;
    } else if (digits.startsWith("261")) {
        e164 = `+${digits}`;
    } else if (digits.startsWith("0")) {
        e164 = `+261${digits.slice(1)}`;
    } else {
        return null;
    }

    return { digits, variants: [...variants], e164 };
};

const findUserByPhone = async (variants) =>
    db.query(
        `
        SELECT id, username
        FROM users
        WHERE username = $1 OR username = $2
        LIMIT 1
        `,
        [variants[0], variants[1] || variants[0]]
    );

const isTwilioConfigured = () =>
    Boolean(
        process.env.TWILIO_ACCOUNT_SID &&
        process.env.TWILIO_AUTH_TOKEN &&
        process.env.TWILIO_VERIFY_SERVICE_SID
    );

const requestTwilioVerification = async (endpoint, values) => {
    const accountSid = process.env.TWILIO_ACCOUNT_SID;
    const authToken = process.env.TWILIO_AUTH_TOKEN;
    const serviceSid = process.env.TWILIO_VERIFY_SERVICE_SID;
    const credentials = Buffer.from(`${accountSid}:${authToken}`).toString("base64");
    const response = await fetch(
        `https://verify.twilio.com/v2/Services/${encodeURIComponent(serviceSid)}/${endpoint}`,
        {
            method: "POST",
            headers: {
                Authorization: `Basic ${credentials}`,
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams(values)
        }
    );

    const result = await response.json();
    if (!response.ok) {
        const error = new Error("Twilio Verify request failed.");
        error.status = response.status;
        throw error;
    }

    return result;
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
    if (!jwtSecret) {
        return res.status(503).json({
            message: "Le serveur doit être configuré avec JWT_SECRET."
        });
    }

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
            token: createUserToken(result.rows[0]),
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
    if (!jwtSecret) {
        return res.status(503).json({
            message: "Le serveur doit être configuré avec JWT_SECRET."
        });
    }

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
            token: createUserToken(userRecord),
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
// GOOGLE LOGIN
// =====================================================

router.post("/google", async (req, res) => {
    const googleClientId = process.env.GOOGLE_CLIENT_ID;
    const idToken = req.body?.idToken;

    if (!jwtSecret) {
        return res.status(503).json({
            message: "Le serveur doit être configuré avec JWT_SECRET."
        });
    }

    if (!googleClientId) {
        return res.status(503).json({
            message: "La connexion Google n’est pas encore configurée sur le serveur."
        });
    }

    if (typeof idToken !== "string" || !idToken) {
        return res.status(400).json({
            message: "Jeton Google manquant."
        });
    }

    let googleUser;
    try {
        const ticket = await googleOAuthClient.verifyIdToken({
            idToken,
            audience: googleClientId
        });
        googleUser = ticket.getPayload();
    } catch (err) {
        return res.status(401).json({
            message: "La vérification de votre compte Google a échoué."
        });
    }

    const email = googleUser?.email?.trim().toLowerCase();
    if (!email || googleUser.email_verified !== true) {
        return res.status(401).json({
            message: "Google doit confirmer votre adresse e-mail avant la connexion."
        });
    }

    try {
        const existingUser = await db.query(
            "SELECT id, username, email FROM users WHERE email = $1",
            [email]
        );
        let user = existingUser.rows[0];

        if (!user) {
            const passwordHash = await bcrypt.hash(randomBytes(32).toString("hex"), 12);
            const result = await db.query(
                `
                INSERT INTO users (username, email, password)
                VALUES ($1, $2, $3)
                RETURNING id, username, email
                `,
                [email, email, passwordHash]
            );
            user = result.rows[0];
        }

        return res.json({
            message: "Connexion Google réussie.",
            token: createUserToken(user),
            user: {
                id: user.id,
                username: user.username,
                email: user.email
            }
        });
    } catch (err) {
        console.error("❌ Erreur connexion Google :", err);
        return res.status(500).json({
            message: "Erreur serveur lors de la connexion Google."
        });
    }
});

// =====================================================
// PASSWORD RESET BY SMS
// =====================================================

router.post("/password-reset/request", async (req, res) => {
    if (!isTwilioConfigured()) {
        return res.status(503).json({
            message: "L’envoi de codes SMS n’est pas encore configuré."
        });
    }

    const phoneDetails = getPhoneDetails(req.body?.phone);
    if (!phoneDetails) {
        return res.status(400).json({
            message: "Veuillez saisir un numéro de téléphone valide."
        });
    }

    try {
        const result = await findUserByPhone(phoneDetails.variants);
        if (result.rows.length > 0) {
            await requestTwilioVerification("Verifications", {
                To: phoneDetails.e164,
                Channel: "sms"
            });
        }

        return res.json({
            message: "Si ce numéro correspond à un compte Shopix, un code de vérification va être envoyé."
        });
    } catch (err) {
        console.error("❌ Erreur envoi code SMS :", err.status || err.message);
        return res.status(502).json({
            message: "Impossible d’envoyer le code SMS pour le moment. Veuillez réessayer."
        });
    }
});

router.post("/password-reset/confirm", async (req, res) => {
    if (!isTwilioConfigured()) {
        return res.status(503).json({
            message: "La vérification par SMS n’est pas encore configurée."
        });
    }

    const phoneDetails = getPhoneDetails(req.body?.phone);
    const code = typeof req.body?.code === "string" ? req.body.code.trim() : "";
    const newPassword = typeof req.body?.newPassword === "string" ? req.body.newPassword : "";

    if (
        !phoneDetails ||
        !/^\d{4,10}$/.test(code) ||
        newPassword.trim().length < 8 ||
        Buffer.byteLength(newPassword, "utf8") > 72
    ) {
        return res.status(400).json({
            message: "Vérifiez le numéro, le code et choisissez un mot de passe de 8 à 72 octets."
        });
    }

    try {
        const result = await findUserByPhone(phoneDetails.variants);
        if (result.rows.length === 0) {
            return res.status(400).json({
                message: "Le code ou le numéro de téléphone est invalide."
            });
        }

        const verification = await requestTwilioVerification("VerificationCheck", {
            To: phoneDetails.e164,
            Code: code
        });

        if (verification.status !== "approved") {
            return res.status(400).json({
                message: "Le code ou le numéro de téléphone est invalide ou expiré."
            });
        }

        const passwordHash = await bcrypt.hash(newPassword, 12);
        await db.query(
            "UPDATE users SET password = $1 WHERE id = $2",
            [passwordHash, result.rows[0].id]
        );

        return res.json({
            message: "Mot de passe modifié. Vous pouvez maintenant vous connecter."
        });
    } catch (err) {
        console.error("❌ Erreur réinitialisation mot de passe :", err.status || err.message);
        return res.status(502).json({
            message: "Impossible de vérifier le code SMS pour le moment. Veuillez réessayer."
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

router.post("/admin/catalog/sync", requireAdmin, async (req, res) => {
    const catalog = req.body?.products;
    if (!Array.isArray(catalog) || catalog.length === 0 || catalog.length > 500) {
        return res.status(400).json({ message: "Catalogue invalide ou vide." });
    }

    try {
        let synchronized = 0;
        for (const product of catalog) {
            const id = Number(product?.id);
            const name = typeof product?.name === "string" ? product.name.trim() : "";
            const rawPrice = String(product?.price ?? "").replace(/[^\d.-]/g, "");
            const price = Number(rawPrice);
            const rating = Number(product?.rating || 0);
            if (!Number.isSafeInteger(id) || id < 1 || !name || name.length > 200 ||
                !Number.isFinite(price) || price <= 0 ||
                !Number.isInteger(rating) || rating < 0 || rating > 5) {
                return res.status(400).json({ message: "Un article du catalogue est invalide." });
            }

            await db.query(
                `INSERT INTO products
                 (id, name, description, category, image, back_image, price, rating)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT (id) DO UPDATE SET
                    name = excluded.name,
                    description = excluded.description,
                    category = excluded.category,
                    image = excluded.image,
                    back_image = excluded.back_image,
                    price = excluded.price,
                    rating = excluded.rating,
                    active = TRUE`,
                [
                    id,
                    name,
                    typeof product.description === "string" ? product.description.slice(0, 2000) : "",
                    typeof product.category === "string" ? product.category.slice(0, 80) : "",
                    typeof product.image === "string" ? product.image.slice(0, 2000) : "",
                    typeof product.backImage === "string" ? product.backImage.slice(0, 2000) : "",
                    price,
                    rating
                ]
            );
            synchronized += 1;
        }
        return res.json({ synchronized });
    } catch (error) {
        console.error("Erreur de synchronisation du catalogue :", error.message);
        return res.status(500).json({ message: "Impossible de synchroniser le catalogue." });
    }
});

router.get("/admin/inventory", requireAdmin, async (_req, res) => {
    try {
        const result = await db.query(
            `SELECT id, name, price, category, image, stock_on_hand, reserved,
                    stock_on_hand - reserved AS available
             FROM products
             WHERE active = TRUE
             ORDER BY name`
        );
        return res.json(result.rows);
    } catch (error) {
        console.error("Erreur de récupération du stock :", error.message);
        return res.status(500).json({ message: "Impossible de récupérer le stock." });
    }
});

router.patch("/admin/inventory/:id", requireAdmin, async (req, res) => {
    const productId = Number(req.params.id);
    const stockOnHand = req.body?.stock_on_hand;
    if (!Number.isSafeInteger(productId) || productId < 1 ||
        !Number.isSafeInteger(stockOnHand) || stockOnHand < 0 || stockOnHand > 1_000_000) {
        return res.status(400).json({ message: "Produit ou quantité de stock invalide." });
    }

    try {
        const result = await db.query(
            `UPDATE products
             SET stock_on_hand = $2
             WHERE id = $1 AND reserved <= $2
             RETURNING id, name, stock_on_hand, reserved,
                       stock_on_hand - reserved AS available`,
            [productId, stockOnHand]
        );
        if (result.rowCount === 0) {
            const product = await db.query(
                "SELECT id, reserved FROM products WHERE id = $1",
                [productId]
            );
            if (product.rowCount === 0) {
                return res.status(404).json({ message: "Produit introuvable." });
            }
            return res.status(409).json({
                message: `Le stock ne peut pas être inférieur aux ${product.rows[0].reserved} article(s) déjà réservés.`
            });
        }
        return res.json(result.rows[0]);
    } catch (error) {
        console.error("Erreur de mise à jour du stock :", error.message);
        return res.status(500).json({ message: "Impossible de mettre à jour le stock." });
    }
});

router.get("/products/availability", async (_req, res) => {
    try {
        const result = await db.query(
            `SELECT id, stock_on_hand - reserved AS available
             FROM products
             WHERE active = TRUE`
        );
        return res.json(result.rows);
    } catch (error) {
        console.error("Erreur de récupération des disponibilités :", error.message);
        return res.status(500).json({ message: "Impossible de récupérer les disponibilités." });
    }
});

router.post("/orders", requireUser, async (req, res) => {
    const reference = typeof req.body?.reference === "string"
        ? req.body.reference.trim()
        : "";
    const items = req.body?.items;
    const normalizedTransactionReference =
        typeof req.body?.transactionReference === "string"
            ? req.body.transactionReference.trim()
            : "";
    const normalizedPaymentMethod = req.body?.paymentMethod || "MVola";

    if (!reference || reference.length > 100 || !Array.isArray(items) ||
        items.length === 0 || items.length > 100) {
        return res.status(400).json({ message: "Données de commande incomplètes ou invalides." });
    }
    if (normalizedPaymentMethod !== "MVola" ||
        normalizedTransactionReference.length < 4 ||
        normalizedTransactionReference.length > 100) {
        return res.status(400).json({
            message: "Saisissez la référence exacte du transfert MVola."
        });
    }

    const requestedQuantities = new Map();
    for (const item of items) {
        const productId = Number(item?.id);
        const quantity = item?.quantity === undefined ? 1 : Number(item.quantity);
        if (!Number.isSafeInteger(productId) || productId < 1 ||
            !Number.isSafeInteger(quantity) || quantity < 1 || quantity > 100) {
            return res.status(400).json({ message: "Un article ou une quantité de commande est invalide." });
        }
        requestedQuantities.set(productId, (requestedQuantities.get(productId) || 0) + quantity);
    }

    let connection;
    let transactionOpen = false;
    try {
        connection = await db.connect();
        await connection.query("BEGIN");
        transactionOpen = true;
        const lockClause = db.isPostgres ? " FOR UPDATE" : "";
        const orderItems = [];
        let subtotal = 0;

        const sortedQuantities = [...requestedQuantities].sort(
            ([firstId], [secondId]) => firstId - secondId
        );
        for (const [productId, quantity] of sortedQuantities) {
            const productResult = await connection.query(
                `SELECT id, name, description, image, price, stock_on_hand, reserved
                 FROM products
                 WHERE id = $1 AND active = TRUE${lockClause}`,
                [productId]
            );
            const product = productResult.rows[0];
            if (!product) {
                await connection.query("ROLLBACK");
                transactionOpen = false;
                return res.status(409).json({
                    message: "Un article n’est plus disponible dans le catalogue."
                });
            }
            if (Number(product.stock_on_hand) - Number(product.reserved) < quantity) {
                await connection.query("ROLLBACK");
                transactionOpen = false;
                return res.status(409).json({
                    message: `Stock insuffisant pour « ${product.name} ».`
                });
            }

            const price = Number(product.price);
            subtotal += price * quantity;
            orderItems.push({
                id: Number(product.id),
                name: product.name,
                description: product.description || "",
                image: product.image || "",
                price,
                quantity
            });
        }

        const shipping = 9.99;
        const orderTotal = Number((subtotal + shipping).toFixed(2));
        const orderResult = await connection.query(
            `INSERT INTO orders
             (client, reference, total, items, payment_method, transaction_reference,
              payment_status, order_status, reservation_expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, 'pending', 'awaiting_payment', $7)
             RETURNING id, reference, payment_method, transaction_reference,
                       payment_status, order_status, total`,
            [
                req.user.username,
                reference,
                orderTotal,
                JSON.stringify(orderItems),
                normalizedPaymentMethod,
                normalizedTransactionReference,
                new Date(Date.now() + 15 * 60 * 1000).toISOString()
            ]
        );
        const order = orderResult.rows[0];
        await connection.query(
            `INSERT INTO order_status_history (order_id, old_status, new_status, changed_by)
             VALUES ($1, NULL, 'awaiting_payment', $2)`,
            [order.id, req.user.username]
        );

        for (const item of orderItems) {
            await connection.query(
                `UPDATE products
                 SET reserved = reserved + $2
                 WHERE id = $1`,
                [item.id, item.quantity]
            );
            await connection.query(
                `INSERT INTO order_inventory_reservations (order_id, product_id, quantity)
                 VALUES ($1, $2, $3)`,
                [order.id, item.id, item.quantity]
            );
        }
        await connection.query("COMMIT");
        transactionOpen = false;

        let paymentStatus = order.payment_status;
        let orderStatus = order.order_status;
        let paymentReconciliationPending = false;
        const detectedReceipt = await db.query(
            `SELECT transaction_reference, amount, sender_phone
             FROM payment_alerts
             WHERE transaction_reference = $1 AND resolved_at IS NULL`,
            [normalizedTransactionReference]
        );
        if (detectedReceipt.rowCount > 0) {
            try {
                paymentStatus = await applyDetectedPayment(
                    {
                        id: order.id,
                        total: orderTotal,
                        payment_status: "pending",
                        order_status: "awaiting_payment",
                        transaction_reference: normalizedTransactionReference
                    },
                    {
                        reference: detectedReceipt.rows[0].transaction_reference,
                        amount: Number(detectedReceipt.rows[0].amount),
                        senderPhone: detectedReceipt.rows[0].sender_phone
                    }
                );
                if (paymentStatus === "verified") orderStatus = "paid";
            } catch (paymentError) {
                paymentReconciliationPending = true;
                console.error("La commande est enregistrée, mais le rapprochement MVola a échoué :", paymentError);
            }
        }

        return res.status(201).json({
            message: paymentReconciliationPending
                ? "Commande enregistrée, mais le rapprochement du paiement doit être réessayé."
                : "Commande enregistrée",
            id: order.id,
            reference: order.reference,
            total: orderTotal,
            paymentMethod: order.payment_method,
            transactionReference: order.transaction_reference,
            paymentStatus,
            orderStatus,
            paymentReconciliationPending
        });
    } catch (err) {
        if (connection && transactionOpen) await connection.query("ROLLBACK");
        if (
            err.code === "23505" ||
            err.code === "SQLITE_CONSTRAINT" ||
            /unique constraint failed/i.test(err.message || "")
        ) {
            return res.status(409).json({
                message: "Cette référence de commande ou de transaction a déjà été utilisée."
            });
        }

        console.error("❌ Erreur commande :", err);
        return res.status(500).json({ message: "Erreur serveur" });
    } finally {
        connection?.release();
    }
});


// =====================================================
// GET ORDERS
// =====================================================

const listOrders = async (req, res) => {
    try {
        const isCustomer = Boolean(req.user);
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
                order_status,
                created_at
            FROM orders
            ${isCustomer ? "WHERE client = $1" : ""}
            ORDER BY id DESC
            `,
            isCustomer ? [req.user.username] : []
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

router.get("/orders", requireUser, listOrders);
router.get("/admin/orders", requireAdmin, listOrders);

router.patch("/admin/orders/:id/status", requireAdmin, async (req, res) => {
    const orderId = Number(req.params.id);
    const nextStatus = typeof req.body?.status === "string" ? req.body.status : "";
    const allowedTransitions = {
        awaiting_payment: ["cancelled"],
        paid: ["preparing"],
        preparing: ["shipped"],
        shipped: ["delivered"],
        delivered: ["refunded"],
        cancelled: [],
        refunded: []
    };
    if (!Number.isSafeInteger(orderId) || orderId < 1 ||
        !Object.prototype.hasOwnProperty.call(allowedTransitions, nextStatus)) {
        return res.status(400).json({ message: "Commande ou statut invalide." });
    }

    let connection;
    try {
        connection = await db.connect();
        await connection.query("BEGIN");
        const lockClause = db.isPostgres ? " FOR UPDATE" : "";
        const orderResult = await connection.query(
            `SELECT id, order_status FROM orders WHERE id = $1${lockClause}`,
            [orderId]
        );
        const order = orderResult.rows[0];
        if (!order) {
            await connection.query("ROLLBACK");
            return res.status(404).json({ message: "Cette commande n’existe plus." });
        }
        if (!allowedTransitions[order.order_status]?.includes(nextStatus)) {
            await connection.query("ROLLBACK");
            return res.status(409).json({
                message: `Transition impossible : ${order.order_status} → ${nextStatus}.`
            });
        }

        if (nextStatus === "cancelled") {
            const reservations = await connection.query(
                `SELECT product_id, quantity
                 FROM order_inventory_reservations
                 WHERE order_id = $1
                 ORDER BY product_id${lockClause}`,
                [orderId]
            );
            for (const reservation of reservations.rows) {
                const released = await connection.query(
                    `UPDATE products
                     SET reserved = reserved - $2
                     WHERE id = $1 AND reserved >= $2`,
                    [reservation.product_id, reservation.quantity]
                );
                if (released.rowCount !== 1) {
                    throw new Error(`Impossible de libérer la réservation du produit ${reservation.product_id}.`);
                }
            }
            await connection.query(
                "DELETE FROM order_inventory_reservations WHERE order_id = $1",
                [orderId]
            );
        }

        await connection.query(
            "UPDATE orders SET order_status = $2, reservation_expires_at = NULL WHERE id = $1",
            [orderId, nextStatus]
        );
        await connection.query(
            `INSERT INTO order_status_history (order_id, old_status, new_status, changed_by)
             VALUES ($1, $2, $3, 'admin')`,
            [orderId, order.order_status, nextStatus]
        );
        await connection.query("COMMIT");
        return res.json({
            id: orderId,
            previous_status: order.order_status,
            order_status: nextStatus
        });
    } catch (error) {
        if (connection) await connection.query("ROLLBACK");
        console.error("Erreur de mise à jour du statut de commande :", error.message);
        return res.status(500).json({ message: "Impossible de mettre à jour le statut." });
    } finally {
        connection?.release();
    }
});

router.get("/admin/payment-alerts", requireAdmin, async (_req, res) => {
    try {
        const result = await db.query(
            `
            SELECT id, order_id, transaction_reference, expected_reference, amount,
                   expected_amount, sender_phone, message, alert_type, created_at
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

router.patch("/admin/payment-alerts/:id/resolve", requireAdmin, async (req, res) => {
    const alertId = Number(req.params.id);
    const action = req.body?.action;
    if (!Number.isSafeInteger(alertId) || alertId < 1 ||
        !["fulfill", "refunded"].includes(action)) {
        return res.status(400).json({ message: "Alerte ou décision invalide." });
    }

    let connection;
    let transactionOpen = false;
    try {
        connection = await db.connect();
        await connection.query("BEGIN");
        transactionOpen = true;
        const lockClause = db.isPostgres ? " FOR UPDATE" : "";
        const alertResult = await connection.query(
            `SELECT id, order_id, transaction_reference, amount, expected_amount, alert_type, resolved_at
             FROM payment_alerts
             WHERE id = $1${lockClause}`,
            [alertId]
        );
        const alert = alertResult.rows[0];
        if (!alert || alert.alert_type !== "late_payment" || alert.resolved_at || !alert.order_id) {
            await connection.query("ROLLBACK");
            transactionOpen = false;
            return res.status(alert ? 409 : 404).json({
                message: alert
                    ? "Cette alerte n’est pas un paiement tardif à traiter ou elle est déjà résolue."
                    : "Cette alerte n’existe plus."
            });
        }

        const orderResult = await connection.query(
            `SELECT id, total, items, transaction_reference, payment_status, order_status
             FROM orders
             WHERE id = $1${lockClause}`,
            [alert.order_id]
        );
        const order = orderResult.rows[0];
        if (!order || order.order_status !== "cancelled" ||
            order.payment_status !== "pending" ||
            order.transaction_reference !== alert.transaction_reference ||
            Math.round(Number(order.total) * 100) !== Math.round(Number(alert.amount) * 100) ||
            Math.round(Number(order.total) * 100) !== Math.round(Number(alert.expected_amount) * 100)) {
            await connection.query("ROLLBACK");
            transactionOpen = false;
            return res.status(409).json({
                message: "La commande ou le montant ne correspond plus à cette alerte."
            });
        }

        const nextStatus = action === "fulfill" ? "paid" : "refunded";
        const nextPaymentStatus = action === "fulfill" ? "verified" : "refunded";
        const inventoryUpdates = [];

        if (action === "fulfill") {
            let items;
            try {
                items = JSON.parse(order.items);
            } catch {
                throw new Error(`Articles invalides dans la commande ${order.id}.`);
            }
            if (!Array.isArray(items) || items.length === 0) {
                throw new Error(`Aucun article valide dans la commande ${order.id}.`);
            }

            const quantities = new Map();
            for (const item of items) {
                const productId = Number(item?.id);
                const quantity = item?.quantity === undefined ? 1 : Number(item.quantity);
                if (!Number.isSafeInteger(productId) || productId < 1 ||
                    !Number.isSafeInteger(quantity) || quantity < 1) {
                    throw new Error(`Article invalide dans la commande ${order.id}.`);
                }
                quantities.set(productId, (quantities.get(productId) || 0) + quantity);
            }

            const sortedQuantities = [...quantities].sort(
                ([firstId], [secondId]) => firstId - secondId
            );
            for (const [productId, quantity] of sortedQuantities) {
                const productResult = await connection.query(
                    `SELECT id, name, stock_on_hand, reserved
                     FROM products
                     WHERE id = $1${lockClause}`,
                    [productId]
                );
                const product = productResult.rows[0];
                if (!product || Number(product.stock_on_hand) - Number(product.reserved) < quantity) {
                    await connection.query("ROLLBACK");
                    transactionOpen = false;
                    return res.status(409).json({
                        message: `Stock insuffisant pour honorer cette commande. Un remboursement manuel est requis.`
                    });
                }

                const updated = await connection.query(
                    `UPDATE products
                     SET stock_on_hand = stock_on_hand - $2
                     WHERE id = $1 AND stock_on_hand - reserved >= $2`,
                    [productId, quantity]
                );
                if (updated.rowCount !== 1) {
                    throw new Error(`Impossible de décrémenter le stock du produit ${productId}.`);
                }
                inventoryUpdates.push({
                    id: Number(product.id),
                    stock_on_hand: Number(product.stock_on_hand) - quantity,
                    reserved: Number(product.reserved),
                    available: Number(product.stock_on_hand) - Number(product.reserved) - quantity
                });
            }
        }

        await connection.query(
            `UPDATE orders
             SET payment_status = $2, order_status = $3, reservation_expires_at = NULL
             WHERE id = $1`,
            [order.id, nextPaymentStatus, nextStatus]
        );
        await connection.query(
            "UPDATE payment_alerts SET resolved_at = CURRENT_TIMESTAMP WHERE id = $1",
            [alertId]
        );
        await connection.query(
            `INSERT INTO order_status_history (order_id, old_status, new_status, changed_by)
             VALUES ($1, 'cancelled', $2, 'admin')`,
            [order.id, nextStatus]
        );
        await connection.query("COMMIT");
        transactionOpen = false;
        return res.json({
            message: action === "fulfill"
                ? "Paiement tardif accepté, commande réactivée et stock décrémenté."
                : "Remboursement confirmé et alerte clôturée.",
            order: {
                id: order.id,
                payment_status: nextPaymentStatus,
                order_status: nextStatus
            },
            inventory: inventoryUpdates
        });
    } catch (error) {
        if (connection && transactionOpen) await connection.query("ROLLBACK");
        console.error("Erreur de résolution d’un paiement tardif :", error);
        return res.status(500).json({
            message: "Impossible de traiter ce paiement tardif."
        });
    } finally {
        connection?.release();
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
            SELECT id, reference, transaction_reference, payment_status, order_status
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

        const orderBeforeVerification = existingOrder.rows[0];
        if (orderBeforeVerification.payment_status === "verified") {
            return res.json({
                message: "Ce paiement est déjà vérifié.",
                order: orderBeforeVerification
            });
        }
        if (orderBeforeVerification.order_status !== "awaiting_payment" ||
            orderBeforeVerification.payment_status !== "pending") {
            return res.status(409).json({
                message: "Cette commande ne peut plus être vérifiée comme un paiement en attente."
            });
        }

        await settleVerifiedOrder(orderId);
        const result = await db.query(
            `
            SELECT id, reference, transaction_reference, payment_status, order_status
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

    let connection;
    try {
        connection = await db.connect();
        await connection.query("BEGIN");
        const lockClause = db.isPostgres ? " FOR UPDATE" : "";
        const existingOrder = await connection.query(
            `SELECT id FROM orders WHERE id = $1${lockClause}`,
            [orderId]
        );
        if (existingOrder.rowCount === 0) {
            await connection.query("ROLLBACK");
            return res.status(404).json({ message: "Cette commande n’existe plus." });
        }
        const reservations = await connection.query(
            `SELECT product_id, quantity
             FROM order_inventory_reservations
             WHERE order_id = $1
             ORDER BY product_id${lockClause}`,
            [orderId]
        );
        for (const reservation of reservations.rows) {
            const released = await connection.query(
                `UPDATE products
                 SET reserved = reserved - $2
                 WHERE id = $1 AND reserved >= $2`,
                [reservation.product_id, reservation.quantity]
            );
            if (released.rowCount !== 1) {
                throw new Error(`Impossible de libérer la réservation du produit ${reservation.product_id}.`);
            }
        }
        await connection.query(
            "DELETE FROM order_inventory_reservations WHERE order_id = $1",
            [orderId]
        );
        await connection.query(
            "DELETE FROM order_status_history WHERE order_id = $1",
            [orderId]
        );
        const result = await connection.query(
            "DELETE FROM orders WHERE id = $1 RETURNING id",
            [orderId]
        );
        await connection.query("COMMIT");
        return res.json({ message: "Commande supprimée." });
    } catch (err) {
        if (connection) await connection.query("ROLLBACK");
        console.error("❌ Erreur suppression commande :", err);
        return res.status(500).json({
            message: "Erreur serveur lors de la suppression de la commande."
        });
    } finally {
        connection?.release();
    }
});


module.exports = router;