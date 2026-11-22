require("dotenv").config();

const express = require("express");
const cors = require("cors");

// Connexion à la base de données
const db = require("./db");
const { createRateLimit } = require("./middleware/rateLimit");
const { releaseExpiredOrderReservations } = require("./services/mvolaPayments");

const app = express();

// =========================
// MIDDLEWARES
// =========================

app.use(cors());
app.use(express.json());
const authAttemptKey = (req) =>
    req.body?.phone ||
    req.body?.identifier ||
    req.body?.username ||
    req.body?.email ||
    req.socket.remoteAddress;
const registerLimit = createRateLimit({
    limit: 10,
    windowMs: 60 * 60 * 1000,
    key: authAttemptKey
});
const loginLimit = createRateLimit({
    limit: 5,
    windowMs: 15 * 60 * 1000,
    key: authAttemptKey,
    countSuccessful: false
});
app.use("/api/auth/register", registerLimit);
app.use("/api/auth/login", loginLimit);
app.use("/api/auth/password-reset/request", createRateLimit({
    limit: 3,
    windowMs: 60 * 60 * 1000,
    key: authAttemptKey
}));
app.use("/api/auth/password-reset/confirm", createRateLimit({
    limit: 5,
    windowMs: 15 * 60 * 1000,
    key: authAttemptKey,
    countSuccessful: false
}));
app.use("/api/auth/admin/login", createRateLimit({
    limit: 5,
    windowMs: 15 * 60 * 1000,
    key: authAttemptKey,
    countSuccessful: false
}));
app.use("/api/auth/google", createRateLimit({
    limit: 20,
    windowMs: 15 * 60 * 1000,
    key: authAttemptKey,
    countSuccessful: false
}));

// =========================
// TEST API
// =========================

app.get("/", (req, res) => {
    res.json({
        message: "API Shopix fonctionne !"
    });
});

// =========================
// ROUTES AUTH
// =========================

const authRoutes = require("./routes/auth");
const detectorRoutes = require("./routes/detector");

app.use("/api/auth", authRoutes);
app.use("/api", detectorRoutes);

// =========================
// SERVER
// =========================

const PORT = process.env.PORT || 5000;

db.ready.then(() => {
    let cleanupRunning = false;
    const cleanupExpiredReservations = async () => {
        if (cleanupRunning) return;
        cleanupRunning = true;
        try {
            await releaseExpiredOrderReservations();
        } catch (err) {
            console.error("❌ Erreur de libération des réservations expirées :", err);
        } finally {
            cleanupRunning = false;
        }
    };
    const cleanupTimer = setInterval(cleanupExpiredReservations, 30 * 1000);
    cleanupTimer.unref?.();
    cleanupExpiredReservations();

    app.listen(PORT, () => {
        console.log(`Server demarre sur le port ${PORT}`);
    });
}).catch((err) => {
    console.error("❌ Impossible de démarrer le serveur :", err.message);
    process.exit(1);
});