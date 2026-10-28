require("dotenv").config();

const express = require("express");
const cors = require("cors");

// Connexion à la base de données
const db = require("./db");

const app = express();

// =========================
// MIDDLEWARES
// =========================

app.use(cors());
app.use(express.json());

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
    app.listen(PORT, () => {
        console.log(`Server demarre sur le port ${PORT}`);
    });
}).catch((err) => {
    console.error("❌ Impossible de démarrer le serveur :", err.message);
    process.exit(1);
});