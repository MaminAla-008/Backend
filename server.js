require("dotenv").config();

const express = require("express");
const cors = require("cors");

// Connexion PostgreSQL
require("./db");

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

app.use("/api/auth", authRoutes);

// =========================
// SERVER
// =========================

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server demarre sur le port ${PORT}`);
});