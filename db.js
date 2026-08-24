const { Pool } = require("pg");

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,

    ssl: {
        rejectUnauthorized: false
    }
});

pool.on("connect", () => {
    console.log("✅ Connecté à PostgreSQL.");
});

pool.on("error", (err) => {
    console.error("❌ Erreur PostgreSQL :", err.message);
});

const initDatabase = async () => {
    try {

        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS orders (
                id SERIAL PRIMARY KEY,
                client TEXT NOT NULL,
                reference TEXT NOT NULL UNIQUE,
                total REAL NOT NULL,
                items TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        console.log("✅ Tables PostgreSQL prêtes.");

    } catch (err) {

        console.error(
            "❌ Erreur de création des tables :",
            err.message
        );
    }
};

if (process.env.DATABASE_URL) {
    initDatabase();
} else {
    console.log(
        "⚠️ DATABASE_URL absente : PostgreSQL désactivé en local."
    );
}

module.exports = pool;