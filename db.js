const fs = require("fs");
const path = require("path");

if (process.env.DATABASE_URL) {
    const { Pool } = require("pg");
    const pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
    });

    pool.on("connect", () => {
        console.log("✅ Connecté à PostgreSQL.");
    });

    pool.on("error", (err) => {
        console.error("❌ Erreur PostgreSQL :", err.message);
    });

    pool.ready = Promise.all([
        pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        `),
        pool.query(`
            CREATE TABLE IF NOT EXISTS orders (
                id SERIAL PRIMARY KEY,
                client TEXT NOT NULL,
                reference TEXT NOT NULL UNIQUE,
                total REAL NOT NULL,
                items TEXT NOT NULL,
                payment_method TEXT,
                transaction_reference TEXT,
                payment_status TEXT NOT NULL DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `)
    ]).then(async () => {
        await pool.query("ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_method TEXT");
        await pool.query("ALTER TABLE orders ADD COLUMN IF NOT EXISTS transaction_reference TEXT");
        await pool.query("ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_status TEXT NOT NULL DEFAULT 'pending'");
        await pool.query(`
            CREATE UNIQUE INDEX IF NOT EXISTS orders_transaction_reference_unique
            ON orders (transaction_reference)
            WHERE transaction_reference IS NOT NULL AND transaction_reference <> ''
        `);
    }).then(() => {
        console.log("✅ Tables PostgreSQL prêtes.");
    });

    module.exports = pool;
} else {
    if (process.env.NODE_ENV === "production" || process.env.RENDER === "true") {
        throw new Error("DATABASE_URL est requise en production pour utiliser PostgreSQL.");
    }

    const initSqlJs = require("sql.js");
    const databasePath = path.join(__dirname, "users.db");
    let sqliteDatabase;

    const databaseReady = initSqlJs().then((SQL) => {
        const existingData = fs.existsSync(databasePath)
            ? new Uint8Array(fs.readFileSync(databasePath))
            : undefined;
        sqliteDatabase = new SQL.Database(existingData);
        sqliteDatabase.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        `);
        sqliteDatabase.run(`
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client TEXT NOT NULL,
                reference TEXT NOT NULL UNIQUE,
                total REAL NOT NULL,
                items TEXT NOT NULL,
                payment_method TEXT,
                transaction_reference TEXT,
                payment_status TEXT NOT NULL DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        const orderColumns = sqliteDatabase
            .exec("PRAGMA table_info(orders)")[0]
            ?.values.map((column) => column[1]) || [];
        if (!orderColumns.includes("payment_method")) {
            sqliteDatabase.run("ALTER TABLE orders ADD COLUMN payment_method TEXT");
        }
        if (!orderColumns.includes("transaction_reference")) {
            sqliteDatabase.run("ALTER TABLE orders ADD COLUMN transaction_reference TEXT");
        }
        if (!orderColumns.includes("payment_status")) {
            sqliteDatabase.run(
                "ALTER TABLE orders ADD COLUMN payment_status TEXT NOT NULL DEFAULT 'pending'"
            );
        }
        sqliteDatabase.run(`
            CREATE UNIQUE INDEX IF NOT EXISTS orders_transaction_reference_unique
            ON orders (transaction_reference)
            WHERE transaction_reference IS NOT NULL AND transaction_reference <> ''
        `);
        fs.writeFileSync(databasePath, Buffer.from(sqliteDatabase.export()));
        console.log("✅ Base SQLite locale prête.");
    });

    module.exports = {
        ready: databaseReady,
        async query(sql, params = []) {
            await databaseReady;
            const statement = sqliteDatabase.prepare(sql);
            try {
                statement.bind(params);
                const rows = [];
                while (statement.step()) {
                    rows.push(statement.getAsObject());
                }
                const isReadQuery = /^\s*(SELECT|PRAGMA|WITH)\b/i.test(sql);
                if (!isReadQuery) {
                    fs.writeFileSync(databasePath, Buffer.from(sqliteDatabase.export()));
                }
                return {
                    rows,
                    rowCount: isReadQuery ? rows.length : sqliteDatabase.getRowsModified()
                };
            } finally {
                statement.free();
            }
        }
    };
}