const db = require("../db");

const applyDetectedPayment = async (order, receipt) => {
    const matches =
        Math.round(Number(order.total) * 100) === Math.round(Number(receipt.amount) * 100);
    const paymentStatus = matches ? "verified" : "rejected";

    if (order.payment_status === "pending") {
        await db.query(
            "UPDATE orders SET payment_status = $1 WHERE id = $2 AND payment_status = 'pending'",
            [paymentStatus, order.id]
        );
    }

    if (matches) {
        await db.query(
            "UPDATE payment_alerts SET resolved_at = CURRENT_TIMESTAMP WHERE transaction_reference = $1",
            [receipt.reference]
        );
    } else {
        await db.query(
            `
            INSERT INTO payment_alerts
                (order_id, transaction_reference, expected_reference, amount,
                 expected_amount, sender_phone, message)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (transaction_reference) DO UPDATE SET
                order_id = excluded.order_id,
                expected_reference = excluded.expected_reference,
                amount = excluded.amount,
                expected_amount = excluded.expected_amount,
                sender_phone = excluded.sender_phone,
                message = excluded.message,
                resolved_at = NULL
            `,
            [
                order.id,
                receipt.reference,
                null,
                receipt.amount,
                Number(order.total),
                receipt.senderPhone || null,
                "Paiement détecté différent : le montant reçu ne correspond pas au montant de la commande."
            ]
        );
    }

    return order.payment_status === "pending"
        ? paymentStatus
        : order.payment_status;
};

async function processDetectedPayment(receipt) {
    const orderResult = await db.query(
        `
        SELECT id, client, total, payment_status, transaction_reference
        FROM orders
        WHERE transaction_reference = $1 AND payment_method = 'MVola'
        LIMIT 1
        `,
        [receipt.reference]
    );

    const order = orderResult.rows[0];

    if (!order) {
        await db.query(
            `
            INSERT INTO payment_alerts
                (transaction_reference, amount, sender_phone, message)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (transaction_reference) DO NOTHING
            `,
            [
                receipt.reference,
                receipt.amount,
                receipt.senderPhone || null,
                "Paiement détecté différent : aucune commande ne correspond à la référence reçue."
            ]
        );
        return "unmatched";
    }

    return applyDetectedPayment(order, receipt);
}

module.exports = { applyDetectedPayment, processDetectedPayment };
