const db = require("../db");

async function settleVerifiedOrder(orderId) {
    let connection;
    try {
        connection = await db.connect();
        await connection.query("BEGIN");
        const lockClause = db.isPostgres ? " FOR UPDATE" : "";
        const orderResult = await connection.query(
            `SELECT order_status, payment_status FROM orders WHERE id = $1${lockClause}`,
            [orderId]
        );
        const order = orderResult.rows[0];
        if (!order) {
            throw new Error(`Commande ${orderId} introuvable lors de la validation du paiement.`);
        }
        if (order.order_status === "cancelled" || order.order_status === "refunded") {
            throw new Error(`La commande ${orderId} est déjà ${order.order_status}.`);
        }
        const reservations = await connection.query(
            `SELECT product_id, quantity
             FROM order_inventory_reservations
             WHERE order_id = $1
             ORDER BY product_id${lockClause}`,
            [orderId]
        );

        for (const reservation of reservations.rows) {
            const result = await connection.query(
                `UPDATE products
                 SET stock_on_hand = stock_on_hand - $2,
                     reserved = reserved - $2
                 WHERE id = $1 AND stock_on_hand >= $2 AND reserved >= $2`,
                [reservation.product_id, reservation.quantity]
            );
            if (result.rowCount !== 1) {
                throw new Error(`Impossible de finaliser le stock du produit ${reservation.product_id}.`);
            }
        }

        await connection.query(
            "DELETE FROM order_inventory_reservations WHERE order_id = $1",
            [orderId]
        );
        await connection.query(
            `UPDATE orders
             SET payment_status = 'verified',
                 reservation_expires_at = NULL,
                 order_status = CASE
                 WHEN order_status = 'awaiting_payment' THEN 'paid'
                 ELSE order_status
             END
             WHERE id = $1`,
            [orderId]
        );
        if (order.order_status === "awaiting_payment") {
            await connection.query(
                "INSERT INTO order_status_history (order_id, old_status, new_status, changed_by) VALUES ($1, 'awaiting_payment', 'paid', 'payment')",
                [orderId]
            );
        }
        await connection.query("COMMIT");
    } catch (error) {
        if (connection) await connection.query("ROLLBACK");
        throw error;
    } finally {
        connection?.release();
    }
}

async function releaseExpiredOrderReservations() {
    let connection;
    try {
        connection = await db.connect();
        await connection.query("BEGIN");
        const lockClause = db.isPostgres ? " FOR UPDATE SKIP LOCKED" : "";
        const expiration = db.isPostgres
            ? "reservation_expires_at <= CURRENT_TIMESTAMP"
            : "datetime(reservation_expires_at) <= CURRENT_TIMESTAMP";
        const expiredOrders = await connection.query(
            `SELECT id
             FROM orders
             WHERE order_status = 'awaiting_payment'
               AND payment_status = 'pending'
               AND reservation_expires_at IS NOT NULL
               AND ${expiration}
             ORDER BY id
             LIMIT 100${lockClause}`
        );

        for (const { id } of expiredOrders.rows) {
            const reservations = await connection.query(
                `SELECT product_id, quantity
                 FROM order_inventory_reservations
                 WHERE order_id = $1
                 ORDER BY product_id${db.isPostgres ? " FOR UPDATE" : ""}`,
                [id]
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
                [id]
            );
            await connection.query(
                `UPDATE orders
                 SET order_status = 'cancelled', reservation_expires_at = NULL
                 WHERE id = $1`,
                [id]
            );
            await connection.query(
                `INSERT INTO order_status_history (order_id, old_status, new_status, changed_by)
                 VALUES ($1, 'awaiting_payment', 'cancelled', 'system')`,
                [id]
            );
        }

        await connection.query("COMMIT");
        return expiredOrders.rows.length;
    } catch (error) {
        if (connection) await connection.query("ROLLBACK");
        throw error;
    } finally {
        connection?.release();
    }
}

const applyDetectedPayment = async (order, receipt) => {
    const matches =
        Math.round(Number(order.total) * 100) === Math.round(Number(receipt.amount) * 100);
    const paymentStatus = matches ? "verified" : "rejected";

    if (matches) {
        if (order.payment_status === "refunded") {
            return "refunded";
        }
        if (order.order_status === "cancelled" || order.order_status === "refunded") {
            await db.query(
                `INSERT INTO payment_alerts
                    (order_id, transaction_reference, amount, expected_amount, sender_phone, message, alert_type)
                 VALUES ($1, $2, $3, $4, $5, $6, 'late_payment')
                 ON CONFLICT (transaction_reference) DO UPDATE SET
                    order_id = excluded.order_id,
                    amount = excluded.amount,
                    expected_amount = excluded.expected_amount,
                    sender_phone = excluded.sender_phone,
                    message = excluded.message,
                    alert_type = 'late_payment',
                    resolved_at = NULL`,
                [
                    order.id,
                    receipt.reference,
                    receipt.amount,
                    Number(order.total),
                    receipt.senderPhone || null,
                    "Paiement reçu après expiration ou annulation : vérification manuelle et remboursement éventuel requis."
                ]
            );
            return "review";
        }
        await settleVerifiedOrder(order.id);
        await db.query(
            "UPDATE payment_alerts SET resolved_at = CURRENT_TIMESTAMP WHERE transaction_reference = $1",
            [receipt.reference]
        );
    } else {
        if (order.payment_status === "pending") {
            await db.query(
                "UPDATE orders SET payment_status = 'rejected' WHERE id = $1 AND payment_status = 'pending'",
                [order.id]
            );
        }
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
                alert_type = 'payment_mismatch',
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
        SELECT id, client, total, payment_status, order_status, transaction_reference
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
                (transaction_reference, amount, sender_phone, message, alert_type)
            VALUES ($1, $2, $3, $4, 'unmatched')
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

module.exports = {
    applyDetectedPayment,
    processDetectedPayment,
    releaseExpiredOrderReservations,
    settleVerifiedOrder
};
