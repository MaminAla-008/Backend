const assert = require("node:assert/strict");
const { after, before, test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

process.env.NODE_ENV = "test";
process.env.RENDER = "";
process.env.DATABASE_URL = "";
process.env.JWT_SECRET = "shopix-auth-test-secret";
process.env.SHOPIX_SQLITE_PATH = path.join(
    os.tmpdir(),
    `shopix-auth-test-${process.pid}.db`
);
delete process.env.GOOGLE_CLIENT_ID;
delete process.env.TWILIO_ACCOUNT_SID;
delete process.env.TWILIO_AUTH_TOKEN;
delete process.env.TWILIO_VERIFY_SERVICE_SID;

const databasePath = process.env.SHOPIX_SQLITE_PATH;
const fetchApi = global.fetch.bind(global);
const express = require("express");
const db = require("../db");
const {
    processDetectedPayment,
    releaseExpiredOrderReservations
} = require("../services/mvolaPayments");
const app = express();
app.use(express.json());
app.use("/api/auth", require("../routes/auth"));

let server;
let apiBase;

before(async () => {
    await db.ready;
    server = app.listen(0);
    await new Promise((resolve) => server.once("listening", resolve));
    apiBase = `http://127.0.0.1:${server.address().port}/api/auth`;
});

after(async () => {
    if (server) {
        await new Promise((resolve) => server.close(resolve));
    }
    if (fs.existsSync(databasePath)) {
        fs.rmSync(databasePath, { force: true });
    }
});

const post = (route, payload, token) =>
    fetchApi(`${apiBase}${route}`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            ...(token ? { Authorization: `Bearer ${token}` } : {})
        },
        body: JSON.stringify(payload)
    });

const patch = (route, payload, token) =>
    fetchApi(`${apiBase}${route}`, {
        method: "PATCH",
        headers: {
            "Content-Type": "application/json",
            ...(token ? { Authorization: `Bearer ${token}` } : {})
        },
        body: JSON.stringify(payload)
    });

test("Google login configuration and customer SMS password reset", async () => {
    const googleWithoutConfiguration = await post("/google", {
        idToken: "test-token"
    });
    assert.equal(googleWithoutConfiguration.status, 503);

    const smsWithoutConfiguration = await post("/password-reset/request", {
        phone: "0341234567"
    });
    assert.equal(smsWithoutConfiguration.status, 503);

    const phone = `034${String(Date.now()).slice(-7)}`;
    const registration = await post("/register", {
        phone,
        password: "old-password"
    });
    assert.equal(registration.status, 201);

    const anonymousOrders = await fetchApi(`${apiBase}/orders`);
    assert.equal(anonymousOrders.status, 401);

    process.env.TWILIO_ACCOUNT_SID = "AC_TEST";
    process.env.TWILIO_AUTH_TOKEN = "test-token";
    process.env.TWILIO_VERIFY_SERVICE_SID = "VA_TEST";
    const twilioRequests = [];
    global.fetch = async (url, options) => {
        const params = new URLSearchParams(options.body);
        twilioRequests.push({ url: String(url), params });
        const approved =
            String(url).endsWith("/VerificationCheck") &&
            params.get("Code") === "123456";

        return {
            ok: true,
            status: 200,
            json: async () => ({ status: approved ? "approved" : "pending" })
        };
    };

    try {
        const requestCode = await post("/password-reset/request", { phone });
        assert.equal(requestCode.status, 200);
        assert.equal(twilioRequests[0].params.get("To"), `+261${phone.slice(1)}`);
        assert.equal(twilioRequests[0].params.get("Channel"), "sms");

        const invalidCode = await post("/password-reset/confirm", {
            phone,
            code: "000000",
            newPassword: "new-password"
        });
        assert.equal(invalidCode.status, 400);

        const reset = await post("/password-reset/confirm", {
            phone,
            code: "123456",
            newPassword: "new-password"
        });
        assert.equal(reset.status, 200);

        const login = await post("/login", {
            identifier: phone,
            password: "new-password"
        });
        assert.equal(login.status, 200);
        const loggedInUser = await login.json();
        await db.query(
            `INSERT INTO products
                (id, name, price, stock_on_hand, reserved, active)
             VALUES ($1, $2, $3, $4, 0, 1)`,
            [901, "Test item", 25, 2]
        );

        const orderReference = `TEST-${Date.now()}`;
        const orderTransactionReference = `TEST-TXN-${Date.now()}`;
        const orderResponse = await post(
            "/orders",
            {
                reference: orderReference,
                paymentMethod: "MVola",
                transactionReference: orderTransactionReference,
                items: [{ id: 901, quantity: 1 }]
            },
            loggedInUser.token
        );
        assert.equal(orderResponse.status, 201);
        const createdOrder = await orderResponse.json();
        assert.equal(createdOrder.total, 34.99);
        assert.equal(createdOrder.orderStatus, "awaiting_payment");
        const stockAfterReservation = await db.query(
            "SELECT stock_on_hand, reserved FROM products WHERE id = $1",
            [901]
        );
        assert.deepEqual(stockAfterReservation.rows[0], { stock_on_hand: 2, reserved: 1 });

        const unavailableOrder = await post(
            "/orders",
            {
                reference: `TEST-OUT-${Date.now()}`,
                paymentMethod: "MVola",
                transactionReference: `TEST-TXN-OUT-${Date.now()}`,
                items: [{ id: 901, quantity: 2 }]
            },
            loggedInUser.token
        );
        assert.equal(unavailableOrder.status, 409);

        await db.query(
            "UPDATE orders SET reservation_expires_at = $1 WHERE reference = $2",
            ["2000-01-01 00:00:00", orderReference]
        );
        assert.equal(await releaseExpiredOrderReservations(), 1);
        const stockAfterExpiry = await db.query(
            "SELECT stock_on_hand, reserved FROM products WHERE id = $1",
            [901]
        );
        assert.deepEqual(stockAfterExpiry.rows[0], { stock_on_hand: 2, reserved: 0 });
        const expiredOrders = await fetchApi(`${apiBase}/orders`, {
            headers: { Authorization: `Bearer ${loggedInUser.token}` }
        });
        assert.equal((await expiredOrders.json())[0].order_status, "cancelled");

        const adminLogin = await post("/admin/login", {
            username: "admin",
            password: "admin123"
        });
        assert.equal(adminLogin.status, 200);
        const adminToken = (await adminLogin.json()).token;
        const paidOrderResponse = await post(
            "/orders",
            {
                reference: `TEST-PAID-${Date.now()}`,
                paymentMethod: "MVola",
                transactionReference: `TEST-TXN-PAID-${Date.now()}`,
                items: [{ id: 901, quantity: 1 }]
            },
            loggedInUser.token
        );
        assert.equal(paidOrderResponse.status, 201);
        const paidOrder = await paidOrderResponse.json();
        const stockBeforePayment = await db.query(
            "SELECT stock_on_hand, reserved FROM products WHERE id = $1",
            [901]
        );
        assert.deepEqual(stockBeforePayment.rows[0], { stock_on_hand: 2, reserved: 1 });
        const verifyPayment = await patch(
            `/admin/orders/${paidOrder.id}/payment`,
            { status: "verified" },
            adminToken
        );
        assert.equal(verifyPayment.status, 200);
        const verifiedOrder = await verifyPayment.json();
        assert.equal(verifiedOrder.order.order_status, "paid");
        const stockAfterFirstVerification = await db.query(
            "SELECT stock_on_hand, reserved FROM products WHERE id = $1",
            [901]
        );
        assert.deepEqual(stockAfterFirstVerification.rows[0], { stock_on_hand: 1, reserved: 0 });
        const verifyPaymentAgain = await patch(
            `/admin/orders/${paidOrder.id}/payment`,
            { status: "verified" },
            adminToken
        );
        assert.equal(verifyPaymentAgain.status, 200);
        const stockAfterPayment = await db.query(
            "SELECT stock_on_hand, reserved FROM products WHERE id = $1",
            [901]
        );
        assert.deepEqual(stockAfterPayment.rows[0], { stock_on_hand: 1, reserved: 0 });

        const ownOrders = await fetchApi(`${apiBase}/orders`, {
            headers: { Authorization: `Bearer ${loggedInUser.token}` }
        });
        assert.equal((await ownOrders.json()).length, 2);

        const secondRegistration = await post("/register", {
            phone: `035${String(Date.now()).slice(-7)}`,
            password: "test-password"
        });
        assert.equal(secondRegistration.status, 201);
        const secondUser = await secondRegistration.json();
        const otherOrders = await fetchApi(`${apiBase}/orders`, {
            headers: { Authorization: `Bearer ${secondUser.token}` }
        });
        assert.deepEqual(await otherOrders.json(), []);

        const cancelableOrderResponse = await post(
            "/orders",
            {
                reference: `TEST-CANCEL-${Date.now()}`,
                paymentMethod: "MVola",
                transactionReference: `TEST-TXN-CANCEL-${Date.now()}`,
                items: [{ id: 901, quantity: 1 }]
            },
            loggedInUser.token
        );
        assert.equal(cancelableOrderResponse.status, 201);
        const cancelableOrder = await cancelableOrderResponse.json();
        const cancelOrder = await patch(
            `/admin/orders/${cancelableOrder.id}/status`,
            { status: "cancelled" },
            adminToken
        );
        assert.equal(cancelOrder.status, 200);
        assert.equal((await cancelOrder.json()).order_status, "cancelled");
        const stockAfterCancellation = await db.query(
            "SELECT stock_on_hand, reserved FROM products WHERE id = $1",
            [901]
        );
        assert.deepEqual(stockAfterCancellation.rows[0], { stock_on_hand: 1, reserved: 0 });
        const cancelPaidOrder = await patch(
            `/admin/orders/${paidOrder.id}/status`,
            { status: "cancelled" },
            adminToken
        );
        assert.equal(cancelPaidOrder.status, 409);

        assert.equal(
            await processDetectedPayment({
                reference: orderTransactionReference,
                amount: createdOrder.total,
                senderPhone: "0341234567"
            }),
            "review"
        );
        const lateAlertsResponse = await fetchApi(`${apiBase}/admin/payment-alerts`, {
            headers: { Authorization: `Bearer ${adminToken}` }
        });
        const lateAlerts = await lateAlertsResponse.json();
        const lateAlert = lateAlerts.find((alert) => alert.alert_type === "late_payment");
        assert.ok(lateAlert);
        const acceptedLatePayment = await patch(
            `/admin/payment-alerts/${lateAlert.id}/resolve`,
            { action: "fulfill" },
            adminToken
        );
        assert.equal(acceptedLatePayment.status, 200);
        assert.equal((await acceptedLatePayment.json()).order.order_status, "paid");
        const stockAfterLatePayment = await db.query(
            "SELECT stock_on_hand, reserved FROM products WHERE id = $1",
            [901]
        );
        assert.deepEqual(stockAfterLatePayment.rows[0], { stock_on_hand: 0, reserved: 0 });

        await db.query("UPDATE products SET stock_on_hand = 2 WHERE id = $1", [901]);
        const refundTransactionReference = `TEST-TXN-REFUND-${Date.now()}`;
        const refundOrderResponse = await post(
            "/orders",
            {
                reference: `TEST-REFUND-${Date.now()}`,
                paymentMethod: "MVola",
                transactionReference: refundTransactionReference,
                items: [{ id: 901, quantity: 1 }]
            },
            loggedInUser.token
        );
        assert.equal(refundOrderResponse.status, 201);
        const refundOrder = await refundOrderResponse.json();
        const cancelRefundOrder = await patch(
            `/admin/orders/${refundOrder.id}/status`,
            { status: "cancelled" },
            adminToken
        );
        assert.equal(cancelRefundOrder.status, 200);
        assert.equal(
            await processDetectedPayment({
                reference: refundTransactionReference,
                amount: refundOrder.total,
                senderPhone: "0341234567"
            }),
            "review"
        );

        const blockingOrderResponse = await post(
            "/orders",
            {
                reference: `TEST-BLOCK-${Date.now()}`,
                paymentMethod: "MVola",
                transactionReference: `TEST-TXN-BLOCK-${Date.now()}`,
                items: [{ id: 901, quantity: 2 }]
            },
            loggedInUser.token
        );
        assert.equal(blockingOrderResponse.status, 201);
        const blockingOrder = await blockingOrderResponse.json();
        const refundAlertsResponse = await fetchApi(`${apiBase}/admin/payment-alerts`, {
            headers: { Authorization: `Bearer ${adminToken}` }
        });
        const refundAlerts = await refundAlertsResponse.json();
        const refundAlert = refundAlerts.find(
            (alert) => alert.transaction_reference === refundTransactionReference
        );
        assert.ok(refundAlert);
        const insufficientStock = await patch(
            `/admin/payment-alerts/${refundAlert.id}/resolve`,
            { action: "fulfill" },
            adminToken
        );
        assert.equal(insufficientStock.status, 409);
        const refundConfirmed = await patch(
            `/admin/payment-alerts/${refundAlert.id}/resolve`,
            { action: "refunded" },
            adminToken
        );
        assert.equal(refundConfirmed.status, 200);
        assert.equal((await refundConfirmed.json()).order.payment_status, "refunded");
        const cancelBlockingOrder = await patch(
            `/admin/orders/${blockingOrder.id}/status`,
            { status: "cancelled" },
            adminToken
        );
        assert.equal(cancelBlockingOrder.status, 200);

        const callsBeforeUnknownPhone = twilioRequests.length;
        const unknownPhoneRequest = await post("/password-reset/request", {
            phone: "0349999999"
        });
        assert.equal(unknownPhoneRequest.status, 200);
        assert.equal(twilioRequests.length, callsBeforeUnknownPhone);

        const adminOrders = await fetchApi(`${apiBase}/admin/orders`);
        assert.equal(adminOrders.status, 401);
    } finally {
        global.fetch = fetchApi;
    }
});
