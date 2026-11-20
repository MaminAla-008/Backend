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

        const orderResponse = await post(
            "/orders",
            {
                reference: `TEST-${Date.now()}`,
                total: 25,
                paymentMethod: "MVola",
                transactionReference: `TEST-TXN-${Date.now()}`,
                items: [{ name: "Test item", price: 25 }]
            },
            loggedInUser.token
        );
        assert.equal(orderResponse.status, 201);

        const ownOrders = await fetchApi(`${apiBase}/orders`, {
            headers: { Authorization: `Bearer ${loggedInUser.token}` }
        });
        assert.equal((await ownOrders.json()).length, 1);

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
