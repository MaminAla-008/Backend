function createRateLimit({ limit, windowMs, key, countSuccessful = true }) {
    const attempts = new Map();
    const cleanupInterval = setInterval(() => {
        const now = Date.now();
        for (const [identifier, bucket] of attempts) {
            if (bucket.resetAt <= now) attempts.delete(identifier);
        }
    }, Math.min(windowMs, 60_000));
    cleanupInterval.unref();

    return (req, res, next) => {
        const identifier = String(key(req) || "unknown").trim().toLowerCase().slice(0, 256);
        const now = Date.now();
        let bucket = attempts.get(identifier);
        if (!bucket || bucket.resetAt <= now) {
            bucket = { count: 0, resetAt: now + windowMs };
            attempts.set(identifier, bucket);
        }

        if (bucket.count >= limit) {
            res.set("Retry-After", String(Math.max(1, Math.ceil((bucket.resetAt - now) / 1000))));
            return res.status(429).json({
                message: "Trop de tentatives. Réessayez plus tard."
            });
        }

        bucket.count += 1;
        if (!countSuccessful) {
            res.once("finish", () => {
                if (res.statusCode < 400) {
                    bucket.count = Math.max(0, bucket.count - 1);
                }
            });
        }
        return next();
    };
}

module.exports = { createRateLimit };
