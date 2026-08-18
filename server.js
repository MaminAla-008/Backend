const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
    res.json({
        message: "API Login fonctionne !"
    });
});

const authRoutes = require("./routes/auth");

app.use("/api/auth", authRoutes);

const PORT = 5000;

app.listen(PORT, () => {
    console.log(`Server demarré sur http://localhost:${PORT}`);
});