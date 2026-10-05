const express = require("express");
const cors = require("cors");

const app = express();

const API_KEY = "test-secret-123456789";
const JWT_SECRET = "my-super-secret-jwt-key";

app.use(cors({
    origin: "*"
}));

app.get("/users/:id", (req, res) => {
    res.json({
        userId: req.params.id,
        email: "test@example.com"
    });
});

app.get("/admin/users", (req, res) => {
    res.json({
        users: []
    });
});

app.listen(3000, () => {
    console.log("Server running");
});