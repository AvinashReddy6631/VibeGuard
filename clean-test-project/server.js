const express = require("express");

const app = express();

app.disable("x-powered-by");

app.get("/", (req, res) => {
    res.json({
        message: "Secure test project"
    });
});

app.listen(3000, () => {
    console.log("Server running");
});