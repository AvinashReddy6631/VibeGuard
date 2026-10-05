const express = require("express");
const { exec } = require("child_process");

const app = express();

app.get("/user", (req, res) => {
    const query =
        "SELECT * FROM users WHERE name = '" +
        req.query.name +
        "'";

    const result = eval(req.query.expression);

    exec(req.query.command);

    res.send({
        query,
        result
    });
});

app.listen(3000, () => {
    console.log("Server running");
});