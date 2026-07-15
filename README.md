const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const User = require("../models/User");

const router = express.Router();

router.post("/register", async (req, res) => {
    try {

        const { email, password } = req.body;

        const hash = await bcrypt.hash(password, 12);

        const user = await User.create({
            email,
            password: hash
        });

        res.json({
            message: "User created"
        });

    } catch (err) {
        res.status(400).json({
            error: err.message
        });
    }
});

router.post("/login", async (req, res) => {

    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user)
        return res.status(401).json({ message: "Invalid credentials" });

    const valid = await bcrypt.compare(password, user.password);

    if (!valid)
        return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
        { id: user._id },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
    );

    res.json({ token });

});

module.exports = router;
