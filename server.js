const express = require('express');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));

// This is a simple in-memory database for demonstration purposes
const users = {
    'john_doe': {
        username: 'john_doe',
        email: 'john_doe@example.com',
        password: 'hashed_password' // Use a proper password hashing library
    }
};

const resetTokens = {};

// Configure nodemailer with your email service
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'your_email@gmail.com', // Replace with your email
        pass: 'your_password' // Replace with your password
    }
});

app.get('/forgot_password', (req, res) => {
    res.sendFile(__dirname + '/forgot-password.html');
});

app.post('/forgot_password', (req, res) => {
    const { email } = req.body;

    // Check if the email exists in the database
    const user = Object.values(users).find(u => u.email === email);

    if (!user) {
        return res.status(404).send('User not found');
    }

    // Generate a unique token
    const token = crypto.randomBytes(20).toString('hex');

    // Store the token for later verification
    resetTokens[token] = user;

    // Create a password reset link
    const resetLink = `http://localhost:3000/reset-password?token=${token}`;

    // Create and send the email
    const mailOptions = {
        from: 'your_email@gmail.com', // Replace with your email
        to: email,
        subject: 'Password Reset',
        text: `Click the following link to reset your password: ${resetLink}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            return res.status(500).send('Failed to send email');
        }

        console.log(`Email sent: ${info.response}`);
        res.send('Email sent successfully');
    });
});

app.get('/reset-password', (req, res) => {
    const { token } = req.query;

    // Check if the token exists
    if (!resetTokens[token]) {
        return res.status(404).send('Invalid or expired token');
    }

    // Render the password reset form with the token
    res.sendFile(__dirname + '/reset-password.html');
});

app.post('/reset-password', (req, res) => {
    const { token, new_password, confirm_new_password } = req.body;

    // Check if the new passwords match
    if (new_password !== confirm_new_password) {
        return res.status(400).send('New passwords do not match');
    }

    // Update the user's password in the database (replace with your actual database update logic)
    const user = resetTokens[token];
    users[user.username].password = new_password;

    // Remove the used token
    delete resetTokens[token];

    res.send('Password reset successfully');
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
