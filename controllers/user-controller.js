const User = require('../models/user-schema');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto'); // Add crypto for generating reset tokens
const ejs = require('ejs');

class UserController {
    static async register(req, res, next) {
        try {
            const { fullName, email, password, telp, role } = req.body;
            const hash = await bcrypt.hash(password, 12);
            const user = new User({
                fullName,
                email,
                password: hash,
                telp,
                role
            });
            await user.save();

            res.status(201).json({
                message: 'Register success',
                data: user
            });
        } catch (error) {
            res.status(500).json({
                error: true,
                message: error.message
            });
        }
    }

    static async login(req, res, next) {
        try {
            const { email, password } = req.body;
            const user = await User.findOne({ email });
            if (!user) {
                const error = new Error('Email not found');
                error.statusCode = 401;
                throw error;
            }
            const isValid = await bcrypt.compare(password, user.password);
            if (!isValid) {
                const error = new Error('Wrong password');
                error.statusCode = 401;
                throw error;
            }
            const secretKey = process.env.SECRET_KEY;
            const payload = {
                id: user._id,
                email: user.email,
                username: user.username,
                role: user.role
            };

            const options = {
                expiresIn: '1h'
            };
            const token = jwt.sign(payload, secretKey, options);

            res.cookie('accessToken', token, {
                maxAge: 3600000, // Waktu kedaluwarsa dalam milidetik (1 jam dalam contoh ini)
                httpOnly: true, // Token hanya dapat diakses melalui HTTP dan tidak dari JavaScript
            })

            res.status(200).json({
                error: false,
                message: 'Success',
                token: token
            });
        } catch (error) {
            res.status(500).json({
                error: true,
                message: error.message
            });
        }
    }

    static async completeProfile(req, res, next) {
        try {
            const { fullName, email, telp, role, shopName } = req.body;
            const userID = req.user.id;
            const user = await User.findByIdAndUpdate(userID, {
                fullName,
                email,
                telp,
                role,
                shopName
            });

            res.status(200).json({
                error: false,
                message: 'Success',
                data: user
            });
        }
        catch (error) {
            res.status(500).json({
                error: true,
                message: error.message
            });
        }
    }

    static async resetPassword(req, res, next) {
        try {
            const { oldPassword, newPassword } = req.body;
            console.log(req.body);
            const userID = req.user.id;
            const user = await
                User.findById(userID);
            const isValid = await bcrypt.compare(oldPassword, user.password);
            if (!isValid) {
                const error = new Error('Wrong password');
                error.statusCode = 401;
                throw error;
            }
            const hash = await bcrypt.hash(newPassword, 12);
            user.password = hash;
            await user.save();
            res.status(200).json({
                error: false,
                message: 'Success update password'
            });
        }
        catch (error) {
            res.status(500).json({
                error: true,
                message: error.message
            });
        }
    }

    static async forgotPassword(req, res, next) {
        try {
            const { email } = req.body;
            console.log(req.body);
            const user = await User.findOne({ email });
            if (!user) {
                const error = new Error('Email not found');
                error.statusCode = 404;
                throw error;
            }

            // Generate a reset token and expiration time
            const resetToken = crypto.randomBytes(3).toString('hex');
            const resetTokenExpiration = Date.now() + 6000000; // 1 jam
            console.log(resetToken);

            user.resetPasswordToken = resetToken;
            user.resetPasswordExpires = resetTokenExpiration;
            await user.save();

            // Set up nodemailer
            const transporter = nodemailer.createTransport({
                service: 'Gmail',
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS
                }
            });
            const emailTemplate = await ejs.renderFile('./views/resetPasswordEmail.ejs', { fullName: user.fullName, resetToken: resetToken });
            console.log(emailTemplate);
            const mailOptions = {
                to: user.email,
                from: process.env.EMAIL_USER,
                subject: 'Password Reset',
                html: emailTemplate
            };

            await transporter.sendMail(mailOptions);

            res.status(200).json({
                error: false,
                message: 'An email has been sent to ' + user.email + ' with further instructions.'
            });
        } catch (error) {
            res.status(500).json({
                error: true,
                message: error.message
            });
        }
    }

    // Reset password method
    static async newPassword(req, res, next) {
        try {
            const { token, newPassword } = req.body;
            const user = await User.findOne({
                resetPasswordToken: token,
                resetPasswordExpires: { $gt: Date.now() } // Ensure the token is still valid
            });

            if (!user) {
                const error = new Error('Password reset token is invalid or has expired');
                error.statusCode = 400;
                throw error;
            }

            const hash = await bcrypt.hash(newPassword, 12);
            user.password = hash;
            user.resetPasswordToken = undefined;
            user.resetPasswordExpires = undefined;
            await user.save();

            res.status(200).json({
                error: false,
                message: 'Password has been reset successfully'
            });
        } catch (error) {
            res.status(500).json({
                error: true,
                message: error.message
            });
        }
    }

    static async logout(req, res, next) {
        try {
            res.clearCookie('accessToken');
            res.status(200).json({
                error: false,
                message: 'Logout success'
            });
        } catch (error) {
            res.status(500).json({
                error: true,
                message: error.message
            });
        }
    }


}

module.exports = UserController;