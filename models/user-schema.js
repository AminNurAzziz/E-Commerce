const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const passportLocalMongoose = require('passport-local-mongoose');

const UserSchema = new Schema({
    fullName: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
    },
    telp: {
        type: String,
        required: true,
        unique: true,
    },
    role: {
        type: String,
        enum: ['Seller', 'Customer'],
    },
    shopName: {
        type: String,
        required: false,
        default: 'No Shop Name',
    },
    resetPasswordToken: {
        type: String,
    },
    resetPasswordExpires: {
        type: Date,
    },
});

UserSchema.plugin(passportLocalMongoose, { usernameField: 'email' });
module.exports = mongoose.model('User', UserSchema);