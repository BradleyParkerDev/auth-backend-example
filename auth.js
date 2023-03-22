const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");


const generatePasswordHash = async (password) => {

    //we never save a password in  database as cleartext,
    //instead we always "hash" it
    // hash = generate a long string of letters and numbers that
    // is associated with our password

    const saltRounds = 5;
    const salt = await bcrypt.genSalt(saltRounds);
    const hash = await bcrypt.hash(password, salt);
    return hash;
}

const validatePassword = async (password, hashedUserPassword) => {
    // we can then use bycrypt to check if the password is valid
    const passwordMatch = await bcrypt.compare(password, hashedUserPassword);
    return passwordMatch;
}

module.exports = {
    generatePasswordHash,
    validatePassword
}