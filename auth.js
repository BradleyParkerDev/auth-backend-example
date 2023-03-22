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

module.exports = {
    generatePasswordHash
}