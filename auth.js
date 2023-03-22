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

const generateUserToken = (data) => {
   //secret key is unique to app
  const secretKey = process.env.JWT_SECRET_KEY;

  // 3600 seconds in an hour (60 min * 60 seconds)

  //server signing off on the payload, so the receiver knows where it's coming from.
  const token = jwt.sign(data, secretKey);

  return token 
}

const verifyToken = (token) => { 
    const jwtSecretKey = process.env.JWT_SECRET_KEY;
    const verified = jwt.verify(token, jwtSecretKey);
    return verified;


}

module.exports = {
    generatePasswordHash,
    validatePassword,
    generateUserToken,
    verifyToken
}