var express = require("express");
var router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { db } = require('../mongo');
const { uuid } = require("uuidv4");
const {
  generatePasswordHash,
  validatePassword,
  generateUserToken,
  verifyToken
} = require('../auth')

/* REGISTER USER */
router.post("/registration", async (req, res, next) => {

  try {

        //parse out email and the password 
      const email = req.body.email;
      const password = req.body.password;

      //generate our hash value 
      const hash = await generatePasswordHash(password);
      
      //create a new user object
      const user = {
        id: uuid(),
        email: email,
        password: hash,
      }; 
      await db().collection("users").insertOne(user);

      res.json({ success: true});
      
  } catch (error) {
    console.log(error);
    res.json({ 
      success: false,
      message: error.toString()
    })
    
  }
  
});

router.post("/login", async (req, res) => {

  try {

    const email = req.body.email;
    const password = req.body.password;
  
    //we would get the hashed password from the database 
    const user = await db().collection("users").findOne({email});
    const isValid = validatePassword(password, user.password);

    // check if the user is an admin or not
    const userType = email.includes("codeimmersives.com") ? "admin" : "user";

    //login valid for an hour
    const exp = Math.floor(Date.now() / 1000) + 60 * 60;
  
    if (!isValid) {
      // The input password is incorrect
      res.json({
        success: false,
        message: "Your password was incorrect",
      }).status(204); //we use 204 because the request is valid, but the input is still incorrect
      return;
    } 
  
    const data = {
        date: new Date(),
        userId: user.id,
        email: email,
        exp: exp,
        scope: userType
    };
  
    const token = generateUserToken(data)
  
    res.json({ 
      success: true,
      token,
      email 
    })
    
  } catch (error) {

    console.log(error);
    res.json({
      success: false, 
      message: error.toString()
    })
    
  }
  
});

router.get("/message", (req, res) => {
  try {

    //this usually comes from the front-end 
    //token header key is stored in the request header hence req.header(....)
    const tokenHeader = req.header(process.env.TOKEN_HEADER_KEY); 
    const token = req.header(tokenHeader) //get the token using the token header key
    console.log(token);
    const verified = verifyToken(token);

    console.log(verified);

    //returned successful if 
    res.json({
      success: true,
			message: `Hello ${verified.email}`
    });

  } catch (error) {
    res.json({
      success: false,
      error: error.toString(),
    });
  }
});

module.exports = router;
