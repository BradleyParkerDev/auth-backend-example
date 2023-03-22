var express = require("express");
var router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { db } = require('../mongo');
const { uuid } = require("uuidv4");
const {
  generatePasswordHash,
  validatePassword
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
  const email = req.body.email;
  const password = req.body.password;


  //we would get the hashed password from the database 
  const user = await db().collection("users").findOne({email});
  const isValid = validatePassword(password, user.password);

  if (isValid === false) {
    // The input password is incorrect
    res.json({
      success: false,
      message: "Your password was incorrect",
    });
    return;
  }

  //login valid for an hour
	const exp = Math.floor(Date.now() / 1000) + 60 * 60;
  // 3600 seconds in an hour (60 min * 60 seconds)

  //other data that describes our "session" of loggin in
  const payload = {
    email,
		exp, 
    scope: "user",
  };

  //secret key is unique to app
  const secretKey = process.env.JWT_SECRET_KEY;

  //server signing off on the payload, so the receiver knows where it's coming from.
  const token = jwt.sign(payload, secretKey);

  res.json({
    success: true,
    token: token,
  });
});

router.get("/message", (req, res) => {
  try {
    const token = req.header("ci_token");

    console.log(token);
    const secretKey = process.env.JWT_SECRET_KEY;

    const verified = jwt.verify(token, secretKey);

    console.log(verified);

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
