var express = require("express");
var router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

let user = {};

/* GET users listing. */
router.post("/registration", async (req, res, next) => {

  //parse out email and the password 
  const email = req.body.email;
  const password = req.body.password;

  const saltRounds = 5; // For prod apps, saltRounds are going to be between 5 and 10
  const salt = await bcrypt.genSalt(saltRounds);
  //we never save a password in  database as cleartext,
  //instead we always "hash" it
  // hash = generate a long string of letters and numbers that
  // is associated with our password
  const hash = await bcrypt.hash(password, salt);

  user = {
    email,
    password: hash,
  }; // Simulating us creating a user in the database

  console.log(salt);
  console.log(hash);

  console.log(user);

  res.send("respond with a resource");
});

router.post("/login", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;


  //we would get the hashed password from the database 
  const hashedUserPassword = user.password;

  console.log(password, hashedUserPassword);

  // we can then use bycrypt to check if the password is valid
  const passwordMatch = await bcrypt.compare(password, hashedUserPassword);

  console.log(passwordMatch);

  if (passwordMatch === false) {
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
  console.log(exp);

  //other data that describes our "session" of loggin in
  const payload = {
    email,
		exp, 
    scope: "user",
  };

  //secret key is unique to app
  const secretKey = process.env.JWT_SECRET_KEY;

  console.log(secretKey);
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
