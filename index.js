require("dotenv").config();
require("./utils.js");

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;
const Joi = require("joi");

const app = express();

const port = process.env.PORT || 3000;

const expireTime = 1 * 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
            secret: mongodb_session_secret
    }
});

app.set('view engine', 'ejs');

app.use(session({
    secret: node_session_secret,
        store: mongoStore,
        saveUninitialized: false,
        resave: true
}));

app.get('/nosql-injection', async (req,res) => {
        var username = req.query.user;
        var input = "";
        if (!username) {
            input = "<h1>No username provided - try \"/nosql-injection?user=name\", or \"/nosql-injection?user[$ne]=name\"</h1>";
            res.render("nosql-injection", {input: input});
        }
        console.log("User: " + username);

        const schema = Joi.string().max(20).required();
        const validationResult = schema.validate(username);

        if (validationResult.error != null) {
            console.log(validationResult.error);
            input = "<h1 style='color:darkred;'>A NoSQL injection attack was detected!<h1>"
            res.render("nosql-injection", {input: input});
            return;
        }

        const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

        console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.use(express.static(__dirname + "/public"));

app.get("/", (req, res) => {
    if (!req.session.authenticated) {
        res.render("index");
    } else {
        res.redirect("/loggedin");
    }
});

app.get("/login", (req, res) => {
    var validateError = req.query.validateError;
    var first = req.query.first;
    var error = "";
    if (validateError == 1) {
        error = "User does not exist. Please sign up instead.";
    } else if (validateError == 2) {
        error = "Incorrect password.";
    } else if (validateError == 3) {
        error = "Incorrect email.";
    } else if (validateError == 4) {
        error = "You are not logged in, please login.";
    }
    if (first == 1) {
        error = "Please now login, the cookie does not get assigned fast enough to automatically log you in."
    }
    res.render("login", {error: error});
});

app.get("/signup", (req, res) => {
    var validateError = req.query.validateError;
    if (validateError == 1) {
        var error = "Username must be between 2 and 24 characters.";
        var error2 = "Password must be between 4 and 20 characters.";
    }
    res.render("signup", {error: error, error2: error2});
});

app.post("/submitUser", async (req, res) => {
    var username = req.body.name;
    var password = req.body.password;
    var email = req.body.email;

        const schema = Joi.object(
            {
                username: Joi.string().alphanum().min(2).max(24).required(),
                password: Joi.string().min(4).max(20).required(),
                email: Joi.string().min(3).max(99).required()
            });

        const validationResult = schema.validate({username, password, email});
        if (validationResult.error != null) {
            console.log(validationResult.error);
            res.redirect("/signup?validateError=1");
            return;
        }

        var hashedPassword = await bcrypt.hash(password, saltRounds);

            await userCollection.insertOne({name: username, password: hashedPassword, email: email, user_type: "user"});
            console.log("Inserted user");;
            res.redirect("/login?first=1");
});

app.post("/loggingin", async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

        const result = await userCollection.find({email: email}).project({name: 1, password: 1, _id: 1}).toArray();

        console.log(result);
        if (result.length != 1) {
            console.log("user not found");
            res.redirect("/login?validateError=1");
            return;
        }
        if (await bcrypt.compare(password, result[0].password)) {
            console.log("correct password");
        } else {
            console.log("incorrect password");
            res.redirect("/login?validateError=2");
            return;
        }
        if (await bcrypt.compare(email, result[0].email)) {
            req.session.authenticated = true;
            req.session.username = username;
            req.session.cookie.maxAge = expireTime;
            res.redirect(`/loggedin?user=${username}`);
            return;
        }
        else {
            console.log("incorrect email");
            res.redirect("/login?validateError=3");
            return;
        }
});

app.get("/loggedin", (req, res) => {
    var user = req.session.name;
    if (!req.session.authenticated) {
        res.redirect("/login?validateError=4");
    }
    res.render("loggedin", {user: user});
});

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

app.get("/members", (req, res) => {
    var num = Math.floor(Math.random() * 3) + 1;
    var src = "image-" + num + ".jpg";
    var user = req.session.username;
    if (!req.session.authenticated) {
        res.redirect("/");
    }
    res.render("members", {src: src, user: user});
});

app.get("/admin", (req, res) => {
    var users = userCollection.find();
    var names = "<p class='admin-usernames'>";
    for (i = 0; users.hasNext(); i++) {
        names += users[i].name;
    }
    names += "</p>";
    res.render("admin", {names: names});
});

app.get("*", (req, res) => {
    res.statusCode = 404;
    res.render("404");

});

app.listen(port, () => {
    console.log("Node application running on port " + port);
});
