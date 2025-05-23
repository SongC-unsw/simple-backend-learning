import dotenv from "dotenv";
dotenv.config();
import express from "express";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";
const db = new Database("database.db");
db.pragma("journal_mode = WAL");
//database setup here schema
const createTable = db.transaction(() => {
  db.prepare(
    `
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        password STRING NOT NULL
        )
        `
  ).run();
});
createTable();

const app = express();
// Middleware
app.set("view engine", "ejs");
app.use(cookieParser());
app.use(function (req, res, next) {
  res.locals.errors = [];
  // try to decode cookie
  try {
    const decodedCookie = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET);
    req.user = decodedCookie;
  } catch (err) {
    req.user = false;
  }

  res.locals.user = req.user;
  next();
});
app.use(express.static("public"));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.get("/", (req, res) => {
  if (req.user) {
    return res.render("dashboard");
  }
  res.render("homepage");
});
app.get("/login", (req, res) => {
  res.render("login");
});
app.get("/logout", (req, res) => {
  res.clearCookie("ourSimpleApp");
  res.redirect("/");
});
app.post("/register", (req, res) => {
  const errors = [];

  if (typeof req.body.username !== "string") req.body.username = "";
  if (typeof req.body.password !== "string") req.body.password = "";

  req.body.username = req.body.username.trim();
  if (!req.body.username) errors.push("You must enter a username");
  if (req.body.username && req.body.username.length < 3) errors.push("Username should be at least 3 characters");
  if (req.body.username && req.body.username.length > 10) {
    errors.push("Username should be less than 10 characters");
  }
  if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/))
    errors.push("Username can only contain letters and numbers");

  // password validation
  req.body.password = req.body.password.trim();
  if (!req.body.password) errors.push("You must enter a password");
  if (req.body.password && req.body.password.length < 8) errors.push("Password should be at least 8 characters");
  if (req.body.password && req.body.password.length > 20) {
    errors.push("Password should be less than 20 characters");
  }
  if (errors.length) {
    return res.render("homepage", { errors });
  }

  // save new user into database
  const salt = bcrypt.genSaltSync(10);
  req.body.password = bcrypt.hashSync(req.body.password, salt);
  const statement = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)");
  // make a secure token based on the user's id and username
  const result = statement.run(req.body.username, req.body.password);
  const lookupStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?");
  const ourUser = lookupStatement.get(result.lastInsertRowid);

  // log the user in by giving them a cookie
  const token = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
      username: ourUser.username,
      userId: ourUser.id,
    },
    process.env.JWTSECRET
  );

  res.cookie("ourSimpleApp", token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24 * 14,
  });
  res.send("Registered");
});

app.listen(3000);
