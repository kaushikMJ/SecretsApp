//require('dotenv').config()
import dotenv from "dotenv";
dotenv.config();
import express from "express";
//const express= require("express");
const app= express();
import bodyParser from "body-parser";
//const bodyParser= require("body-parser")
import mongoose from "mongoose";
//const mongoose= require('mongoose');
//const encrypt= require('mongoose-encryption')
import session from "express-session";
//const session= require('express-session');
import passport from "passport";
//const passport= require("passport");
import passportLocalMongoose from "passport-local-mongoose";
//const passportLocalMongoose= require("passport-local-mongoose");
import { title } from "process";
import pkg from "passport";
const { use } =pkg 
//const { title } = require("process");
//const { use } = require('passport');

import { fileURLToPath } from 'url';
import path from 'path';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(bodyParser.urlencoded({extended: true}))

//app.use(express.static("public"))

// Require static assets from public folder
app.use(express.static(path.join(__dirname, 'public')));

// Set 'views' directory for any views 
// being rendered res.render()
app.set('views', path.join(__dirname, 'views'));
app.set("view engine", "ejs")

mongoose.set('strictQuery', true);

//session
//to know more about secret,resave etc..follow documentation of npm module express-session
app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));

//use passport to start authentication
app.use(passport.initialize());

//use passport to set up a session
app.use(passport.session());

const uri= process.env.URI;
mongoose.connect(uri, {useNewUrlParser: true}); 

const secretSchema= new mongoose.Schema({
    secretPost: String,
    userId: String
});

const userSchema= new mongoose.Schema({
    username: String,
    password: String,
    secretIdArray: [String]
});


//plugin..for salting and hashing and store the user to db
userSchema.plugin(passportLocalMongoose);

const Secret= new mongoose.model("Secret", secretSchema);
const User= new mongoose.model("User", userSchema);

//passportLocalMongoose codes
passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/", function(req, res){
    if(req.isAuthenticated()){
        //when user is authenticated,there is no point in showing home page with register and login option
        res.redirect("/secrets");
    }
    else{
        res.render("home", {isItAuthenticated: false});
    }
});

app.get("/login", function(req, res){
    if(req.isAuthenticated()){
        //when user is authenticated,there is no point in showing login page 
        res.redirect("/secrets");
    }
    else{
        res.render("login", {isItAuthenticated: false, err: false});
    }
});

app.get("/submit", function(req, res){
    if(req.isAuthenticated()){
        //when user is authenticated,then the user can access the "/submit" route else not 
        res.render("submit", {isItAuthenticated: true});
    }
    else{
        res.render("login", {isItAuthenticated: false, err: false});
    }
});

//submit a secret
app.post("/submit", function(req, res){
    if(req.isAuthenticated()){
        const newSecret= new Secret({
            secretPost: req.body.secret,
            userId: req.user.id
        })

        newSecret.save(function(err){
            if(err) console.log(err);
            else{
                //find the newly inserted secret 
                Secret.findOne({}, {}, { sort: { _id: -1 } }, function(err, result) {
                    if (err) throw err;
                    else{
                        //add the id of newly inserted secret inside the secretIdArray of current user
                        const userid= req.user.id;
                        User.findByIdAndUpdate(userid, {$push: {secretIdArray: result.id}}, function(err){
                            if(err) console.log(err);
                        })
                    }
                });
            }
            res.redirect("/secrets");
        });
    }
    else{
        //when user is not authenticated,then they can't access the logout route
        res.redirect("/login");
    }
});
app.get("/logout", function(req, res){
    if(req.isAuthenticated()){
        req.logout(function(err){
            if(err) console.log(err);
        });
        res.redirect("/");
    }
    else{
        //when user is not authenticated,then they can't access the logout route
        res.redirect("/login");
    }
});
app.get("/register", function(req, res){
    if(req.isAuthenticated()){
        //when user is authenticated,there is no point in showing register page 
        res.redirect("/secrets");
    }
    else{
        res.render("register", {isItAuthenticated: false, err: false});
    }
});

app.get("/secrets", function(req, res){
    if(req.isAuthenticated()){
        
        Secret.find({},{_id: 0, secretPost: 1}, function(err, allSecrets){
            if(err) {console.log(err); }
            else{
                res.render("secrets", {allSecrets: allSecrets, isItAuthenticated: true});
            }
        });
    }
    else{
        res.redirect("/login")
    }
});

app.get("/mysecrets", function(req, res){
    //show the secrets of the current user
    if(req.isAuthenticated()){
        Secret.find({userId: req.user.id}, {_id:0, secretPost: 1}, function(err, secrets){
            if(err){console.log(err); res.redirect("/secrets");}
            else{
                res.render("mysecrets", {mySecrets: secrets, isItAuthenticated: true});
            }
        })
    }
    else{
        res.redirect("/login");
    }
});

app.post("/register", function(req, res){
    //no need to use findOne() and check if user registered in past..USer.register gives the error when user is already registered in past
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err);
            res.render("register", {isItAuthenticated: false,err: true});
        }
        else{
            passport.authenticate("local", {failureRedirect: '/register'})(req, res, function(){
                //res.locals.user= req.user;
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login", function(req, res){

    const user= new User({
        username: req.body.username,
        password: req.body.password
    })
    passport.authenticate('local', function(err, user, info) {

        if(err) { res.render('login', {err: true, isItAuthenticated: false}); }
        if(user){
            req.logIn(user, function(err) {
                if (err) { res.render('login', {err: true, isItAuthenticated: false}); }
                else {
                    //res.locals.user= req.user;
                    res.redirect('/secrets');
                }
            });
        }
        else{ 
            //Incorrect credentials, hence redirect to login 
            return res.render('login', {err: true, isItAuthenticated: false});; 
        }
        
    })(req, res);
});
    
            /*when user have successfully registered or logged in using the right credentials, we are going to send a cookie
            and tell the browser to hold onto that cookie, because the cookie has a few pieces of information that tells our 
            server abput the user,namely that they are authorized to view any of the pages that require authentication
            */
            //the control gets into else part even when password is incorrect
            /*
            //problem with below code: user getting authenticated(cookie gets created) even after providing wrong password
            passport.authenticate("local", {failureRedirect: '/login'})(req, res, function(){
                res.redirect("/secrets");
            })
            */

            //app.get('/login', function(req, res) {
                
            
app.get("/check", function(req, res){
    if(req.isAuthenticated()){
        Secret.find({userId: req.user.id}, {_id:0, secretPost: 1}, function(err, secrets){
            if(err){console.log(err); res.redirect("/secrets");}
            else{
                res.render("check", {mySecrets: secrets, isItAuthenticated: true});
            }
        })
    }
    else{
        res.redirect("/login");
    }
});

app.get('*', (req, res) => {
    res.render("notFound.ejs", {msg: "PAGE NOT FOUND!", isItAuthenticated: req.isAuthenticated()});
  });


app.listen(9000, function(){
    console.log("Server started on port 9000");
})