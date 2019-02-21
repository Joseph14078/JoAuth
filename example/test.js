const JoAuth = require("./index.js");
const MongoClient = require('mongodb').MongoClient;

let db, auth;

MongoClient.connect(
    "mongodb://main:1qwerty@ds343895.mlab.com:43895/joauthtest",
    { useNewUrlParser: true },
    (errorConnect, client) => {
        db = client.db("joauthtest");
        auth = new JoAuth({
            collection: db.collection("users")
        });
        console.log("Connected");
    }
);