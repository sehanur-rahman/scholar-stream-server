// ScholarStream Backend 

require("dotenv").config();

const admin = require("firebase-admin");

const decoded = Buffer.from(
  process.env.FB_SERVICE_KEY,
  "base64"
).toString("utf8");

const serviceAccount = JSON.parse(decoded);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});


const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const stripe = require("stripe")(process.env.STRIPE_SECRET);

const app = express();
const port = process.env.PORT || 5000;

// ---------------- Middleware ----------------
app.use(
  cors({
    origin: process.env.CLIENT_ORIGIN,
    credentials: true,
  })
);
app.use(express.json());

// ---------------- MongoDB Setup ----------------
const client = new MongoClient(process.env.MONGO_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let usersCollection;
let scholarshipsCollection;
let applicationsCollection;
let reviewsCollection;

// ---------------- JWT Middleware ----------------
const verifyJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer "))
    return res.status(401).send({ message: "Unauthorized" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).send({ message: "Forbidden" });
    req.decoded = decoded;
    next();
  });
};

// ---------------- Role Middleware ----------------
const verifyAdmin = async (req, res, next) => {
  const user = await usersCollection.findOne({ email: req.decoded.email });
  if (user?.role !== "Admin")
    return res.status(403).send({ message: "Admin only" });
  next();
};

const verifyModerator = async (req, res, next) => {
  const user = await usersCollection.findOne({ email: req.decoded.email });
  if (user?.role !== "Moderator")
    return res.status(403).send({ message: "Moderator only" });
  next();
};

// ---------------- Main Function ----------------
async function run() {
  try {
    await client.connect();
    const db = client.db("scholar-stream");

    usersCollection = db.collection("users");
    scholarshipsCollection = db.collection("scholarships");
    applicationsCollection = db.collection("applications");
    reviewsCollection = db.collection("reviews");

    console.log(" MongoDB Connected");

    // ---------------- JWT ----------------
    app.post("/jwt", async (req, res) => {
      const user = await usersCollection.findOne({ email: req.body.email });
      if (!user) return res.status(401).send({ message: "Unauthorized" });

      const token = jwt.sign(
        { email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: "7d" }
      );
      res.send({ token });
    });

    // ---------------- Users ----------------
    app.post("/users", async (req, res) => {
      const exists = await usersCollection.findOne({ email: req.body.email });
      if (exists) return res.send({ message: "User exists" });

      req.body.role = "Student";
      res.send(await usersCollection.insertOne(req.body));
    });

    app.get("/users", verifyJWT, verifyAdmin, async (req, res) => {
      res.send(await usersCollection.find().toArray());
    });


    app.get("/users/:email", verifyJWT, async (req, res) => {
      if (req.params.email !== req.decoded.email)
        return res.status(403).send({ message: "Forbidden" });

      const user = await usersCollection.findOne({ email: req.params.email });
      res.send(user);
    });


    app.patch("/users/role/:id", verifyJWT, verifyAdmin, async (req, res) => {
      res.send(
        await usersCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { role: req.body.role } }
        )
      );
    });

    app.delete("/users/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;

      const user = await usersCollection.findOne({ _id: new ObjectId(id) });

      if (!user) {
        return res.status(404).send({ message: "User not found" });
      }

      // Prevent admin deleting himself
      if (user.email === req.decoded.email) {
        return res.status(400).send({ message: "You cannot delete yourself" });
      }

      try {
        // Delete from Firebase Auth
        const firebaseUser = await admin.auth().getUserByEmail(user.email);
        await admin.auth().deleteUser(firebaseUser.uid);

        // Delete from MongoDB
        await usersCollection.deleteOne({ _id: new ObjectId(id) });

        res.send({ success: true });
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Failed to delete user" });
      }
    });


  } catch (err) {
    console.error(err);
  }
}

run();

// ---------------- Root ----------------
app.get("/", (req, res) => {
  res.send("ScholarStream Server Running...");
});

module.exports = app;

