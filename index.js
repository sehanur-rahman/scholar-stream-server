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


    // ---------------- Scholarships ----------------
    app.get("/scholarships", async (req, res) => {
      let {
        search = "",
        category = "",
        subject = "",
        country = "",
        degree = "",
        sort = "",
        page = 1,
        limit = 10,
      } = req.query;

      page = parseInt(page);
      limit = parseInt(limit);

      const query = {};
      if (search) {
        query.$or = [
          { scholarshipName: { $regex: search, $options: "i" } },
          { universityName: { $regex: search, $options: "i" } },
          { degree: { $regex: search, $options: "i" } },
        ];
      }
      if (category) query.scholarshipCategory = category;
      if (subject) query.subjectCategory = subject;
      if (country) query.universityCountry = country;
      if (degree) query.degree = degree;


      let sortOption = {};
      if (sort === "fees-asc") sortOption.applicationFees = 1;
      if (sort === "fees-desc") sortOption.applicationFees = -1;
      if (sort === "newest") sortOption.scholarshipPostDate = -1;
      if (sort === "oldest") sortOption.scholarshipPostDate = 1;

      const total = await scholarshipsCollection.countDocuments(query);
      const data = await scholarshipsCollection
        .find(query)
        .sort(sortOption)
        .skip((page - 1) * limit)
        .limit(limit)
        .toArray();

      res.send({ total, page, limit, totalPages: Math.ceil(total / limit), data });
    });

    app.get("/scholarships/:id", async (req, res) => {
      res.send(
        await scholarshipsCollection.findOne({ _id: new ObjectId(req.params.id) })
      );
    });

    app.post("/scholarships", verifyJWT, verifyAdmin, async (req, res) => {
      res.send(await scholarshipsCollection.insertOne(req.body));
    });

    app.patch("/scholarships/:id", verifyJWT, verifyAdmin, async (req, res) => {
      res.send(
        await scholarshipsCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: req.body }
        )
      );
    });

    app.delete("/scholarships/:id", verifyJWT, verifyAdmin, async (req, res) => {
      res.send(
        await scholarshipsCollection.deleteOne({ _id: new ObjectId(req.params.id) })
      );
    });

    app.get("/scholarships/admin/all", verifyJWT, verifyAdmin, async (req, res) => {
      const data = await scholarshipsCollection.find().toArray();
      res.send(data);
    });


    // ---------------- Applications ----------------
    app.post("/applications", verifyJWT, async (req, res) => {
      const exists = await applicationsCollection.findOne({
        scholarshipId: req.body.scholarshipId,
        userEmail: req.decoded.email,
      });

      if (exists) {
        return res.status(409).send({
          message: "Application already exists"
        });
      }

      const user = await usersCollection.findOne({
        email: req.decoded.email,
      });

      const application = {
        ...req.body,
        userName: user?.name || "Unknown",
        userEmail: req.decoded.email,
        applicationStatus: "pending",
        paymentStatus: req.body.paymentStatus,
        applicationDate: new Date(),
      };

      const result = await applicationsCollection.insertOne(application);
      res.send(result);
    });


    app.get(
      "/applications/check/:scholarshipId",
      verifyJWT,
      async (req, res) => {
        const exists = await applicationsCollection.findOne({
          scholarshipId: req.params.scholarshipId,
          userEmail: req.decoded.email,
        });

        res.send({ applied: !!exists });
      }
    );


    app.get("/applications/me", verifyJWT, async (req, res) => {
      res.send(
        await applicationsCollection
          .find({ userEmail: req.decoded.email })
          .toArray()
      );
    });


    app.get("/applications", verifyJWT, verifyModerator, async (req, res) => {
      res.send(await applicationsCollection.find().toArray());
    });


    app.patch(
      "/applications/pay/:id",
      verifyJWT,
      async (req, res) => {
        const _id = new ObjectId(req.params.id);

        const appData = await applicationsCollection.findOne({ _id });

        if (!appData) {
          return res.status(404).send({ message: "Application not found" });
        }

        if (appData.paymentStatus === "paid") {
          return res
            .status(400)
            .send({ message: "Application already paid" });
        }

        const result = await applicationsCollection.updateOne(
          { _id },
          {
            $set: {
              paymentStatus: "paid",
            },
          }
        );

        res.send(result);
      }
    );


    app.delete(
      "/applications/:id",
      verifyJWT,
      async (req, res) => {
        const id = req.params.id;

        const application = await applicationsCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!application) {
          return res.status(404).send({ message: "Application not found" });
        }

        if (application.userEmail !== req.decoded.email) {
          return res.status(403).send({ message: "Forbidden" });
        }

        if (application.applicationStatus !== "pending") {
          return res.status(400).send({
            message: "Only pending applications can be deleted",
          });
        }

        await applicationsCollection.deleteOne({
          _id: new ObjectId(id),
        });

        res.send({ success: true });
      }
    );


    // --------MODERATOR Status Flow --------
    app.patch(
      "/applications/status/:id",
      verifyJWT,
      verifyModerator,
      async (req, res) => {
        const { status } = req.body;
        const allowed = ["pending", "processing", "completed", "rejected"];

        if (!allowed.includes(status)) {
          return res.status(400).send({ message: "Invalid status" });
        }

        const _id = new ObjectId(req.params.id);

        const appData = await applicationsCollection.findOne({ _id });

        if (!appData) {
          return res.status(404).send({ message: "Application not found" });
        }

        if (appData.paymentStatus !== "paid" && status !== "rejected") {
          return res
            .status(403)
            .send({ message: "Unpaid application cannot be processed" });
        }

        const result = await applicationsCollection.updateOne(
          { _id },
          { $set: { applicationStatus: status } }
        );

        res.send(result);
      }
    );


    // -------- MODERATOR: ADD / UPDATE FEEDBACK --------
    app.patch(
      "/applications/:id",
      verifyJWT,
      verifyModerator,
      async (req, res) => {
        const { feedback } = req.body;

        if (!feedback || feedback.trim() === "") {
          return res.status(400).send({ message: "Feedback is required" });
        }

        const result = await applicationsCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          {
            $set: {
              feedback: feedback,
            },
          }
        );

        res.send(result);
      }
    );


    // -------- MODERATOR: GET ALL REVIEWS --------
    app.get(
      "/reviews/admin/all",
      verifyJWT,
      verifyModerator,
      async (req, res) => {
        const reviews = await reviewsCollection.find().toArray();
        res.send(reviews);
      }
    );


    // -------- MODERATOR: DELETE ANY REVIEW --------
    app.delete(
      "/reviews/moderator/:id",
      verifyJWT,
      verifyModerator,
      async (req, res) => {
        const review = await reviewsCollection.findOne({
          _id: new ObjectId(req.params.id),
        });

        if (!review) {
          return res.status(404).send({ message: "Review not found" });
        }

        await reviewsCollection.deleteOne({
          _id: new ObjectId(req.params.id),
        });

        res.send({ success: true });
      }
    );


    // ---------------- Reviews ----------------
    app.post("/reviews", verifyJWT, async (req, res) => {
      const applied = await applicationsCollection.findOne({
        userEmail: req.decoded.email,
        scholarshipId: req.body.scholarshipId,
        applicationStatus: "completed",
      });
      if (!applied)
        return res.status(403).send({ message: "Application not completed" });

      req.body.reviewDate = new Date();
      res.send(await reviewsCollection.insertOne(req.body));
    });

    app.get("/reviews/:scholarshipId", async (req, res) => {
      res.send(
        await reviewsCollection
          .find({ scholarshipId: req.params.scholarshipId })
          .toArray()
      );
    });

    // -------- STUDENT: UPDATE REVIEW --------
    app.patch(
      "/reviews/:id",
      verifyJWT,
      async (req, res) => {
        const { ratingPoint, reviewComment } = req.body;

        const review = await reviewsCollection.findOne({
          _id: new ObjectId(req.params.id),
        });

        if (!review) {
          return res.status(404).send({ message: "Review not found" });
        }

        if (review.userEmail !== req.decoded.email) {
          return res.status(403).send({ message: "Forbidden" });
        }

        const result = await reviewsCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          {
            $set: {
              ratingPoint,
              reviewComment,
            },
          }
        );

        res.send(result);
      }
    );


    // -------- STUDENT: DELETE REVIEW --------
    app.delete(
      "/reviews/:id",
      verifyJWT,
      async (req, res) => {
        const review = await reviewsCollection.findOne({
          _id: new ObjectId(req.params.id),
        });

        if (!review) {
          return res.status(404).send({ message: "Review not found" });
        }

        // Only owner can delete
        if (review.userEmail !== req.decoded.email) {
          return res.status(403).send({ message: "Forbidden" });
        }

        await reviewsCollection.deleteOne({
          _id: new ObjectId(req.params.id),
        });

        res.send({ success: true });
      }
    );


    // ---------------- Admin Analytics ----------------
    app.get("/admin-stats", verifyJWT, verifyAdmin, async (req, res) => {
      const users = await usersCollection.estimatedDocumentCount();
      const scholarships = await scholarshipsCollection.estimatedDocumentCount();

      const totalFees = await applicationsCollection
        .aggregate([
          { $match: { paymentStatus: "paid" } },
          {
            $group: {
              _id: null,
              total: {
                $sum: {
                  $add: [
                    { $ifNull: [{ $toDouble: "$applicationFees" }, 0] },
                    { $ifNull: [{ $toDouble: "$serviceCharge" }, 0] },
                  ],
                },
              },
            },
          },
        ])
        .toArray();

      res.send({
        users,
        scholarships,
        totalFees: totalFees[0]?.total || 0,
      });
    });


    // -------- ADMIN ANALYTICS: APPLICATION COUNT --------
    app.get(
      "/admin-application-stats",
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        const groupBy = req.query.by || "university";

        let groupStage = {};

        if (groupBy === "category") {
          groupStage = { $group: { _id: "$scholarshipCategory", count: { $sum: 1 } } };
        } else {
          groupStage = { $group: { _id: "$universityName", count: { $sum: 1 } } };
        }

        const result = await applicationsCollection
          .aggregate([
            { $match: { paymentStatus: "paid" } },
            groupStage,
            { $sort: { count: -1 } },
          ])
          .toArray();

        res.send(result);
      }
    );

    // ---------------- Stripe ----------------
    app.post("/create-payment-intent", async (req, res) => {
      const scholarship = await scholarshipsCollection.findOne({
        _id: new ObjectId(req.body.scholarshipId),
      });
      if (!scholarship)
        return res.status(404).send({ message: "Scholarship not found" });

      const fee = Number(scholarship.applicationFees);
      if (!fee || fee <= 0)
        return res.status(400).send({ message: "Invalid application fee" });

      const intent = await stripe.paymentIntents.create({
        amount: fee * 100,
        currency: "usd",
      });

      res.send({ clientSecret: intent.client_secret });
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

