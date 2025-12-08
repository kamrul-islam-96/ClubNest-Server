const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const serviceAccount = require("./firebase-adminsdk.json");
const { MongoClient, ServerApiVersion } = require("mongodb");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const port = process.env.PORT || 3000;

// MongoDB URI
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@clubnest.9yeit7s.mongodb.net/?appName=clubnest`;

// MongoClient setup
const client = new MongoClient(uri, {
  serverApi: ServerApiVersion.v1,
});

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const verifyFirebaseToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized: No token" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.decodedUser = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

async function run() {
  try {
    await client.connect();
    const db = client.db("clubnest");
    const userCollection = db.collection("users");

    // Save User (Register + Google Login) → role default "member"
    app.post("/api/auth/save-user", async (req, res) => {
      const { uid, name, email, photoURL, role = "member" } = req.body;

      if (!uid || !email) {
        return res.status(400).json({ message: "UID and Email required" });
      }

      const userData = {
        uid,
        name: name || "Anonymous",
        email: email.toLowerCase(),
        photoURL: photoURL || "",
        role,
        createdAt: new Date(),
      };

      // $setOnInsert → first time save all then update
      const result = await userCollection.updateOne(
        { uid: uid },
        {
          $setOnInsert: userData,
          $set: { updatedAt: new Date() },
        },
        { upsert: true }
      );

      res.json({ success: true, role });
    });

    // Get single user role
    app.get("/api/users/role", async (req, res) => {
      const { email } = req.query;
      if (!email) return res.status(400).json({ message: "Email required" });

      const user = await userCollection.findOne({ email: email });
      res.json({ role: user?.role || "member" });
    });

    // Get all users (Admin dashboard)
    app.get("/api/users", async (req, res) => {
      const users = await userCollection
        .find({})
        .project({
          uid: 1,
          name: 1,
          email: 1,
          photoURL: 1,
          role: 1,
          createdAt: 1,
        })
        .sort({ createdAt: -1 })
        .toArray();
      res.json(users);
    });

    // MIDDLEWARE: Verify Admin
    const verifyAdmin = async (req, res, next) => {
      const email = req.decodedUser?.email;

      if (!email) return res.status(401).json({ message: "Unauthorized" });

      const user = await userCollection.findOne({ email });

      if (!user || user.role !== "admin") {
        return res
          .status(403)
          .json({ message: "Forbidden: Admin access only" });
      }

      req.requestedBy = user.email;
      next();
    };

    app.patch(
      "/api/users/role",
      verifyFirebaseToken,
      verifyAdmin,
      async (req, res) => {
        const { email, newRole } = req.body;

        if (!email || !newRole) {
          return res
            .status(400)
            .json({ message: "Email and newRole required" });
        }

        if (!["admin", "clubManager", "member"].includes(newRole)) {
          return res.status(400).json({ message: "Invalid role" });
        }

        // Admin cannot demote himself
        const requestingAdminEmail = req.requestedBy;
        if (email === requestingAdminEmail && newRole !== "admin") {
          return res
            .status(403)
            .json({ message: "Admin cannot demote himself" });
        }

        const result = await userCollection.updateOne(
          { email: email },
          { $set: { role: newRole, updatedAt: new Date() } }
        );

        if (result.modifiedCount === 0) {
          return res.status(404).json({ message: "User not found" });
        }

        res.json({ success: true, message: "Role updated to " + newRole });
      }
    );

    console.log("MongoDB Connected + All Routes Ready");
  } catch (err) {
    console.error("MongoDB connection error:", err);
  }
}

run();

// simple route
app.get("/", (req, res) => {
  res.send("Server is running");
});

app.listen(port, () => {
  console.log(`Server listening on ${port}`);
});
