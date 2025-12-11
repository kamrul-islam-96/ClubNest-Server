require("dotenv").config();

const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const Stripe = require("stripe"); 
const serviceAccount = require("./firebase-adminsdk.json");
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

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

// firebase admin sdk initialize
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
    const clubCollection = db.collection("clubs");
    const membershipCollection = db.collection("memberships");

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

    app.post("/clubs", async (req, res) => {
      const {
        clubName,
        description,
        category,
        location,
        bannerImage,
        membershipFee,
        managerEmail,
        status,
        createdAt,
        updatedAt,
      } = req.body;

      if (
        !clubName ||
        !description ||
        !category ||
        !location ||
        !managerEmail
      ) {
        return res.status(400).json({ message: "Required fields missing" });
      }

      const newClub = {
        clubName,
        description,
        category,
        location,
        bannerImage: bannerImage || "",
        membershipFee: membershipFee || 0,
        status: status || "pending",
        managerEmail,
        createdAt,
        updatedAt,
      };

      const result = await clubCollection.insertOne(newClub);
      res.json({ success: true, clubId: result.insertedId });
    });

    app.get("/clubs", async (req, res) => {
      const { managerEmail } = req.query;

      if (managerEmail) {
        // Only fetch clubs managed by logged-in manager
        const clubs = await clubCollection.find({ managerEmail }).toArray();
        return res.json(clubs);
      }

      // Optional: return all approved clubs for public pages
      const allClubs = await clubCollection
        .find({ status: "approved" })
        .toArray();
      res.json(allClubs);
    });

    app.get("/clubs/:id", async (req, res) => {
      const { id } = req.params;

      try {
        const club = await clubCollection.findOne({ _id: new ObjectId(id) });
        if (!club) return res.status(404).json({ message: "Club not found" });

        // Active members count
        const membersCount = await membershipCollection
          .find({ clubId: id, status: "active" })
          .count();

        // Manager info
        const manager = await userCollection.findOne({
          email: club.managerEmail,
        });

        res.json({
          ...club,
          membersCount,
          managerName: manager?.name || "Unknown",
          managerEmail: manager?.email || club.managerEmail,
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
      }
    });

    app.patch("/clubs/:id", async (req, res) => {
      const { id } = req.params;
      const updates = req.body;

      const club = await clubCollection.findOne({ _id: new ObjectId(id) });
      if (!club) return res.status(404).json({ message: "Club not found" });

      // Only manager who created it can update
      if (club.managerEmail !== req.decodedUser.email) {
        return res.status(403).json({ message: "Forbidden" });
      }

      updates.updatedAt = new Date();
      await clubCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updates }
      );

      res.json({ success: true, message: "Club updated" });
    });

    // Create Membership route updated to handle free vs paid
    app.post("/memberships", verifyFirebaseToken, async (req, res) => {
      const { userEmail, clubId } = req.body;
      if (!userEmail || !clubId)
        return res.status(400).json({ message: "Missing fields" });

      // 🔹 fetch club to check membership fee
      const club = await clubCollection.findOne({ _id: new ObjectId(clubId) }); // 🔹 new
      if (!club) return res.status(404).json({ message: "Club not found" }); // 🔹 new

      // 🔹 determine initial membership status based on fee
      const status = club.membershipFee > 0 ? "pendingPayment" : "active"; // 🔹 new

      const membershipData = {
        userEmail,
        clubId,
        status, 
        paymentId: null, 
        joinedAt: new Date(),
        expiresAt: null,
      };

      const result = await membershipCollection.insertOne(membershipData);
      res.json({
        success: true,
        membershipId: result.insertedId,
        status, 
      });
    });

    // Create Payment Intent route (for paid memberships)
    app.post(
      "/create-payment-intent",
      verifyFirebaseToken,
      async (req, res) => {
        const { amount, currency, userEmail, clubId } = req.body;
        if (!amount || !currency || !userEmail || !clubId)
          return res.status(400).json({ message: "Missing fields" });

        const paymentIntent = await stripe.paymentIntents.create({
          amount,
          currency,
          metadata: { userEmail, clubId, type: "membership" },
        });

        res.json({ clientSecret: paymentIntent.client_secret }); 
      }
    );

    // Confirm Membership after Payment Success
    app.patch(
      "/memberships/:id/confirm",
      verifyFirebaseToken,
      async (req, res) => {
        // 🔹 new
        const { id } = req.params;
        const { paymentId } = req.body;

        const membership = await membershipCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!membership)
          return res.status(404).json({ message: "Membership not found" });

        await membershipCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status: "active", paymentId, updatedAt: new Date() } }
        );

        res.json({ success: true, message: "Membership activated" });
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
