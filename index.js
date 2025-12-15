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
    const clubsCollection = db.collection("clubs");
    const membershipCollection = db.collection("memberships");
    const eventsCollection = db.collection("events");
    const eventRegistrationsCollection = db.collection("eventRegistrations");

    // MIDDLEWARE: Verify Admin
    const verifyAdmin = async (req, res, next) => {
      const email = req.decodedUser?.email;

      const user = await userCollection.findOne({ email });

      if (!user || user.role !== "admin") {
        return res
          .status(403)
          .json({ message: "Forbidden: Admin access only" });
      }

      req.requestedBy = email;
      next();
    };

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
        status: "pending",
        managerEmail,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await clubsCollection.insertOne(newClub);
      res.json({ success: true, clubId: result.insertedId });
    });

    app.get("/clubs", async (req, res) => {
      const { managerEmail } = req.query;

      if (managerEmail) {
        // Only fetch clubs managed by logged-in manager
        const clubs = await clubsCollection.find({ managerEmail }).toArray();
        return res.json(clubs);
      }

      // Optional: return all approved clubs for public pages
      const allClubs = await clubsCollection
        .find({ status: "approved" })
        .toArray();
      res.json(allClubs);
    });

    app.get("/clubs/:id", async (req, res) => {
      const { id } = req.params;

      try {
        const club = await clubsCollection.findOne({ _id: new ObjectId(id) });
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

    app.patch("/clubs/:id", verifyFirebaseToken, async (req, res) => {
      const { id } = req.params;
      const updates = req.body;

      const club = await clubsCollection.findOne({ _id: new ObjectId(id) });
      if (!club) return res.status(404).json({ message: "Club not found" });

      if (club.managerEmail !== req.decodedUser.email) {
        return res.status(403).json({ message: "Forbidden" });
      }

      updates.updatedAt = new Date();

      await clubsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updates }
      );

      res.json({ success: true, message: "Club updated" });
    });

    app.get(
      "/api/admin/clubs",
      verifyFirebaseToken,
      verifyAdmin,
      async (req, res) => {
        const clubs = await clubsCollection
          .find({ status: "pending" })
          .toArray();
        // Ensure membershipFee is numeric for frontend
        const fixedClubs = clubs.map((c) => ({
          ...c,
          membershipFee: Number(c.membershipFee || 0),
        }));
        res.json(fixedClubs);
      }
    );

    // PATCH: Approve club
    app.patch(
      "/api/admin/clubs/:id/approve",
      verifyFirebaseToken,
      verifyAdmin,
      async (req, res) => {
        const { id } = req.params;
        if (!ObjectId.isValid(id))
          return res.status(400).json({ error: "Invalid ID" });

        const result = await clubsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status: "approved", updatedAt: new Date() } }
        );

        if (result.matchedCount === 0)
          return res.status(404).json({ error: "Club not found" });
        res.json({ success: true });
      }
    );

    // PATCH: Reject club
    app.patch(
      "/api/admin/clubs/:id/reject",
      verifyFirebaseToken,
      verifyAdmin,
      async (req, res) => {
        const { id } = req.params;
        if (!ObjectId.isValid(id))
          return res.status(400).json({ error: "Invalid ID" });

        const result = await clubsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status: "rejected", updatedAt: new Date() } }
        );

        if (result.matchedCount === 0)
          return res.status(404).json({ error: "Club not found" });
        res.json({ success: true });
      }
    );

    // Create Membership route updated to handle free vs paid
    app.post("/memberships", verifyFirebaseToken, async (req, res) => {
      const { userEmail, clubId } = req.body;
      if (!userEmail || !clubId)
        return res.status(400).json({ message: "Missing fields" });

      // 🔹 fetch club to check membership fee
      const club = await clubsCollection.findOne({ _id: new ObjectId(clubId) }); // 🔹 new
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

    // GET /memberships?managerEmail=...
    app.get("/memberships", verifyFirebaseToken, async (req, res) => {
      try {
        const { managerEmail } = req.query;
        if (!managerEmail) {
          return res.status(400).json({ message: "managerEmail required" });
        }

        // manager এর ক্লাবগুলো
        const clubs = await clubsCollection.find({ managerEmail }).toArray();
        const clubMap = {};
        clubs.forEach((c) => {
          clubMap[c._id.toString()] = c.clubName;
        });

        const clubIds = Object.keys(clubMap);

        const memberships = await membershipCollection
          .find({ clubId: { $in: clubIds } })
          .toArray();

        const result = memberships.map((m) => ({
          _id: m._id,
          userEmail: m.userEmail,
          clubId: m.clubId,
          clubName: clubMap[m.clubId],
          status: m.status,
          joinedAt: m.joinedAt,
        }));

        res.json(result); // ✅ always array
      } catch (err) {
        console.error(err);
        res.status(500).json([]);
      }
    });

    // Get all memberships (for admin summary card)
    app.get("/api/memberships", verifyFirebaseToken, async (req, res) => {
      try {
        const memberships = await membershipCollection.find({}).toArray();
        res.json(memberships);
      } catch (err) {
        console.error(err);
        res.status(500).json([]);
      }
    });

    // Confirm Membership after Payment Success
    app.patch(
      "/memberships/:id/confirm",
      verifyFirebaseToken,
      async (req, res) => {
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

    app.patch(
      "/api/users/role",
      verifyFirebaseToken, // verify token first
      verifyAdmin, // only admin can proceed
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

        // Admin cannot demote self
        if (email === req.requestedBy && newRole !== "admin") {
          return res
            .status(403)
            .json({ message: "Admin cannot demote himself" });
        }

        const result = await userCollection.updateOne(
          { email },
          { $set: { role: newRole, updatedAt: new Date() } }
        );

        if (result.modifiedCount === 0) {
          return res.status(404).json({ message: "User not found" });
        }

        res.json({ success: true, message: `Role updated to ${newRole}` });
      }
    );

    // payments data show
    app.get("/api/payments", verifyFirebaseToken, async (req, res) => {
      try {
        const db = client.db("clubnest");
        const membershipCollection = db.collection("memberships");
        const clubsCollection = db.collection("clubs");

        const memberships = await membershipCollection
          .find({ paymentId: { $ne: null } })
          .toArray();

        // যদি কিছু না থাকে, empty array return করবে
        if (!memberships) return res.json([]);

        const payments = await Promise.all(
          memberships.map(async (m) => {
            const club = await clubsCollection.findOne({
              _id: new ObjectId(m.clubId),
            });
            return {
              _id: m._id,
              userEmail: m.userEmail,
              clubName: club?.clubName || "Unknown Club",
              amount: club?.membershipFee || 0,
              date: m.updatedAt || m.joinedAt,
            };
          })
        );

        res.json(payments); // <-- **always array**
      } catch (err) {
        console.error(err);
        res.status(500).json([]); // <-- error হলে ও array
      }
    });

    // GET /api/member/summary?email=
    app.get("/api/member/summary", verifyFirebaseToken, async (req, res) => {
      const { email } = req.query;
      if (!email) return res.status(400).json({ message: "email required" });

      const clubsJoined = await membershipCollection.countDocuments({
        userEmail: email,
        status: "active",
      });

      res.json({
        clubsJoined,
        eventsRegistered: 0, // 🔹 events এখনো implement করো নাই
      });
    });

    // GET /api/member/clubs?email=
    app.get("/api/member/clubs", verifyFirebaseToken, async (req, res) => {
      const { email } = req.query;
      if (!email) return res.status(400).json({ message: "email required" });

      const memberships = await membershipCollection
        .find({ userEmail: email })
        .toArray();

      const clubs = await Promise.all(
        memberships.map(async (m) => {
          const club = await clubsCollection.findOne({
            _id: new ObjectId(m.clubId),
          });

          return {
            id: club?._id,
            name: club?.clubName,
            location: club?.location,
            membershipStatus: m.status,
            expiryDate: m.expiresAt || "N/A",
          };
        })
      );

      res.json(clubs);
    });

    // GET /api/member/payments?email=
    app.get("/api/member/payments", verifyFirebaseToken, async (req, res) => {
      const { email } = req.query;
      if (!email) return res.status(400).json({ message: "email required" });

      const memberships = await membershipCollection
        .find({ userEmail: email })
        .toArray();

      const payments = await Promise.all(
        memberships.map(async (m) => {
          const club = await clubsCollection.findOne({
            _id: new ObjectId(m.clubId),
          });

          return {
            amount: club?.membershipFee || 0,
            type: "Membership",
            club: club?.clubName || "Unknown",
            date: m.updatedAt || m.joinedAt,
            status: club?.membershipFee > 0 ? "Paid" : "Free", // paid বা free
          };
        })
      );

      res.json(payments); // সব membership return হবে
    });

    //  Manager Dashboard Summary
    app.get("/api/manager/summary", verifyFirebaseToken, async (req, res) => {
      try {
        const { email } = req.query;
        if (!email) {
          return res.status(400).json({ message: "manager email required" });
        }

        const db = client.db("clubnest");
        const clubsCollection = db.collection("clubs");
        const membershipCollection = db.collection("memberships");

        // 1️⃣ Manager Clubs
        const clubs = await clubsCollection
          .find({ managerEmail: email })
          .toArray();
        const clubIds = clubs.map((c) => c._id.toString());

        // 2️⃣ Members of manager clubs
        const membersCount = await membershipCollection.countDocuments({
          clubId: { $in: clubIds },
        });

        // 3️⃣ Payments (paid memberships only)
        const paymentsCount = await membershipCollection.countDocuments({
          clubId: { $in: clubIds },
          paymentId: { $ne: null },
        });

        res.json({
          totalClubs: clubs.length,
          totalMembers: membersCount,
          totalEvents: 0, // assignment allowed
          totalPayments: paymentsCount,
        });
      } catch (error) {
        console.error(error);
        res.status(500).json({
          totalClubs: 0,
          totalMembers: 0,
          totalEvents: 0,
          totalPayments: 0,
        });
      }
    });

    // 🔥 Admin: Memberships per Club (Chart Data)
    app.get(
      "/api/admin/memberships-per-club",
      verifyFirebaseToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const db = client.db("clubnest");
          const clubsCollection = db.collection("clubs");
          const membershipCollection = db.collection("memberships");

          const clubs = await clubsCollection.find({}).toArray();

          const data = await Promise.all(
            clubs.map(async (club) => {
              const totalMembers = await membershipCollection.countDocuments({
                clubId: club._id.toString(),
              });

              return {
                clubName: club.clubName,
                totalMembers,
              };
            })
          );

          res.json(data);
        } catch (error) {
          console.error("Memberships per club error:", error);
          res.status(500).json([]);
        }
      }
    );

    // Create Event (Manager Only)
    app.post("/events", verifyFirebaseToken, async (req, res) => {
      const {
        clubId,
        title,
        description,
        eventDate,
        location,
        isPaid,
        eventFee,
        maxAttendees,
      } = req.body;

      // Required fields check
      if (!clubId || !title || !eventDate) {
        return res.status(400).json({ message: "Required fields missing" });
      }

      // Find club
      const club = await clubsCollection.findOne({ _id: new ObjectId(clubId) });
      if (!club) return res.status(404).json({ message: "Club not found" });

      // Only club manager can create event
      if (club.managerEmail !== req.decodedUser.email) {
        return res.status(403).json({ message: "Forbidden" });
      }

      // Prepare new event object
      const newEvent = {
        clubId,
        title,
        description,
        eventDate: new Date(eventDate),
        location,
        isPaid: !!isPaid, // convert to boolean
        eventFee: Number(eventFee) || 0,
        maxAttendees: maxAttendees || null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      // Insert into DB
      const result = await eventsCollection.insertOne(newEvent);
      res.json({ success: true, eventId: result.insertedId });
    });

    //  Get Manager's Events
    app.get("/events/manager", verifyFirebaseToken, async (req, res) => {
      const managerEmail = req.decodedUser.email;

      // Get clubs managed by this user
      const clubs = await clubsCollection.find({ managerEmail }).toArray();
      const clubIds = clubs.map((c) => c._id.toString());

      // Get events for these clubs
      const events = await eventsCollection
        .find({ clubId: { $in: clubIds } })
        .toArray();

      // Add clubName and registeredUsers length for each event
      const detailedEvents = await Promise.all(
        events.map(async (ev) => {
          const club = clubs.find(
            (c) => c._id.toString() === ev.clubId.toString()
          );
          const registeredUsers = await eventRegistrationsCollection
            .find({ eventId: ev._id.toString(), status: "registered" })
            .toArray();
          return {
            ...ev,
            clubName: club?.clubName || "Unknown Club",
            registeredUsersCount: registeredUsers.length,
          };
        })
      );

      res.json(detailedEvents);
    });

    // Get All Events (Public)
    app.get("/events", async (req, res) => {
      const events = await eventsCollection
        .find({})
        .sort({ eventDate: 1 })
        .toArray();

      const detailedEvents = await Promise.all(
        events.map(async (ev) => {
          const club = await clubsCollection.findOne({
            _id: new ObjectId(ev.clubId),
          });
          return {
            ...ev,
            clubName: club?.clubName || "Unknown Club",
          };
        })
      );

      res.json(detailedEvents);
    });

    // Get Single Event
    app.get("/events/:id", async (req, res) => {
      const { id } = req.params;

      const event = await eventsCollection.findOne({ _id: new ObjectId(id) });
      if (!event) return res.status(404).json({ message: "Event not found" });

      const club = await clubsCollection.findOne({
        _id: new ObjectId(event.clubId),
      });

      // 🔹 রেজিস্টার্ড ইউজার কাউন্ট
      const registeredCount = await eventRegistrationsCollection.countDocuments(
        {
          eventId: id,
          status: "registered",
        }
      );

      res.json({
        ...event,
        clubName: club?.clubName || "Unknown Club",
        registeredCount, // ✅ নতুন ফিল্ড
      });
    });

    // Get Event Registration Details for Checkout
    app.get(
      "/event-registrations/:id",
      verifyFirebaseToken,
      async (req, res) => {
        const { id } = req.params;

        const registration = await eventRegistrationsCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!registration)
          return res.status(404).json({ message: "Registration not found" });

        const event = await eventsCollection.findOne({
          _id: new ObjectId(registration.eventId),
        });

        res.json({
          registrationId: registration._id,
          event,
          userEmail: registration.userEmail,
        });
      }
    );

    // Check event registration - UPDATED VERSION
    app.get(
      "/check-event-registration",
      verifyFirebaseToken,
      async (req, res) => {
        try {
          const { eventId } = req.query;
          const userEmail = req.decodedUser.email;

          console.log(
            "Checking registration for event:",
            eventId,
            "user:",
            userEmail
          );

          // ✅ Check for ANY registration (not just "registered" status)
          const registration = await eventRegistrationsCollection.findOne({
            eventId,
            userEmail,
          });

          console.log("Found registration:", registration);

          res.json({
            isRegistered: !!registration,
            registrationId: registration?._id,
            status: registration?.status || "not_registered",
            needsPayment: registration?.status === "pendingPayment",
          });
        } catch (error) {
          console.error("Check registration error:", error);
          res.status(500).json({
            isRegistered: false,
            status: "error",
          });
        }
      }
    );

    // Update event registration route to allow re-payment attempt
    app.post("/event-registrations", verifyFirebaseToken, async (req, res) => {
      try {
        const { eventId } = req.body;
        const userEmail = req.decodedUser.email;

        console.log(
          "Registration attempt for event:",
          eventId,
          "by:",
          userEmail
        );

        // 1. Validate event
        const event = await eventsCollection.findOne({
          _id: new ObjectId(eventId),
        });
        if (!event) {
          return res.status(404).json({ message: "Event not found" });
        }

        // 2. Check if event date passed
        if (new Date(event.eventDate) < new Date()) {
          return res.status(400).json({ message: "Event has already passed" });
        }

        // 3. Check max attendees
        if (event.maxAttendees) {
          const registeredCount =
            await eventRegistrationsCollection.countDocuments({
              eventId,
              status: "registered",
            });

          if (registeredCount >= event.maxAttendees) {
            return res.status(400).json({ message: "Event is full" });
          }
        }

        // 4. Check if already registered
        const existing = await eventRegistrationsCollection.findOne({
          eventId,
          userEmail,
        });

        // ✅ If already exists with pendingPayment, return that registration ID
        if (existing) {
          if (existing.status === "pendingPayment") {
            return res.json({
              success: true,
              registrationId: existing._id,
              status: existing.status,
              message: "Continue with payment",
              existing: true,
            });
          } else if (existing.status === "registered") {
            return res.status(400).json({
              message: "Already registered",
              registrationId: existing._id,
            });
          }
        }

        // 5. Get club info
        const club = await clubsCollection.findOne({
          _id: new ObjectId(event.clubId),
        });

        // 6. Create NEW registration
        const registration = {
          eventId,
          clubId: event.clubId,
          userEmail,
          clubName: club?.clubName,
          eventTitle: event.title,
          eventFee: event.eventFee,
          status: event.isPaid ? "pendingPayment" : "registered",
          paymentId: null,
          registeredAt: new Date(),
          updatedAt: new Date(),
        };

        const result = await eventRegistrationsCollection.insertOne(
          registration
        );

        res.json({
          success: true,
          registrationId: result.insertedId,
          status: registration.status,
          requiresPayment: event.isPaid,
          message: event.isPaid
            ? "Please complete payment to confirm registration"
            : "Successfully registered for event",
          existing: false,
        });
      } catch (err) {
        console.error("Registration error:", err);
        res.status(500).json({
          success: false,
          message: "Server error: " + err.message,
        });
      }
    });

    // Update Event (Manager Only)
    app.patch("/events/:id", verifyFirebaseToken, async (req, res) => {
      const { id } = req.params;
      const updates = req.body;

      const event = await eventsCollection.findOne({ _id: new ObjectId(id) });
      if (!event) return res.status(404).json({ message: "Event not found" });

      // Only manager of the club can update
      const club = await clubsCollection.findOne({
        _id: new ObjectId(event.clubId),
      });
      if (club.managerEmail !== req.decodedUser.email) {
        return res.status(403).json({ message: "Forbidden" });
      }

      updates.updatedAt = new Date();
      await eventsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updates }
      );

      res.json({ success: true, message: "Event updated" });
    });

    // Delete Event (Manager Only)
    app.delete("/events/:id", verifyFirebaseToken, async (req, res) => {
      const { id } = req.params;

      const event = await eventsCollection.findOne({ _id: new ObjectId(id) });
      if (!event) return res.status(404).json({ message: "Event not found" });

      // Only manager of the club can delete
      const club = await clubsCollection.findOne({
        _id: new ObjectId(event.clubId),
      });
      if (club.managerEmail !== req.decodedUser.email) {
        return res.status(403).json({ message: "Forbidden" });
      }

      await eventsCollection.deleteOne({ _id: new ObjectId(id) });
      res.json({ success: true, message: "Event deleted" });
    });

    // Register for Event (Member)
    // app.post("/event-registrations", verifyFirebaseToken, async (req, res) => {
    //   const { eventId } = req.body;
    //   const userEmail = req.decodedUser.email;

    //   const event = await eventsCollection.findOne({
    //     _id: new ObjectId(eventId),
    //   });
    //   if (!event) return res.status(404).json({ message: "Event not found" });

    //   // Check if already registered
    //   const alreadyRegistered = await eventRegistrationsCollection.findOne({
    //     eventId,
    //     userEmail,
    //   });
    //   if (alreadyRegistered)
    //     return res.status(400).json({ message: "Already registered" });

    //   // Prepare registration
    //   const registration = {
    //     eventId,
    //     clubId: event.clubId,
    //     userEmail,
    //     status: event.isPaid ? "pendingPayment" : "registered",
    //     paymentId: null,
    //     registeredAt: new Date(),
    //   };

    //   const result = await eventRegistrationsCollection.insertOne(registration);
    //   res.json({
    //     success: true,
    //     registrationId: result.insertedId,
    //     status: registration.status,
    //   });
    // });

    // Create Payment Intent (Stripe) for Paid Event
    app.post(
      "/create-event-payment-intent",
      verifyFirebaseToken,
      async (req, res) => {
        const { eventId } = req.body;

        const event = await eventsCollection.findOne({
          _id: new ObjectId(eventId),
        });
        if (!event) return res.status(404).json({ message: "Event not found" });
        if (!event.isPaid)
          return res.status(400).json({ message: "Event is free" });

        const paymentIntent = await stripe.paymentIntents.create({
          amount: Math.round(event.eventFee * 100), // convert to cents
          currency: "usd", // currency
          metadata: { eventId, userEmail: req.decodedUser.email },
        });

        res.json({ clientSecret: paymentIntent.client_secret });
      }
    );

    // Confirm Event Registration After Payment
    app.patch(
      "/event-registrations/:id/confirm",
      verifyFirebaseToken,
      async (req, res) => {
        const { id } = req.params;
        const { paymentId } = req.body;

        const registration = await eventRegistrationsCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!registration)
          return res.status(404).json({ message: "Registration not found" });

        await eventRegistrationsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status: "registered", paymentId, updatedAt: new Date() } }
        );

        res.json({ success: true, message: "Event registration confirmed" });
      }
    );

    // Get User's Event Registrations (Member Dashboard)
    app.get(
      "/api/member/event-registrations",
      verifyFirebaseToken,
      async (req, res) => {
        const userEmail = req.decodedUser.email;

        const registrations = await eventRegistrationsCollection
          .find({ userEmail })
          .toArray();

        // Populate event details
        const detailed = await Promise.all(
          registrations.map(async (r) => {
            const event = await eventsCollection.findOne({
              _id: new ObjectId(r.eventId),
            });
            return {
              ...r,
              eventTitle: event?.title,
              eventDate: event?.eventDate,
              clubId: event?.clubId,
            };
          })
        );

        res.json(detailed);
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
