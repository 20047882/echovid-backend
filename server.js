const express = require("express");
const sql = require("mssql");
const jwt = require("jsonwebtoken");
const { BlobServiceClient } = require("@azure/storage-blob");
const cors = require("cors");

const app = express();

// ✅ Allow localhost (dev) and any domain (prod). Adjust later if needed
app.use(
  cors({
    origin: ["http://localhost:3000", "*"],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// ✅ Increase request size limit (fix 413 error)
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

// ENV VARIABLES
const sqlConfig = {
  user: process.env.SQL_USER,
  password: process.env.SQL_PASSWORD,
  database: process.env.SQL_DB,
  server: process.env.SQL_SERVER,
  options: {
    encrypt: true,
    trustServerCertificate: false,
  },
};

const AZURE_STORAGE_CONNECTION = process.env.AZURE_STORAGE_CONNECTION;
const CONTAINER_NAME = process.env.CONTAINER_NAME || "videos";
const JWT_SECRET = "supersecretkey";

// SQL Connection Pool
let pool;
async function getPool() {
  if (!pool) {
    pool = await sql.connect(sqlConfig);
  }
  return pool;
}

// ---------- ROUTES ---------- //

// Signup (Consumers only)
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const pool = await getPool();

    const result = await pool
      .request()
      .input("Email", sql.NVarChar, email.toLowerCase())
      .query(
        "SELECT * FROM Users WHERE Email COLLATE Latin1_General_CI_AS = @Email"
      );

    if (result.recordset.length > 0) {
      return res.status(400).json({ error: "Email already registered" });
    }

    await pool
      .request()
      .input("Name", sql.NVarChar, name)
      .input("Email", sql.NVarChar, email.toLowerCase())
      .input("PasswordHash", sql.NVarChar, password)
      .input("Role", sql.NVarChar, "Consumer")
      .query(
        "INSERT INTO Users (Name, Email, PasswordHash, Role, CreatedAt) VALUES (@Name, @Email, @PasswordHash, @Role, GETDATE())"
      );

    res.json({ message: "Consumer registered successfully" });
  } catch (err) {
    console.error("❌ Signup error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const pool = await getPool();

    const result = await pool
      .request()
      .input("Email", sql.NVarChar, email.trim().toLowerCase())
      .input("PasswordHash", sql.NVarChar, password.trim())
      .query(
        "SELECT * FROM Users WHERE Email COLLATE Latin1_General_CI_AS = @Email AND PasswordHash = @PasswordHash"
      );

    if (result.recordset.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = result.recordset[0];
    const token = jwt.sign(
      { id: user.UserID, role: user.Role },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ token, role: user.Role });
  } catch (err) {
    console.error("❌ Login error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Middleware
function auth(requiredRole) {
  return (req, res, next) => {
    const header = req.headers["authorization"];
    if (!header) return res.status(401).json({ error: "No token" });
    try {
      const token = header.split(" ")[1];
      const decoded = jwt.verify(token, JWT_SECRET);
      if (requiredRole && decoded.role !== requiredRole) {
        return res.status(403).json({ error: "Forbidden" });
      }
      req.user = decoded;
      next();
    } catch (err) {
      res.status(401).json({ error: "Invalid token" });
    }
  };
}

// Upload Video
app.post("/upload", auth("Creator"), async (req, res) => {
  const { title, publisher, producer, genre, ageRating, fileName, fileContent } = req.body;
  try {
    const blobServiceClient = BlobServiceClient.fromConnectionString(AZURE_STORAGE_CONNECTION);
    const containerClient = blobServiceClient.getContainerClient(CONTAINER_NAME);
    const blockBlobClient = containerClient.getBlockBlobClient(fileName);
    const buffer = Buffer.from(fileContent, "base64");
    await blockBlobClient.uploadData(buffer);

    const blobUrl = blockBlobClient.url;

    const pool = await getPool();
    await pool.request()
      .input("Title", sql.NVarChar, title)
      .input("Publisher", sql.NVarChar, publisher)
      .input("Producer", sql.NVarChar, producer)
      .input("Genre", sql.NVarChar, genre)
      .input("AgeRating", sql.NVarChar, ageRating)
      .input("BlobURL", sql.NVarChar, blobUrl)
      .input("CreatorID", sql.Int, req.user.id)
      .query(`INSERT INTO Videos (Title, Publisher, Producer, Genre, AgeRating, BlobURL, CreatorID)
              VALUES (@Title, @Publisher, @Producer, @Genre, @AgeRating, @BlobURL, @CreatorID)`);

    res.json({ message: "Video uploaded successfully", url: blobUrl });
  } catch (err) {
    console.error("❌ Upload error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Get Videos
app.get("/getVideos", async (req, res) => {
  try {
    const pool = await getPool();
    const result = await pool.request().query("SELECT * FROM Videos ORDER BY UploadedAt DESC");
    res.json(result.recordset);
  } catch (err) {
    console.error("❌ Fetch videos error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Comment
app.post("/comment", auth(), async (req, res) => {
  const { videoId, comment } = req.body;
  try {
    const pool = await getPool();
    await pool.request()
      .input("VideoID", sql.Int, videoId)
      .input("UserID", sql.Int, req.user.id)
      .input("CommentText", sql.NVarChar, comment)
      .query("INSERT INTO Comments (VideoID, UserID, CommentText) VALUES (@VideoID, @UserID, @CommentText)");
    res.json({ message: "Comment added" });
  } catch (err) {
    console.error("❌ Comment error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Rate
app.post("/rate", auth(), async (req, res) => {
  const { videoId, rating } = req.body;
  try {
    const pool = await getPool();
    await pool.request()
      .input("VideoID", sql.Int, videoId)
      .input("UserID", sql.Int, req.user.id)
      .input("Rating", sql.Int, rating)
      .query("INSERT INTO Ratings (VideoID, UserID, Rating) VALUES (@VideoID, @UserID, @Rating)");
    res.json({ message: "Rating submitted" });
  } catch (err) {
    console.error("❌ Rating error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Start server
const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`EchoVid API running on port ${port}`));
