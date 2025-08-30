const express = require("express");
const sql = require("mssql");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { BlobServiceClient } = require("@azure/storage-blob");

const app = express();
app.use(express.json());

// ENV VARIABLES
const sqlConfig = {
  user: process.env.SQL_USER,
  password: process.env.SQL_PASSWORD,
  database: process.env.SQL_DB,
  server: process.env.SQL_SERVER,
  options: {
    encrypt: true,
    trustServerCertificate: false
  }
};

const AZURE_STORAGE_CONNECTION = process.env.AZURE_STORAGE_CONNECTION;
const CONTAINER_NAME = process.env.CONTAINER_NAME || "videos";
const JWT_SECRET = "supersecretkey"; // change to stronger secret

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
    const hashed = await bcrypt.hash(password, 10);
    await pool.request()
      .input("Name", sql.NVarChar, name)
      .input("Email", sql.NVarChar, email)
      .input("PasswordHash", sql.NVarChar, hashed)
      .input("Role", sql.NVarChar, "Consumer")
      .query("INSERT INTO Users (Name, Email, PasswordHash, Role) VALUES (@Name, @Email, @PasswordHash, @Role)");
    res.json({ message: "Consumer registered successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login (Consumers + Creators)
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const pool = await getPool();
    const result = await pool.request()
      .input("Email", sql.NVarChar, email)
      .query("SELECT * FROM Users WHERE Email=@Email");

    if (result.recordset.length === 0) return res.status(400).json({ error: "User not found" });

    const user = result.recordset[0];
    const valid = await bcrypt.compare(password, user.PasswordHash);
    if (!valid) return res.status(400).json({ error: "Invalid password" });

    const token = jwt.sign({ id: user.UserID, role: user.Role }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ token, role: user.Role });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Middleware to protect routes
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

// Upload Video (Creators only)
app.post("/upload", auth("Creator"), async (req, res) => {
  const { title, publisher, producer, genre, ageRating, fileName, fileContent } = req.body;
  try {
    // Upload to Blob
    const blobServiceClient = BlobServiceClient.fromConnectionString(AZURE_STORAGE_CONNECTION);
    const containerClient = blobServiceClient.getContainerClient(CONTAINER_NAME);
    const blockBlobClient = containerClient.getBlockBlobClient(fileName);
    const buffer = Buffer.from(fileContent, "base64"); // frontend sends base64
    await blockBlobClient.uploadData(buffer);

    const blobUrl = blockBlobClient.url;

    // Save metadata in DB
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
    res.status(500).json({ error: err.message });
  }
});

// Get all videos
app.get("/getVideos", async (req, res) => {
  try {
    const pool = await getPool();
    const result = await pool.request().query("SELECT * FROM Videos ORDER BY UploadedAt DESC");
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Comment on a video
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
    res.status(500).json({ error: err.message });
  }
});

// Rate a video
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
    res.status(500).json({ error: err.message });
  }
});

// ---------- START SERVER ---------- //
const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`EchoVid API running on port ${port}`));
