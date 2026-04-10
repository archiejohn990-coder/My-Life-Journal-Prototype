const express = require("express");
const cors = require("cors");
const fs = require("fs");

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

const USERS_FILE = "users.json";

// read users
function readUsers() {
  if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, "[]");
  }
  return JSON.parse(fs.readFileSync(USERS_FILE));
}

// write users
function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// TEST
app.get("/", (req, res) => {
  res.send("Server is working!");
});

// REGISTER
app.post("/api/register", (req, res) => {
  const { email, password } = req.body;

  let users = readUsers();

  if (users.find(u => u.email === email)) {
    return res.json({ success: false, error: "User already exists" });
  }

  users.push({ email, password });
  writeUsers(users);

  res.json({ success: true });
});

// LOGIN
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  let users = readUsers();

  const user = users.find(u => u.email === email && u.password === password);

  if (!user) {
    return res.json({ success: false });
  }

  res.json({ success: true, user });
});

// START SERVER
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});