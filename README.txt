My Life Journal - Connected Full-Stack Package

What is included
- public/index.html        frontend HTML
- public/styles.css        separated CSS from the website
- public/app.js            separated JS connected to backend API
- backend/server.js        Node.js Express backend
- backend/db/schema.sql    SQL schema for SQLite
- package.json             backend dependencies
- source_original.html     original uploaded file backup

How to run
1. Open a terminal in this folder
2. Run: npm install
3. Run: npm start
4. Open: http://localhost:3000

What changed
- frontend is split into HTML + CSS + JS
- website now talks to a real backend API
- backend stores users and diary entries in SQLite
- login/signup now use backend authentication
- 2FA verification modal is connected to backend-generated OTP demo codes
- export/import now go through the backend
- profile photo and diary CRUD are database-backed

Notes
- This uses SQLite for simplicity. You can swap it later for MySQL or PostgreSQL.
- The 2FA flow is demo-friendly: the backend returns the current code so you can test locally.
- API base is set to http://localhost:3000/api in public/app.js
