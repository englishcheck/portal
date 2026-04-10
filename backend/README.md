English Check Backend

This provides:
- User registration with hashed passwords (bcrypt)
- User login with JWT tokens
- User progress storage per module
- SQLite database persisted at backend/data/english-check.db

How to Setup
1. Open terminal in backend folder.
2. Run: npm install
3. Copy `.env.example` to `.env`
4. Set `JWT_SECRET` in `.env` with a long random value
5. Run: npm start
6. Backend will run on http://localhost:3000

Endpoints
- GET /api/health
- POST /api/register
  Body:
  {
    "name": "User Name",
    "email": "user@email.com",
    "password": "secret123",
    "whatsapp": "62123456789",
    "instagram": "@username",
    "institution": "Campus",
    "major": "Major",
    "academicStatus": "Mahasiswa angkatan 2026"
  }

- POST /api/login
  Body:
  {
    "email": "user@email.com",
    "password": "secret123"
  }

- GET /api/progress
  Header:
  Authorization: Bearer <token>

- POST /api/progress
  Header:
  Authorization: Bearer <token>
  Body:
  {
    "moduleKey": "simple-present-tense",
    "score": 90,
    "completed": true
  }

Notes
- Passwords are never stored as plain text.
- Hashing uses bcrypt with 12 salt rounds.
- Server requires JWT_SECRET from environment variables.
