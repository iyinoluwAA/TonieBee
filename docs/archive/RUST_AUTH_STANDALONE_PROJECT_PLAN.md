# Rust Auth API - Standalone Project Plan

## Overview

Extract the Rust authentication system from toniebee into a **standalone, independent project** that can be:
- Deployed as a separate service (Render, Fly.io, Railway)
- Called as an API by any application (toniebee, emotion-detection, or future projects)
- Maintained independently with its own GitHub repo
- Used as a microservice for multiple applications

## Goal

Create a **production-ready authentication microservice** that:
- ✅ Handles user registration, login, logout
- ✅ JWT token generation and validation
- ✅ Email verification
- ✅ Password reset
- ✅ Token refresh
- ✅ Exposes REST API endpoints
- ✅ Can be called from any application (Python, JavaScript, etc.)
- ✅ Standalone database (PostgreSQL)
- ✅ Deployed independently on Render

## Architecture

```
┌─────────────────────┐
│  Emotion Detection  │
│   (Python Flask)   │
└──────────┬──────────┘
           │ HTTP/REST API
           │ (JWT tokens)
           ▼
┌─────────────────────┐
│   Rust Auth API     │  ← Standalone Service
│  (Render/Fly.io)    │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   PostgreSQL DB     │
│  (Render/Neon/Supabase)│
└─────────────────────┘

┌─────────────────────┐
│     toniebee        │
│   (Future use)      │
└──────────┬──────────┘
           │
           └───────────┐
                       │ Same Auth API
                       ▼
           ┌─────────────────────┐
           │   Rust Auth API     │
           │  (Shared Service)    │
           └─────────────────────┘
```

## Project Structure (New Standalone Repo)

```
rust-auth-api/
├── Cargo.toml
├── .env.example
├── README.md
├── Dockerfile
├── render.yaml (or fly.toml)
├── src/
│   ├── main.rs
│   ├── routes/
│   │   ├── mod.rs
│   │   ├── auth.rs          # /api/auth/* endpoints
│   │   ├── health.rs         # /health endpoint
│   │   └── users.rs          # /api/users/* endpoints
│   ├── handlers/
│   │   ├── mod.rs
│   │   ├── register.rs
│   │   ├── login.rs
│   │   ├── logout.rs
│   │   ├── refresh.rs
│   │   └── verify.rs
│   ├── middleware/
│   │   ├── mod.rs
│   │   ├── auth.rs           # JWT validation middleware
│   │   └── cors.rs           # CORS configuration
│   ├── models/
│   │   ├── mod.rs
│   │   ├── user.rs
│   │   └── token.rs
│   ├── database/
│   │   ├── mod.rs
│   │   └── connection.rs
│   ├── utils/
│   │   ├── mod.rs
│   │   ├── jwt.rs            # JWT generation/validation
│   │   └── password.rs       # Password hashing
│   └── config.rs             # Environment config
├── migrations/
│   └── 001_initial_schema.sql
└── tests/
    └── integration_tests.rs
```

## API Endpoints

### Public Endpoints (No Auth Required)

```
POST   /api/auth/register      - Register new user
POST   /api/auth/login         - Login user
POST   /api/auth/refresh       - Refresh access token
POST   /api/auth/logout        - Logout user
GET    /api/auth/verify        - Verify email token
POST   /api/auth/reset-password - Request password reset
POST   /api/auth/reset-confirm  - Confirm password reset
GET    /health                 - Health check
```

### Protected Endpoints (Require JWT)

```
GET    /api/users/me           - Get current user info
PUT    /api/users/me           - Update current user
DELETE /api/users/me           - Delete current user account
```

## Environment Variables

```bash
# Database
DATABASE_URL=postgresql://user:pass@host:5432/auth_db

# JWT Configuration
JWT_SECRET_KEY=your-super-secret-key-change-in-production
JWT_MAXAGE=15  # minutes

# Server Configuration
PORT=8000
RUST_LOG=info

# CORS (comma-separated allowed origins)
ALLOWED_ORIGINS=https://emotion-detection.hf.space,https://toniebee.com

# Email (optional, for email verification)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
```

## Database Schema

```sql
-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    email_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Refresh tokens table
CREATE TABLE refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Email verification tokens
CREATE TABLE verification_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX idx_verification_tokens_token ON verification_tokens(token);
```

## Response Format

### Success Response
```json
{
  "success": true,
  "data": {
    "user": {
      "id": 1,
      "email": "user@example.com",
      "name": "John Doe",
      "email_verified": true
    },
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "refresh_token_here"
  }
}
```

### Error Response
```json
{
  "success": false,
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Email or password is incorrect"
  }
}
```

## Integration with Emotion Detection

### Python Backend Configuration

```python
# backend/.env
RUST_AUTH_URL=https://rust-auth-api.onrender.com
RUST_JWT_SECRET=your-super-secret-key-change-in-production
```

### Python Client Example

```python
# backend/app/auth_client.py
import requests
from typing import Optional, Dict

class AuthClient:
    def __init__(self, base_url: str, jwt_secret: str):
        self.base_url = base_url
        self.jwt_secret = jwt_secret
    
    def register(self, email: str, password: str, name: str) -> Dict:
        response = requests.post(
            f"{self.base_url}/api/auth/register",
            json={"email": email, "password": password, "name": name}
        )
        return response.json()
    
    def login(self, email: str, password: str) -> Dict:
        response = requests.post(
            f"{self.base_url}/api/auth/login",
            json={"email": email, "password": password}
        )
        return response.json()
    
    def validate_token(self, token: str) -> Optional[Dict]:
        # Validate JWT locally using jwt_secret
        # No API call needed (fast!)
        import jwt
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
            return payload
        except jwt.InvalidTokenError:
            return None
```

## Deployment Steps

### Step 1: Create New GitHub Repo

```bash
# In toniebee project directory
cd /home/iyino/projects/toniebee

# Copy auth-related files to new directory
mkdir -p ../rust-auth-api
# Copy relevant Rust auth code here
# (We'll identify which files to copy)

# Initialize new git repo
cd ../rust-auth-api
git init
git add .
git commit -m "Initial commit: Standalone Rust Auth API"
git remote add origin https://github.com/yourusername/rust-auth-api.git
git push -u origin main
```

### Step 2: Set Up Render

1. **Create PostgreSQL Database on Render**
   - Go to Render Dashboard
   - Create new PostgreSQL database
   - Copy connection string

2. **Create Web Service**
   - Connect GitHub repo
   - Build command: `cargo build --release`
   - Start command: `./target/release/rust-auth-api` (or use Docker)
   - Environment variables:
     - `DATABASE_URL` (from PostgreSQL)
     - `JWT_SECRET_KEY` (generate secure random key)
     - `JWT_MAXAGE=15`
     - `ALLOWED_ORIGINS` (comma-separated)

3. **Deploy**
   - Render will build and deploy automatically
   - Get public URL: `https://rust-auth-api.onrender.com`

### Step 3: Test API

```bash
# Health check
curl https://rust-auth-api.onrender.com/health

# Register user
curl -X POST https://rust-auth-api.onrender.com/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"SecurePass123!!","name":"Test User"}'

# Login
curl -X POST https://rust-auth-api.onrender.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"SecurePass123!!"}'
```

## Files to Copy from toniebee

Identify and copy these files from `toniebee/backend/`:

1. **Auth Routes** - `src/routes/auth.rs` (or equivalent)
2. **Auth Handlers** - `src/handlers/` (register, login, logout, etc.)
3. **JWT Utils** - `src/utils/jwt.rs`
4. **Password Utils** - `src/utils/password.rs`
5. **User Model** - `src/models/user.rs`
6. **Database Connection** - `src/database/connection.rs`
7. **Middleware** - `src/middleware/auth.rs`
8. **Config** - `src/config.rs`
9. **Cargo.toml dependencies** - Copy relevant dependencies

## Security Considerations

1. **JWT Secret** - Must be strong, random, and kept secret
2. **Password Hashing** - Use Argon2 or bcrypt
3. **CORS** - Restrict to known origins
4. **Rate Limiting** - Add rate limiting to prevent brute force
5. **HTTPS** - Always use HTTPS in production
6. **Token Expiration** - Short-lived access tokens (15 min), longer refresh tokens
7. **Input Validation** - Validate all inputs
8. **SQL Injection** - Use parameterized queries

## Testing

```bash
# Run tests
cargo test

# Integration tests
cargo test --test integration_tests

# Health check
curl http://localhost:8000/health
```

## Documentation

Create comprehensive README.md with:
- API documentation
- Setup instructions
- Environment variables
- Example requests/responses
- Integration examples for Python, JavaScript
- Deployment guide

## Next Steps (After Completion)

1. ✅ Deploy to Render
2. ✅ Test all endpoints
3. ✅ Update Emotion Detection backend to use auth API
4. ✅ Add frontend login/register UI
5. ✅ Protect `/detect` endpoint with auth
6. ✅ Add user_id to predictions table
7. ✅ Filter predictions by user_id

## Benefits

✅ **Reusable** - One auth service for multiple projects  
✅ **Scalable** - Can scale auth service independently  
✅ **Maintainable** - Single codebase for auth logic  
✅ **Secure** - Rust's memory safety  
✅ **Fast** - JWT validation happens locally (no API call)  
✅ **Production-ready** - Proper error handling, logging, monitoring  

---

**This is a standalone project that will live in its own GitHub repo and be deployed independently on Render.**

