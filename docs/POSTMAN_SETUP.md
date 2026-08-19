# Postman Setup Guide for Authentication API

## 🎯 Overview

This guide helps you set up Postman to test all authentication endpoints with proper CSRF token handling, authentication, and test scripts.

---

## 📥 Step 1: Import Collection

### Option A: Create Collection Manually

1. Open Postman
2. Click **"New"** → **"Collection"**
3. Name it: **"Toniebee Auth API"**

### Option B: Import from JSON (if we create one later)

1. Click **"Import"** button
2. Select JSON file (we'll create this)
3. Collection imported with all endpoints

---

## 🔧 Step 2: Set Up Environment

### Create Environment

1. Click **"Environments"** (left sidebar)
2. Click **"+"** to create new
3. Name: **"Toniebee Local"**

### Add Variables

Add these variables to your environment:

| Variable | Initial Value | Current Value | Type |
|----------|---------------|---------------|------|
| `base_url` | `http://localhost:8000/api` | `http://localhost:8000/api` | default |
| `frontend_url` | `http://localhost:5173` | `http://localhost:5173` | default |
| `csrf_token` | (empty) | (auto-set) | secret |
| `access_token` | (empty) | (auto-set) | secret |
| `refresh_token` | (empty) | (auto-set) | secret |
| `user_id` | (empty) | (auto-set) | default |
| `user_email` | `test@example.com` | `test@example.com` | default |
| `admin_email` | `admin@example.com` | `admin@example.com` | default |

**Note:** `csrf_token`, `access_token`, `refresh_token` will be auto-populated by scripts.

---

## 📝 Step 3: Create Pre-request Script for CSRF

### For Collection Level (Applies to All Requests)

1. Click on your collection
2. Go to **"Pre-request Script"** tab
3. Add this script:

```javascript
// Get CSRF token from cookies (if available)
const cookies = pm.cookies.all();
const csrfCookie = cookies.find(cookie => cookie.name === 'csrf_token');

if (csrfCookie) {
    pm.environment.set("csrf_token", csrfCookie.value);
}

// If no CSRF token, make a request to get one
if (!pm.environment.get("csrf_token")) {
    pm.sendRequest({
        url: pm.environment.get("base_url") + "/auth/login",
        method: "GET",
    }, function (err, res) {
        if (res && res.cookies) {
            const csrf = res.cookies.get("csrf_token");
            if (csrf) {
                pm.environment.set("csrf_token", csrf.value);
            }
        }
    });
}
```

### For Individual Requests (Alternative)

Add this to each POST/PUT/DELETE request's **Pre-request Script**:

```javascript
// Get CSRF token from environment or cookies
const csrfToken = pm.environment.get("csrf_token") || pm.cookies.get("csrf_token");

if (csrfToken) {
    pm.request.headers.add({
        key: "X-CSRF-Token",
        value: csrfToken
    });
}
```

---

## 🔐 Step 4: Create Auth Endpoints

### 4.1 Register User

**Request:**
- Method: `POST`
- URL: `{{base_url}}/auth/register`
- Headers:
  ```
  Content-Type: application/json
  ```
- Body (raw JSON):
```json
{
  "name": "Test User",
  "email": "{{user_email}}",
  "password": "TestPassword123!",
  "confirmPassword": "TestPassword123!"
}
```

**Tests Script:**
```javascript
pm.test("Status code is 200 or 201", function () {
    pm.response.to.have.status(200);
});

pm.test("Response has user data", function () {
    const jsonData = pm.response.json();
    pm.expect(jsonData).to.have.property('data');
});
```

---

### 4.2 Login

**Request:**
- Method: `POST`
- URL: `{{base_url}}/auth/login`
- Headers:
  ```
  Content-Type: application/json
  ```
- Body (raw JSON):
```json
{
  "email": "{{user_email}}",
  "password": "TestPassword123!"
}
```

**Tests Script:**
```javascript
pm.test("Status code is 200", function () {
    pm.response.to.have.status(200);
});

pm.test("Response has tokens", function () {
    const jsonData = pm.response.json();
    if (jsonData.data && jsonData.data.token) {
        pm.environment.set("access_token", jsonData.data.token);
    }
    if (jsonData.data && jsonData.data.refreshToken) {
        pm.environment.set("refresh_token", jsonData.data.refreshToken);
    }
});

// Extract CSRF token from cookies
const cookies = pm.cookies.all();
const csrfCookie = cookies.find(cookie => cookie.name === 'csrf_token');
if (csrfCookie) {
    pm.environment.set("csrf_token", csrfCookie.value);
}
```

---

### 4.3 Get CSRF Token (Alternative Method)

**Request:**
- Method: `GET`
- URL: `{{base_url}}/auth/login`
- Headers: (none needed)

**Tests Script:**
```javascript
// Extract CSRF token from Set-Cookie header
const cookies = pm.response.headers.get("Set-Cookie");
if (cookies) {
    const csrfMatch = cookies.match(/csrf_token=([^;]+)/);
    if (csrfMatch) {
        pm.environment.set("csrf_token", csrfMatch[1]);
    }
}
```

---

### 4.4 Verify Email

**Request:**
- Method: `GET`
- URL: `{{base_url}}/auth/verify?token=YOUR_VERIFICATION_TOKEN`
- Headers: (none needed)

**Note:** Get token from email (MailHog or real email)

---

### 4.5 Forgot Password

**Request:**
- Method: `POST`
- URL: `{{base_url}}/auth/forgot-password`
- Headers:
  ```
  Content-Type: application/json
  X-CSRF-Token: {{csrf_token}}
  ```
- Body (raw JSON):
```json
{
  "email": "{{user_email}}"
}
```

---

### 4.6 Reset Password

**Request:**
- Method: `POST`
- URL: `{{base_url}}/auth/reset-password`
- Headers:
  ```
  Content-Type: application/json
  X-CSRF-Token: {{csrf_token}}
  ```
- Body (raw JSON):
```json
{
  "token": "YOUR_RESET_TOKEN",
  "password": "NewPassword123!",
  "confirmPassword": "NewPassword123!"
}
```

---

### 4.7 Logout

**Request:**
- Method: `POST`
- URL: `{{base_url}}/auth/logout`
- Headers:
  ```
  Content-Type: application/json
  X-CSRF-Token: {{csrf_token}}
  Authorization: Bearer {{access_token}}
  ```

**Tests Script:**
```javascript
pm.test("Status code is 200", function () {
    pm.response.to.have.status(200);
});

// Clear tokens after logout
pm.environment.set("access_token", "");
pm.environment.set("refresh_token", "");
pm.environment.set("csrf_token", "");
```

---

## 🔒 Step 5: 2FA Endpoints

### 5.1 Setup 2FA

**Request:**
- Method: `POST`
- URL: `{{base_url}}/2fa/setup`
- Headers:
  ```
  Content-Type: application/json
  X-CSRF-Token: {{csrf_token}}
  Authorization: Bearer {{access_token}}
  ```
- Body (raw JSON):
```json
{}
```

**Tests Script:**
```javascript
pm.test("Status code is 200", function () {
    pm.response.to.have.status(200);
});

pm.test("Response has QR code", function () {
    const jsonData = pm.response.json();
    pm.expect(jsonData).to.have.property('data');
    pm.expect(jsonData.data).to.have.property('qr_code_url');
    pm.expect(jsonData.data).to.have.property('secret');
});
```

---

### 5.2 Verify 2FA Setup

**Request:**
- Method: `POST`
- URL: `{{base_url}}/2fa/verify`
- Headers:
  ```
  Content-Type: application/json
  X-CSRF-Token: {{csrf_token}}
  Authorization: Bearer {{access_token}}
  ```
- Body (raw JSON):
```json
{
  "code": "123456"
}
```

**Note:** Get code from authenticator app

---

### 5.3 Verify 2FA Login

**Request:**
- Method: `POST`
- URL: `{{base_url}}/auth/verify-login`
- Headers:
  ```
  Content-Type: application/json
  X-CSRF-Token: {{csrf_token}}
  ```
- Body (raw JSON):
```json
{
  "email": "{{user_email}}",
  "code": "123456"
}
```

---

### 5.4 Get Recovery Codes Status

**Request:**
- Method: `GET`
- URL: `{{base_url}}/2fa/recovery-codes`
- Headers:
  ```
  Authorization: Bearer {{access_token}}
  ```

---

### 5.5 Regenerate Recovery Codes

**Request:**
- Method: `POST`
- URL: `{{base_url}}/2fa/recovery-codes/regenerate`
- Headers:
  ```
  Content-Type: application/json
  X-CSRF-Token: {{csrf_token}}
  Authorization: Bearer {{access_token}}
  ```
- Body (raw JSON):
```json
{}
```

---

## 👤 Step 6: User Endpoints

### 6.1 Get Current User

**Request:**
- Method: `GET`
- URL: `{{base_url}}/users/me`
- Headers:
  ```
  Authorization: Bearer {{access_token}}
  ```

---

### 6.2 Get All Users (Admin)

**Request:**
- Method: `GET`
- URL: `{{base_url}}/users/users`
- Headers:
  ```
  Authorization: Bearer {{access_token}}
  ```

---

## 🔄 Step 7: Refresh Token

### Refresh Access Token

**Request:**
- Method: `POST`
- URL: `{{base_url}}/auth/refresh`
- Headers:
  ```
  Content-Type: application/json
  ```
- Body (raw JSON):
```json
{
  "refreshToken": "{{refresh_token}}"
}
```

**Tests Script:**
```javascript
pm.test("Status code is 200", function () {
    pm.response.to.have.status(200);
});

pm.test("New access token received", function () {
    const jsonData = pm.response.json();
    if (jsonData.data && jsonData.data.token) {
        pm.environment.set("access_token", jsonData.data.token);
    }
});
```

---

## 🧪 Step 8: Test Scripts

### Global Test Script (Collection Level)

Add to collection's **Tests** tab:

```javascript
// Log response time
pm.test("Response time is less than 2000ms", function () {
    pm.expect(pm.response.responseTime).to.be.below(2000);
});

// Check for errors
pm.test("No error in response", function () {
    const jsonData = pm.response.json();
    pm.expect(jsonData).to.not.have.property('error');
});
```

---

## 📋 Step 9: Common Headers

### Create Header Preset

1. Click on collection
2. Go to **"Variables"** tab
3. Add collection-level headers:

| Key | Value |
|-----|-------|
| `Content-Type` | `application/json` |
| `X-CSRF-Token` | `{{csrf_token}}` |
| `Authorization` | `Bearer {{access_token}}` |

**Note:** These will be added to all requests in the collection (you can override per request).

---

## 🎯 Step 10: Testing Workflow

### Typical Testing Flow:

1. **Get CSRF Token:**
   - Run "Get CSRF Token" request
   - Token auto-saved to environment

2. **Register User:**
   - Run "Register User" request
   - Check response

3. **Verify Email:**
   - Get token from email (MailHog)
   - Run "Verify Email" request

4. **Login:**
   - Run "Login" request
   - Tokens auto-saved to environment

5. **Setup 2FA:**
   - Run "Setup 2FA" request
   - Scan QR code with authenticator app
   - Get code from app
   - Run "Verify 2FA Setup" request

6. **Test Protected Endpoints:**
   - All requests now have access_token in headers
   - CSRF token auto-added

---

## 🔍 Step 11: Debugging Tips

### Check Environment Variables

1. Click **"Environments"** → Your environment
2. Check if variables are set correctly
3. Manually set if needed

### Check Cookies

1. Click on request
2. Go to **"Cookies"** tab
3. See all cookies for the domain

### View Request/Response

1. Click on request
2. Check **"Headers"**, **"Body"**, **"Tests"** tabs
3. Run request and check **"Response"**

---

## 📦 Step 12: Export Collection

### Save Your Setup

1. Click on collection
2. Click **"..."** (three dots)
3. Click **"Export"**
4. Save as JSON file
5. Share with team or backup

---

## 🚀 Quick Start Checklist

- [ ] Create Postman collection
- [ ] Set up environment with variables
- [ ] Add pre-request script for CSRF
- [ ] Create register endpoint
- [ ] Create login endpoint (with token extraction)
- [ ] Create 2FA endpoints
- [ ] Create user endpoints
- [ ] Test complete flow
- [ ] Export collection for backup

---

## 💡 Pro Tips

1. **Use Environments:** Create separate environments for:
   - Local development
   - Staging
   - Production

2. **Organize Folders:** Group endpoints by feature:
   - Authentication
   - 2FA
   - Users
   - Admin

3. **Use Variables:** Don't hardcode values, use `{{variable_name}}`

4. **Save Examples:** Save example responses for documentation

5. **Use Tests:** Automate validation with test scripts

6. **Share Collection:** Export and share with team

---

## 🐛 Troubleshooting

### CSRF Token Not Working
- Check if token is being set in environment
- Verify token is in request headers
- Check backend logs for CSRF errors

### Authentication Failing
- Verify access_token is set in environment
- Check token expiration (1 hour)
- Use refresh token to get new access token

### Cookies Not Persisting
- Enable "Manage Cookies" in Postman settings
- Check cookie domain matches your backend URL

---

**Ready to test!** Start with the register endpoint and work through the flow.

