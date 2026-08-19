# Rate Limiting HeaderMap Extraction Fix

## Problem
Axum 0.7 has strict extractor ordering requirements. We can't easily extract `HeaderMap` or `Request` alongside `CookieJar` and `Extension` in the login handler.

## Solution Options

### Option 1: Middleware-Level Rate Limiting (Recommended for now)
Move rate limiting to middleware level. This works but loses some handler-specific control.

### Option 2: Custom Extractor (Current attempt)
Create `OptionalClientIp` extractor using `FromRequestParts`. This should work but needs proper trait implementation.

### Option 3: Extract IP in Middleware, Use in Handler
The `ip_extractor` middleware already adds `ClientIp` to extensions. We need to extract it properly.

## Current Status
- Rate limiting logic: ✅ Complete
- Security monitoring: ✅ Complete  
- IP extraction: ⚠️ Blocked by Axum extractor ordering
- Handler integration: ⚠️ Waiting on IP extraction fix

## Next Steps
1. Fix IP extraction (try Option 3 with proper Extension usage)
2. Complete integration in all auth endpoints
3. Test thoroughly

