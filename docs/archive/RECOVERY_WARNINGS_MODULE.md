# Recovery Warnings Module

## Status: Temporarily Disabled

The `recovery_warnings` module has been temporarily disabled due to a compilation error. This module was designed to send email warnings to users when their recovery codes are about to expire.

## What It Does

The module provides functionality to:
- Check all users with 2FA enabled
- Find recovery codes expiring at 90, 60, 30, and 7 days
- Send email warnings to users
- Track which warnings have been sent to avoid duplicates

## Why It Was Disabled

There was a compilation error related to the Axum handler signature. The handler function needs to be properly structured to work with Axum's routing system.

## Impact

**This is NOT critical for core functionality.** The recovery code system works fine without it. This module is an enhancement that:
- Sends proactive email warnings
- Helps users remember to regenerate codes before expiration
- Improves user experience

## Re-enabling

To re-enable this module:

1. Fix the handler signature in `backend/src/handler/recovery_warnings.rs`
2. Uncomment the module in `backend/src/handler/mod.rs`
3. Uncomment the route in `backend/src/routes.rs`
4. Test the endpoint: `POST /api/recovery-warnings/check-and-send`

## Alternative

You can manually check and send warnings by:
- Querying the database for expiring codes
- Using the email system directly
- Or implementing a simpler scheduled task

## Priority

**Low Priority** - This is a nice-to-have feature, not essential for the recovery code system to function.

