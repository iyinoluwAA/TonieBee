# Redirect Methods: window.location vs useNavigate

## Comparison

### `window.location.replace()` (Hard Redirect)

**Pros:**
- ✅ Works everywhere (even outside React Router)
- ✅ Can't be blocked by React state
- ✅ Clears browser history (prevents back button)
- ✅ Forces full page reload
- ✅ Good for external redirects or when you need to clear all state

**Cons:**
- ❌ Loses React state
- ❌ Full page reload (slower)
- ❌ Can't use React Router features
- ❌ Breaks SPA (Single Page Application) flow
- ❌ Loses all component state

**When to Use:**
- External redirects (to different domain)
- When you need to clear ALL state
- When React Router isn't available
- Logout scenarios where you want to clear everything

### `useNavigate()` (React Router Navigation)

**Pros:**
- ✅ Maintains React state
- ✅ No page reload (faster, smoother)
- ✅ Works with React Router features
- ✅ Preserves SPA experience
- ✅ Can use `replace: true` to prevent back button
- ✅ Better for internal navigation
- ✅ Can pass state: `navigate('/path', { state: { data } })`

**Cons:**
- ❌ Only works within React Router context
- ❌ Can be blocked if component unmounts
- ❌ Requires React Router setup

**When to Use:**
- Internal navigation within your app
- When you want to maintain React state
- When you want smooth transitions
- Most cases in a React SPA

## For Our Recovery Code Redirect

**We should use `useNavigate()` because:**

1. **It's an internal redirect** - staying within our app
2. **We want to maintain state** - sessionStorage flag, user session
3. **Better UX** - No page reload, smoother transition
4. **React Router context** - We're already in a React Router app
5. **Can use replace** - `navigate('/recovery-setup', { replace: true })` prevents back button

## Code Example

```typescript
// ✅ GOOD - For internal redirects
import { useNavigate } from 'react-router-dom';

const navigate = useNavigate();
navigate('/recovery-setup', { replace: true });

// ❌ AVOID - For internal redirects (unless you need to clear all state)
window.location.replace('/recovery-setup');
```

## Best Practice

**Use `useNavigate()` for internal redirects, `window.location` for external/logout.**

