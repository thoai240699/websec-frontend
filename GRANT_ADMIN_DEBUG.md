# Grant Admin Functionality - Debug Guide

## Issue

The manager's grant admin functionality isn't working when clicking the "Grant Admin" button.

## Changes Made for Debugging

### 1. Enhanced Logging in `manager.html`

- Added console.log to display each staff member's ID when the list is rendered
- Check browser console for: `Staff ID for <username>: <id>`

### 2. Enhanced Logging in `api.js`

- Added detailed logging in `grantAdminRole()` and `revokeAdminRole()` methods
- Added comprehensive request/response logging in the `request()` method

### 3. Fixed Staff ID Reference

- Changed from `staff.id || staff._id` to `staff._id || staff.id`
- MongoDB returns `_id` as the primary identifier

## How to Debug

### Step 1: Open Browser DevTools

1. Open the manager page in your browser
2. Press F12 to open Developer Tools
3. Go to the "Console" tab

### Step 2: Load Staff List

When the page loads, you should see:

```
Staff ID for admin: 507f1f77bcf86cd799439011
Staff ID for thoai123: 507f191e810c19729de860ea
```

**❌ Problem Sign**: If you see `Staff ID for <username>: undefined`

- This means the backend is not returning the \_id field properly

### Step 3: Click "Grant Admin"

After clicking the Grant Admin button, you should see in console:

```
Grant Admin clicked: 507f191e810c19729de860ea thoai123
```

### Step 4: Confirm in Modal

After clicking "Grant Admin" button in the modal, you should see:

```
Confirm action: grant for staff: 507f191e810c19729de860ea
Calling grantAdminRole API...
grantAdminRole called with staffId: 507f191e810c19729de860ea
Full endpoint: /api/manager/grant-admin/507f191e810c19729de860ea
Full URL: http://localhost:3052/api/manager/grant-admin/507f191e810c19729de860ea
API Request: {method: 'PUT', url: 'http://localhost:3052/api/manager/grant-admin/507f191e810c19729de860ea', hasAuth: true}
```

### Step 5: Check Response

You should then see:

```
API Response status: 200
API Response data: {message: 'Admin role granted successfully'}
```

## Common Issues & Solutions

### Issue 1: staffId is undefined

**Symptom**: Console shows `Staff ID for <username>: undefined`

**Solution**:

- Check backend `getAllAdmins()` controller
- Ensure it's returning the full document with \_id field
- Verify the query: `Admin.find({...}, '-password')` is not excluding \_id

### Issue 2: 401 Unauthorized

**Symptom**: `API Response status: 401`

**Solution**:

- Your JWT token has expired (currently set to 10 minutes)
- Log out and log back in to get a new token
- Or increase `JWT_EXPIRES_IN` in backend `.env` file to `1h` or `24h`

### Issue 3: 403 Forbidden

**Symptom**: `API Response status: 403`

**Solution**:

- Your user doesn't have MANAGER role
- Check your admin roles in the database
- Ensure you logged in with a manager account

### Issue 4: 404 Not Found

**Symptom**: `API Response status: 404`

**Possibilities**:

1. **Staff not found**: The staffId doesn't exist in database
2. **Route not found**: Backend server might not be running
3. **Wrong URL**: Check if URL matches backend route

**Solution**:

- Verify backend is running on port 3052
- Check the constructed URL matches: `/api/manager/grant-admin/:adminId`
- Verify the staffId exists in the admins collection

### Issue 5: Network Error

**Symptom**: `API Error: Failed to fetch` or `TypeError: Failed to fetch`

**Solution**:

- Backend server is not running
- Start backend: `cd websec && npm start`
- Check port 3052 is available
- Verify CORS is enabled on backend

### Issue 6: CORS Error

**Symptom**: Console shows CORS policy error

**Solution**:

- Verify backend has `app.use(cors())` in `src/index.js`
- Backend should allow requests from frontend origin

## Backend Verification

### Check Backend is Running

```cmd
cd e:\InformationTechnology\7_Web\project\websec
npm start
```

Should show:

```
Server running on port 3052
Database connected
```

### Test Endpoint Directly with curl or Postman

```bash
PUT http://localhost:3052/api/manager/grant-admin/STAFF_ID_HERE
Headers:
  Authorization: Bearer YOUR_JWT_TOKEN_HERE
  Content-Type: application/json
```

Expected Response:

```json
{
  "message": "Admin role granted successfully"
}
```

## Frontend Testing Checklist

- [ ] Backend server is running on port 3052
- [ ] You're logged in with a MANAGER role account
- [ ] JWT token is valid (not expired)
- [ ] Staff list loads successfully
- [ ] Each staff member shows a valid \_id in console
- [ ] Clicking "Grant Admin" shows the modal
- [ ] Console logs show the correct staffId
- [ ] Console logs show 200 response status
- [ ] Success message appears
- [ ] Staff list reloads with updated role

## Next Steps

1. Open browser console
2. Navigate to manager page
3. Check all console logs
4. Take note of any errors
5. Match errors with the "Common Issues" section above
6. Apply the appropriate solution

## Quick Fix for Token Expiration

If token keeps expiring (every 10 minutes), update backend `.env`:

```env
JWT_EXPIRES_IN = 24h
```

Then restart the backend server and log in again.
