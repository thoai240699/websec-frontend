# Activity Log Feature - Implementation Guide

## Overview

The Activity Log feature provides comprehensive system monitoring and audit trail capabilities for the WebSec application. It tracks all user actions including CREATE, READ, UPDATE, DELETE, LOGIN, and LOGOUT operations.

## Features Implemented

### 1. **Activity Log Page** (`pages/activity.html`)

- **Full Timeline View**: Visual timeline showing all system activities
- **Filtering**: Filter by action type (CREATE, READ, UPDATE, DELETE, etc.) and entity
- **Statistics**: Real-time stats showing total activities, today's activities, and activities in the last hour
- **Detail Modal**: Click any activity to view full details including before/after changes
- **Auto-refresh**: Manual refresh button to update the log
- **Access Control**: Only accessible by users with MANAGER or ADMIN roles

### 2. **Dashboard Integration**

Both regular dashboard and admin dashboard now show recent activity:

- **Recent Activity Widget**: Shows last 5 activities for managers/admins
- **Quick Access**: "View All" button links to full activity page
- **Real-time Updates**: Activity loads automatically on dashboard

### 3. **API Integration**

New API endpoint added:

```javascript
// Get activity logs
api.getActivityLogs(limit); // Optional limit parameter
```

Endpoint: `GET /api/manager/logs`

### 4. **Visual Design**

- **Timeline Layout**: Clean vertical timeline with color-coded markers
- **Action Badges**: Color-coded badges for different action types:
  - 🟢 CREATE (Success/Green)
  - 🔵 READ (Info/Blue)
  - 🟡 UPDATE (Warning/Yellow)
  - 🔴 DELETE (Danger/Red)
  - 🟣 LOGIN (Primary/Purple)
  - ⚫ LOGOUT (Secondary/Gray)
- **Responsive Design**: Works on all screen sizes
- **Smooth Animations**: Timeline items animate on hover

## File Changes

### New Files Created

1. **`pages/activity.html`** - Full activity log page
2. **`ACTIVITY_FEATURE.md`** - This documentation

### Modified Files

1. **`assets/js/config.js`**

   - Added `MANAGER_LOGS` endpoint

2. **`assets/js/api.js`**

   - Added `getActivityLogs()` method

3. **`assets/js/auth.js`**

   - Added Activity link to navigation for managers/admins

4. **`assets/css/styles.css`**

   - Added timeline styles
   - Added activity log styles
   - Added compact activity styles for dashboard
   - Added detail modal styles

5. **`pages/dashboard.html`**

   - Added recent activity section for managers/admins
   - Added activity loading functionality

6. **`pages/admin-dashboard.html`**
   - Updated system activity section to show real logs
   - Added activity loading functionality

## Usage

### For Managers/Admins

1. **Access Activity Log**

   - Navigate to the Activity menu item in the navigation bar
   - Or click "View Activity" on the dashboard

2. **Filter Activities**

   - Use the action dropdown to filter by action type
   - Use the entity dropdown to filter by entity type
   - Both filters can be used together

3. **View Details**

   - Click any activity item to see full details
   - Modal shows before/after changes if available
   - Close modal by clicking X or outside the modal

4. **Refresh**
   - Click the refresh button to reload latest activities

### Dashboard Widget

- Automatically shows last 5 activities for managers/admins
- Click "View All" to open full activity page
- Updates on page load

## Backend Requirements

The activity log feature relies on the backend endpoint:

- **Endpoint**: `GET /api/manager/logs`
- **Authentication**: Required (JWT token)
- **Authorization**: MANAGER or ADMIN role required
- **Response Format**:

```json
{
  "message": "Logs retrieved successfully",
  "body": [
    {
      "_id": "...",
      "action": "CREATE",
      "entity": "Admin",
      "userId": "...",
      "content": "Created admin user: john_doe",
      "before": null,
      "after": {...},
      "createdAt": "2025-11-22T10:30:00.000Z",
      "updatedAt": "2025-11-22T10:30:00.000Z"
    }
  ]
}
```

## Security

- **Access Control**: Only MANAGER and ADMIN roles can access activity logs
- **Frontend Validation**: Pages check user roles before displaying
- **Backend Protection**: API endpoint protected with JWT and role middleware
- **XSS Prevention**: All displayed content is escaped using `escapeHtml()`

## Performance Considerations

1. **Log Limit**: Backend limits logs to 100 most recent by default
2. **Auto-expiry**: Logs expire after 24 hours (set in backend model)
3. **Efficient Queries**: Logs sorted by creation date (descending)
4. **Frontend Filtering**: Filtering done client-side to reduce API calls

## Future Enhancements

Potential improvements for future versions:

1. **Advanced Filtering**

   - Date range picker
   - User-based filtering
   - Full-text search

2. **Export Functionality**

   - Export logs to CSV/PDF
   - Email digest of activities

3. **Real-time Updates**

   - WebSocket integration for live updates
   - Push notifications for critical actions

4. **Analytics**

   - Activity charts and graphs
   - User activity heatmap
   - Trend analysis

5. **Pagination**
   - Load more activities on scroll
   - Better performance for large datasets

## Troubleshooting

### Activity page shows "Failed to load"

- Check if user has MANAGER or ADMIN role
- Verify backend endpoint is running
- Check browser console for API errors

### No activities showing

- Verify backend is logging activities
- Check if logs have expired (24-hour TTL)
- Ensure database connection is working

### Activities not updating

- Click the refresh button
- Clear browser cache
- Check network tab for failed requests

## Testing Checklist

- [ ] Manager can access activity page
- [ ] Admin can access activity page
- [ ] Regular users cannot access activity page
- [ ] Activities display correctly
- [ ] Filtering works for actions
- [ ] Filtering works for entities
- [ ] Statistics update correctly
- [ ] Modal shows activity details
- [ ] Dashboard shows recent activities
- [ ] Refresh button works
- [ ] Navigation link appears for authorized users
- [ ] Responsive design works on mobile

---

**Status**: ✅ Fully Implemented and Ready for Testing
**Last Updated**: November 22, 2025
