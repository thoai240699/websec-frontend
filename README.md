# WebSec Frontend

A frontend application for the WebSec backend API with role-based access control.

## Features

- **User Authentication**: Login and signup functionality
- **Admin Authentication**: Separate admin login portal
- **User Profile Management**: View and update user profiles
- **Business Operations**: Customer and admin business management
- **Role-Based Access Control**: Different views for CUSTOMER, ADMIN, and MANAGER roles

## Structure

```
websec-frontend/
├── index.html              # Landing page
├── pages/
│   ├── login.html          # User login
│   ├── signup.html         # User registration
│   ├── admin-login.html    # Admin login
│   ├── dashboard.html      # User dashboard
│   ├── profile.html        # User profile
│   ├── business.html       # Business operations
│   └── admin-dashboard.html # Admin dashboard
├── assets/
│   ├── css/
│   │   └── styles.css      # Main stylesheet
│   └── js/
│       ├── config.js       # API configuration
│       ├── api.js          # API service
│       ├── auth.js         # Authentication utilities
│       └── main.js         # Main JavaScript
└── README.md
```

## Setup

1. Make sure the WebSec backend is running (default: http://localhost:3052)
2. Update the API URL in `assets/js/config.js` if needed
3. Open `index.html` in a browser or serve with a local server

## API Endpoints

- **Auth**: `/api/auth/signup`, `/api/auth/login`
- **Admin Auth**: `/api/admin/auth/login`
- **User**: `/api/user/profile` (GET, PUT)
- **Business**: `/api/business/` (GET, POST)
- **Admin Business**: `/api/admin/business/` (GET, POST)

## Usage

1. **Sign Up**: Create a new customer account
2. **Login**: Access your dashboard with credentials
3. **Profile**: View and update your profile information
4. **Business**: Perform business operations based on your role
5. **Admin**: Admins can access admin dashboard for management

## Security

- JWT tokens stored in localStorage
- Protected routes require authentication
- Role-based middleware on frontend pages
"# websec-frontend" 
