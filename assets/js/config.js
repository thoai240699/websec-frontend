// API Configuration
const API_CONFIG = {
  BASE_URL: 'http://localhost:3052',
  ENDPOINTS: {
    // Auth endpoints
    SIGNUP: '/api/auth/signup',
    LOGIN: '/api/auth/login',

    // Admin auth endpoints
    ADMIN_LOGIN: '/api/admin/auth/login',

    // User endpoints
    USER_PROFILE: '/api/user/profile',

    // Business endpoints
    BUSINESS: '/api/business',
    BUSINESS_PRODUCT: '/api/business/product',
    BUSINESS_ORDER: '/api/business/order',
    BUSINESS_BASEMENT: '/api/business/basement',

    // Admin business endpoints
    ADMIN_BUSINESS: '/api/admin/business',

    // Manager endpoints
    MANAGER_BUSINESS: '/api/manager',
    MANAGER_STAFF_LIST: '/api/manager/admins',
    MANAGER_REGISTER_STAFF: '/api/manager/add-staff',
    MANAGER_GRANT_ADMIN: '/api/manager/grant-admin',
    MANAGER_REVOKE_ADMIN: '/api/manager/revoke-admin',
    MANAGER_LOGS: '/api/manager/logs',
  },
};

// Storage keys
const STORAGE_KEYS = {
  TOKEN: 'websec_token',
  USER_DATA: 'websec_user',
  USER_ROLE: 'websec_role',
};
