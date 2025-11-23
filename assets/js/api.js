// API Service
class APIService {
  constructor() {
    this.baseURL = API_CONFIG.BASE_URL;
    this.requestCache = new Map();
    this.cacheTimeout = 5 * 60 * 1000; // 5 minutes
  }

  // Get headers with authentication and security
  getHeaders(includeAuth = false) {
    const headers = {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest', // CSRF protection
    };

    if (includeAuth) {
      const token = localStorage.getItem(STORAGE_KEYS.TOKEN);
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
    }

    // Add CSRF token if available
    if (typeof SecurityUtils !== 'undefined') {
      const csrfToken = SecurityUtils.getCSRFToken();
      if (csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;
      }
    }

    return headers;
  }

  // Generic request method with security enhancements
  async request(endpoint, options = {}) {
    try {
      // Check rate limiting
      if (typeof SecurityUtils !== 'undefined') {
        const rateLimitCheck = SecurityUtils.isRateLimited(
          endpoint,
          options.maxAttempts || 10,
          options.timeWindow || 60000
        );
        if (rateLimitCheck.limited) {
          throw new Error(rateLimitCheck.message);
        }
      }

      // Check cache for GET requests
      if (options.method === 'GET' && options.useCache) {
        const cached = this.getFromCache(endpoint);
        if (cached) return cached;
      }

      const url = `${this.baseURL}${endpoint}`;
      const response = await fetch(url, {
        ...options,
        headers: this.getHeaders(options.auth),
        credentials: 'omit', // Don't send credentials cross-origin
      });

      const data = await response.json();

      if (!response.ok) {
        // Handle specific error codes
        if (response.status === 401) {
          // Unauthorized - clear auth and redirect
          if (typeof Auth !== 'undefined') {
            Auth.logout();
          }
          throw new Error('Session expired. Please login again.');
        } else if (response.status === 403) {
          throw new Error('Access denied. Insufficient permissions.');
        } else if (response.status === 429) {
          throw new Error('Too many requests. Please try again later.');
        }

        throw new Error(data.message || data.error || 'Request failed');
      }

      // Cache successful GET requests
      if (options.method === 'GET' && options.useCache) {
        this.saveToCache(endpoint, data);
      }

      return data;
    } catch (error) {
      console.error('API Error:', error);
      
      // Network error handling
      if (error.name === 'TypeError' && error.message.includes('fetch')) {
        throw new Error('Network error. Please check your connection.');
      }
      
      throw error;
    }
  }

  // Cache management
  getFromCache(key) {
    const cached = this.requestCache.get(key);
    if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
      return cached.data;
    }
    this.requestCache.delete(key);
    return null;
  }

  saveToCache(key, data) {
    this.requestCache.set(key, {
      data,
      timestamp: Date.now(),
    });
  }

  clearCache() {
    this.requestCache.clear();
  }

  // Auth methods
  async signup(username, password) {
    return this.request(API_CONFIG.ENDPOINTS.SIGNUP, {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
  }

  async login(username, password) {
    return this.request(API_CONFIG.ENDPOINTS.LOGIN, {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
  }

  async adminLogin(username, password) {
    return this.request(API_CONFIG.ENDPOINTS.ADMIN_LOGIN, {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
  }

  // User methods
  async getUserProfile() {
    return this.request(API_CONFIG.ENDPOINTS.USER_PROFILE, {
      method: 'GET',
      auth: true,
    });
  }

  async updateUserProfile(fullname, dob) {
    return this.request(API_CONFIG.ENDPOINTS.USER_PROFILE, {
      method: 'PUT',
      auth: true,
      body: JSON.stringify({ fullname, dob }),
    });
  }

  // Business methods
  async getBusiness() {
    return this.request(API_CONFIG.ENDPOINTS.BUSINESS, {
      method: 'GET',
      auth: true,
    });
  }

  async doBusiness(businessData) {
    return this.request(API_CONFIG.ENDPOINTS.BUSINESS, {
      method: 'POST',
      auth: true,
      body: JSON.stringify(businessData),
    });
  }

  // Admin business methods
  async getAdminBusiness() {
    return this.request(API_CONFIG.ENDPOINTS.ADMIN_BUSINESS, {
      method: 'GET',
      auth: true,
    });
  }

  async doAdminBusiness(businessData) {
    return this.request(API_CONFIG.ENDPOINTS.ADMIN_BUSINESS, {
      method: 'POST',
      auth: true,
      body: JSON.stringify(businessData),
    });
  }

  // Manager methods
  async getStaffList() {
    return this.request(API_CONFIG.ENDPOINTS.MANAGER_STAFF_LIST, {
      method: 'GET',
      auth: true,
    });
  }

  async registerStaff(staffData) {
    return this.request(API_CONFIG.ENDPOINTS.MANAGER_REGISTER_STAFF, {
      method: 'POST',
      auth: true,
      body: JSON.stringify(staffData),
    });
  }

  async grantAdminRole(staffId) {
    return this.request(
      `${API_CONFIG.ENDPOINTS.MANAGER_GRANT_ADMIN}/${staffId}`,
      {
        method: 'PUT',
        auth: true,
      }
    );
  }

  async revokeAdminRole(staffId) {
    return this.request(
      `${API_CONFIG.ENDPOINTS.MANAGER_REVOKE_ADMIN}/${staffId}`,
      {
        method: 'PUT',
        auth: true,
      }
    );
  }

  // Activity/Logs methods
  async getActivityLogs(limit) {
    const endpoint = limit
      ? `${API_CONFIG.ENDPOINTS.MANAGER_LOGS}?limit=${limit}`
      : API_CONFIG.ENDPOINTS.MANAGER_LOGS;
    return this.request(endpoint, {
      method: 'GET',
      auth: true,
    });
  }
}

// Create global API instance
const api = new APIService();
