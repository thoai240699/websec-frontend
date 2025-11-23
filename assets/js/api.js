// API Service
class APIService {
  constructor() {
    this.baseURL = API_CONFIG.BASE_URL;
  }

  // Get headers with authentication
  getHeaders(includeAuth = false) {
    const headers = {
      'Content-Type': 'application/json',
    };

    if (includeAuth) {
      const token = localStorage.getItem(STORAGE_KEYS.TOKEN);
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
    }

    return headers;
  }

  // Generic request method
  async request(endpoint, options = {}) {
    try {
      const url = `${this.baseURL}${endpoint}`;
      const response = await fetch(url, {
        ...options,
        headers: this.getHeaders(options.auth),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || data.error || 'Request failed');
      }

      return data;
    } catch (error) {
      console.error('API Error:', error);
      throw error;
    }
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
