// Authentication utilities
const Auth = {
  // Save authentication data
  saveAuth(token, userData, roles) {
    localStorage.setItem(STORAGE_KEYS.TOKEN, token);
    localStorage.setItem(STORAGE_KEYS.USER_DATA, JSON.stringify(userData));
    localStorage.setItem(STORAGE_KEYS.USER_ROLE, JSON.stringify(roles));
  },

  // Get token
  getToken() {
    return localStorage.getItem(STORAGE_KEYS.TOKEN);
  },

  // Get user data
  getUserData() {
    const data = localStorage.getItem(STORAGE_KEYS.USER_DATA);
    return data ? JSON.parse(data) : null;
  },

  // Get user roles
  getUserRoles() {
    const roles = localStorage.getItem(STORAGE_KEYS.USER_ROLE);
    return roles ? JSON.parse(roles) : [];
  },

  // Check if user is authenticated
  isAuthenticated() {
    return !!this.getToken();
  },

  // Check if user has specific role
  hasRole(role) {
    const roles = this.getUserRoles();
    return roles.includes(role);
  },

  // Logout
  logout() {
    localStorage.removeItem(STORAGE_KEYS.TOKEN);
    localStorage.removeItem(STORAGE_KEYS.USER_DATA);
    localStorage.removeItem(STORAGE_KEYS.USER_ROLE);
    window.location.href = '/index.html';
  },

  // Redirect if not authenticated
  requireAuth() {
    if (!this.isAuthenticated()) {
      window.location.href = '/pages/login.html';
      return false;
    }
    return true;
  },

  // Redirect if not admin
  requireAdmin() {
    if (!this.isAuthenticated() || !this.hasRole('ADMIN')) {
      window.location.href = '/pages/admin-login.html';
      return false;
    }
    return true;
  },

  // Redirect if not manager
  requireManager() {
    if (!this.isAuthenticated() || !this.hasRole('MANAGER')) {
      window.location.href = '/pages/dashboard.html';
      return false;
    }
    return true;
  },

  // Redirect if authenticated (for login pages)
  redirectIfAuthenticated() {
    if (this.isAuthenticated()) {
      if (this.hasRole('ADMIN')) {
        window.location.href = '/pages/admin-dashboard.html';
      } else {
        window.location.href = '/pages/dashboard.html';
      }
      return true;
    }
    return false;
  },
};

// Show/hide elements based on auth status
function updateUIBasedOnAuth() {
  const isAuth = Auth.isAuthenticated();
  const userData = Auth.getUserData();

  // Update navigation
  const navMenu = document.getElementById('navMenu');
  if (navMenu && isAuth) {
    const userRoles = Auth.getUserRoles();
    const isAdmin = userRoles.includes('ADMIN');
    const isManager = userRoles.includes('MANAGER');
    const isCustomer = userRoles.includes('CUSTOMER');

    // Show Business link only for non-manager users (customers, admins, staff)
    const showBusiness = !isManager || isAdmin || isCustomer;

    navMenu.innerHTML = `
            <li><a href="/pages/dashboard.html">Dashboard</a></li>
            <li><a href="/pages/profile.html">Profile</a></li>
            ${
              showBusiness
                ? '<li><a href="/pages/business.html">Business</a></li>'
                : ''
            }
            ${
              isAdmin
                ? '<li><a href="/pages/admin-dashboard.html">Admin</a></li>'
                : ''
            }
            ${
              isManager
                ? '<li><a href="/pages/manager.html">Manager</a></li>'
                : ''
            }
            ${
              isManager || isAdmin
                ? '<li><a href="/pages/activity.html">Activity</a></li>'
                : ''
            }
            <li><a href="#" onclick="Auth.logout()">Logout</a></li>
        `;
  }

  // Update user display
  const userDisplay = document.getElementById('userDisplay');
  if (userDisplay && isAuth && userData) {
    userDisplay.innerHTML = `
            <div class="user-info">
                <img src="${
                  userData.avatar || '/assets/images/default-avatar.png'
                }" alt="Avatar" class="avatar">
                <span>${userData.name || userData.email}</span>
            </div>
        `;
  }
}

// Initialize auth UI on page load
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', updateUIBasedOnAuth);
} else {
  updateUIBasedOnAuth();
}
