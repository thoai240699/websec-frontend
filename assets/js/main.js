// Main JavaScript utilities

// Show loading spinner
function showLoading(elementId = 'loadingSpinner') {
  const spinner = document.getElementById(elementId);
  if (spinner) {
    spinner.style.display = 'flex';
  }
}

// Hide loading spinner
function hideLoading(elementId = 'loadingSpinner') {
  const spinner = document.getElementById(elementId);
  if (spinner) {
    spinner.style.display = 'none';
  }
}

// Show message
function showMessage(message, type = 'success') {
  const messageContainer = document.getElementById('messageContainer');
  if (!messageContainer) return;

  const messageDiv = document.createElement('div');
  messageDiv.className = `message message-${type}`;
  messageDiv.textContent = message;

  messageContainer.appendChild(messageDiv);

  setTimeout(() => {
    messageDiv.remove();
  }, 5000);
}

// Show error message
function showError(error) {
  const message = error.message || error || 'An error occurred';
  showMessage(message, 'error');
}

// Show success message
function showSuccess(message) {
  showMessage(message, 'success');
}

// Format date for display
function formatDate(dateString) {
  if (!dateString) return 'N/A';
  const date = new Date(dateString);
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
}

// Format date for input (YYYY-MM-DD)
function formatDateForInput(dateString) {
  if (!dateString) return '';
  const date = new Date(dateString);
  return date.toISOString().split('T')[0];
}

// Validate email
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// Validate password strength
function validatePassword(password) {
  if (password.length < 8) {
    return {
      valid: false,
      message: 'Password must be at least 8 characters long',
    };
  }
  return { valid: true };
}

// Handle form submission with validation
async function handleFormSubmit(formId, submitHandler) {
  const form = document.getElementById(formId);
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    try {
      showLoading();
      await submitHandler(new FormData(form));
      hideLoading();
    } catch (error) {
      hideLoading();
      showError(error);
    }
  });
}

// Debounce function
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

// Toggle mobile menu
function toggleMobileMenu() {
  const navMenu = document.getElementById('navMenu');
  const mobileToggle = document.getElementById('mobileMenuToggle');
  
  // Get or create overlay
  let overlay = document.querySelector('.menu-overlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.className = 'menu-overlay';
    document.body.appendChild(overlay);
    
    // Click overlay to close menu
    overlay.addEventListener('click', toggleMobileMenu);
  }
  
  if (navMenu) {
    const isActive = navMenu.classList.toggle('active');
    overlay.classList.toggle('active', isActive);
    
    // Prevent body scroll when menu is open
    if (isActive) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
  }
  
  if (mobileToggle) {
    mobileToggle.classList.toggle('active');
  }
}

// Initialize mobile menu on page load
document.addEventListener('DOMContentLoaded', function() {
  const mobileMenuToggle = document.getElementById('mobileMenuToggle');
  
  if (mobileMenuToggle) {
    mobileMenuToggle.addEventListener('click', function(e) {
      e.stopPropagation();
      toggleMobileMenu();
    });
  }
  
  // Close mobile menu when clicking on a link
  const navMenu = document.getElementById('navMenu');
  if (navMenu) {
    navMenu.querySelectorAll('a').forEach(link => {
      link.addEventListener('click', () => {
        if (navMenu.classList.contains('active')) {
          toggleMobileMenu();
        }
      });
    });
    
    // Prevent clicks inside menu from closing it
    navMenu.addEventListener('click', function(e) {
      e.stopPropagation();
    });
  }
});

// Escape HTML to prevent XSS
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
