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
  if (navMenu) {
    navMenu.classList.toggle('active');
  }
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
