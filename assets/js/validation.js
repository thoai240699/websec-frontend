// Form Validation and Security Utilities

class FormValidator {
  constructor() {
    this.validators = {
      email: this.validateEmail,
      password: this.validatePassword,
      username: this.validateUsername,
      required: this.validateRequired,
      minLength: this.validateMinLength,
      maxLength: this.validateMaxLength,
      pattern: this.validatePattern,
      match: this.validateMatch,
    };
  }

  // Email validation with comprehensive regex
  validateEmail(value) {
    const emailRegex =
      /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(value)) {
      return {
        valid: false,
        message: 'Please enter a valid email address',
      };
    }
    // Additional security checks
    if (value.length > 254) {
      return { valid: false, message: 'Email address is too long' };
    }
    return { valid: true };
  }

  // Password validation with entropy-based strength checking
  validatePassword(value, options = {}) {
    // Prioritize length over complexity!
    const minLength = options.minLength || 12;  // Increased from 8 to 12
    const maxLength = options.maxLength || 128;

    if (value.length < minLength) {
      return {
        valid: false,
        message: `Password must be at least ${minLength} characters`,
      };
    }

    if (value.length > maxLength) {
      return {
        valid: false,
        message: `Password must not exceed ${maxLength} characters`,
      };
    }

    // Check for at least one lowercase letter
    if (options.requireLowercase !== false && !/[a-z]/.test(value)) {
      return {
        valid: false,
        message: 'Password must contain at least one lowercase letter',
      };
    }

    // Check for at least one uppercase letter
    if (options.requireUppercase && !/[A-Z]/.test(value)) {
      return {
        valid: false,
        message: 'Password must contain at least one uppercase letter',
      };
    }

    // Check for at least one number
    if (options.requireNumber && !/\d/.test(value)) {
      return {
        valid: false,
        message: 'Password must contain at least one number',
      };
    }

    // Check for at least one special character
    if (
      options.requireSpecial &&
      !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(value)
    ) {
      return {
        valid: false,
        message: 'Password must contain at least one special character',
      };
    }

    return { valid: true };
  }

  // Calculate password strength using Entropy
  calculatePasswordStrength(password) {
    const length = password.length;
    
    // Determine character set size (N)
    const checks = {
      lowercase: /[a-z]/.test(password),
      uppercase: /[A-Z]/.test(password),
      number: /\d/.test(password),
      special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(password),
      spaces: /\s/.test(password),
    };

    let charsetSize = 0;
    if (checks.lowercase) charsetSize += 26;  // a-z
    if (checks.uppercase) charsetSize += 26;  // A-Z
    if (checks.number) charsetSize += 10;     // 0-9
    if (checks.special) charsetSize += 32;    // Special characters
    if (checks.spaces) charsetSize += 1;      // Space

    // Minimum charset size (at least lowercase if nothing detected)
    if (charsetSize === 0) charsetSize = 26;

    // Calculate entropy: L × log₂(N)
    const entropy = length * Math.log2(charsetSize);

    // Determine strength level based on entropy
    // < 40 bits: Very Weak (vulnerable to brute force)
    // 40-59 bits: Weak (can be cracked with effort)
    // 60-79 bits: Medium (reasonable for most uses)
    // 80-99 bits: Strong (difficult to crack)
    // >= 100 bits: Very Strong (extremely difficult to crack)
    let level = 'very-weak';
    let label = 'Very Weak';
    let percentage = Math.min(100, (entropy / 120) * 100);

    if (entropy >= 100) {
      level = 'very-strong';
      label = 'Very Strong';
    } else if (entropy >= 80) {
      level = 'strong';
      label = 'Strong';
    } else if (entropy >= 60) {
      level = 'medium';
      label = 'Medium';
    } else if (entropy >= 40) {
      level = 'weak';
      label = 'Weak';
    }

    // Additional checks
    const recommendations = [];
    if (length < 12) {
      recommendations.push('Use at least 12 characters (length matters most!)');
    }
    if (length < 14 && !checks.special) {
      recommendations.push('Add special characters or make it longer');
    }
    if (charsetSize < 26) {
      recommendations.push('Use letters to increase complexity');
    }

    return {
      entropy: Math.round(entropy * 10) / 10,  // Round to 1 decimal
      level,
      label,
      percentage: Math.round(percentage),
      charsetSize,
      length,
      checks,
      recommendations,
      // Estimate time to crack (very rough)
      estimatedCrackTime: this.estimateCrackTime(entropy)
    };
  }

  // Estimate time to crack based on entropy
  estimateCrackTime(entropy) {
    // Assume 10 billion guesses/second (modern GPU)
    const guessesPerSecond = 10e9;
    const possibleCombinations = Math.pow(2, entropy);
    const secondsToCrack = possibleCombinations / (2 * guessesPerSecond); // Average case

    if (secondsToCrack < 1) return 'Instant';
    if (secondsToCrack < 60) return `${Math.round(secondsToCrack)} seconds`;
    if (secondsToCrack < 3600) return `${Math.round(secondsToCrack / 60)} minutes`;
    if (secondsToCrack < 86400) return `${Math.round(secondsToCrack / 3600)} hours`;
    if (secondsToCrack < 31536000) return `${Math.round(secondsToCrack / 86400)} days`;
    if (secondsToCrack < 31536000 * 100) return `${Math.round(secondsToCrack / 31536000)} years`;
    
    return 'Centuries+';
  }

  // Username validation
  validateUsername(value, options = {}) {
    const minLength = options.minLength || 3;
    const maxLength = options.maxLength || 30;

    if (value.length < minLength) {
      return {
        valid: false,
        message: `Username must be at least ${minLength} characters`,
      };
    }

    if (value.length > maxLength) {
      return {
        valid: false,
        message: `Username must not exceed ${maxLength} characters`,
      };
    }

    // Only allow alphanumeric characters, underscores, and hyphens
    const usernameRegex = /^[a-zA-Z0-9_-]+$/;
    if (!usernameRegex.test(value)) {
      return {
        valid: false,
        message:
          'Username can only contain letters, numbers, underscores, and hyphens',
      };
    }

    // Must start with a letter
    if (!/^[a-zA-Z]/.test(value)) {
      return {
        valid: false,
        message: 'Username must start with a letter',
      };
    }

    return { valid: true };
  }

  // Required field validation
  validateRequired(value) {
    if (!value || value.toString().trim() === '') {
      return { valid: false, message: 'This field is required' };
    }
    return { valid: true };
  }

  // Minimum length validation
  validateMinLength(value, length) {
    if (value.length < length) {
      return {
        valid: false,
        message: `Must be at least ${length} characters`,
      };
    }
    return { valid: true };
  }

  // Maximum length validation
  validateMaxLength(value, length) {
    if (value.length > length) {
      return {
        valid: false,
        message: `Must not exceed ${length} characters`,
      };
    }
    return { valid: true };
  }

  // Pattern validation
  validatePattern(value, pattern, message) {
    const regex = new RegExp(pattern);
    if (!regex.test(value)) {
      return {
        valid: false,
        message: message || 'Invalid format',
      };
    }
    return { valid: true };
  }

  // Match validation (e.g., password confirmation)
  validateMatch(value, matchValue, fieldName = 'field') {
    if (value !== matchValue) {
      return {
        valid: false,
        message: `${fieldName} does not match`,
      };
    }
    return { valid: true };
  }

  // Sanitize input to prevent XSS
  sanitizeInput(input) {
    if (typeof input !== 'string') return input;

    // Create a temporary div to use browser's built-in HTML escaping
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
  }

  // Sanitize HTML while allowing safe tags
  sanitizeHTML(html, allowedTags = []) {
    const div = document.createElement('div');
    div.innerHTML = html;

    // If no tags are allowed, return text content only
    if (allowedTags.length === 0) {
      return div.textContent || div.innerText || '';
    }

    // Remove disallowed tags
    const allElements = div.querySelectorAll('*');
    allElements.forEach((el) => {
      if (!allowedTags.includes(el.tagName.toLowerCase())) {
        el.replaceWith(el.textContent);
      }
    });

    return div.innerHTML;
  }

  // Validate and sanitize form data
  validateForm(formElement, rules) {
    const errors = {};
    let isValid = true;

    Object.keys(rules).forEach((fieldName) => {
      const field = formElement.querySelector(`[name="${fieldName}"]`);
      if (!field) return;

      const value = field.value;
      const fieldRules = rules[fieldName];

      for (const rule of fieldRules) {
        const { type, ...options } = rule;
        let result;

        switch (type) {
          case 'required':
            result = this.validateRequired(value);
            break;
          case 'email':
            result = this.validateEmail(value);
            break;
          case 'password':
            result = this.validatePassword(value, options);
            break;
          case 'username':
            result = this.validateUsername(value, options);
            break;
          case 'minLength':
            result = this.validateMinLength(value, options.length);
            break;
          case 'maxLength':
            result = this.validateMaxLength(value, options.length);
            break;
          case 'pattern':
            result = this.validatePattern(
              value,
              options.pattern,
              options.message
            );
            break;
          case 'match':
            const matchField = formElement.querySelector(
              `[name="${options.field}"]`
            );
            result = this.validateMatch(
              value,
              matchField?.value,
              options.fieldName
            );
            break;
          default:
            result = { valid: true };
        }

        if (!result.valid) {
          errors[fieldName] = result.message;
          isValid = false;
          break; // Stop at first error for this field
        }
      }
    });

    return { isValid, errors };
  }

  // Add real-time validation to a field
  addLiveValidation(fieldElement, validationRules) {
    // Check if feedback element already exists
    let feedbackElement = fieldElement.parentElement.querySelector('.form-feedback');
    if (!feedbackElement) {
      feedbackElement = this.createFeedbackElement();
      fieldElement.parentElement.appendChild(feedbackElement);
    }

    const validateField = () => {
      const value = fieldElement.value;
      let isValid = true;
      let message = '';

      for (const rule of validationRules) {
        const { type, ...options } = rule;
        let result;

        switch (type) {
          case 'required':
            result = this.validateRequired(value);
            break;
          case 'email':
            result = this.validateEmail(value);
            break;
          case 'password':
            result = this.validatePassword(value, options);
            break;
          case 'username':
            result = this.validateUsername(value, options);
            break;
          case 'minLength':
            result = this.validateMinLength(value, options.length);
            break;
          case 'maxLength':
            result = this.validateMaxLength(value, options.length);
            break;
          case 'pattern':
            result = this.validatePattern(
              value,
              options.pattern,
              options.message
            );
            break;
          default:
            result = { valid: true };
        }

        if (!result.valid) {
          isValid = false;
          message = result.message;
          break;
        }
      }

      this.updateFieldValidation(
        fieldElement,
        feedbackElement,
        isValid,
        message
      );
    };

    // Validate on blur and input
    fieldElement.addEventListener('blur', validateField);
    fieldElement.addEventListener('input', debounce(validateField, 500));
  }

  // Create feedback element
  createFeedbackElement() {
    const feedback = document.createElement('span');
    feedback.className = 'form-feedback';
    return feedback;
  }

  // Update field validation UI
  updateFieldValidation(field, feedbackElement, isValid, message) {
    if (isValid && field.value) {
      field.classList.remove('invalid');
      field.classList.add('valid');
      feedbackElement.textContent = '';
      feedbackElement.className = 'form-feedback';
    } else if (!isValid) {
      field.classList.remove('valid');
      field.classList.add('invalid');
      feedbackElement.textContent = message;
      feedbackElement.className = 'form-feedback error';
    } else {
      field.classList.remove('valid', 'invalid');
      feedbackElement.textContent = '';
      feedbackElement.className = 'form-feedback';
    }
  }
}

// Security utilities
const SecurityUtils = {
  // Rate limiting for API calls
  rateLimiter: new Map(),

  // Check if action is rate limited
  isRateLimited(action, maxAttempts = 5, timeWindow = 60000) {
    const now = Date.now();
    const key = action;

    if (!this.rateLimiter.has(key)) {
      this.rateLimiter.set(key, []);
    }

    const attempts = this.rateLimiter.get(key);
    // Remove old attempts outside the time window
    const validAttempts = attempts.filter(
      (timestamp) => now - timestamp < timeWindow
    );

    if (validAttempts.length >= maxAttempts) {
      return {
        limited: true,
        message: `Too many attempts. Please try again later.`,
      };
    }

    validAttempts.push(now);
    this.rateLimiter.set(key, validAttempts);

    return { limited: false };
  },

  // Generate CSRF token
  generateCSRFToken() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, (byte) => byte.toString(16).padStart(2, '0')).join(
      ''
    );
  },

  // Store CSRF token
  storeCSRFToken() {
    const token = this.generateCSRFToken();
    sessionStorage.setItem('csrf_token', token);
    return token;
  },

  // Get CSRF token
  getCSRFToken() {
    let token = sessionStorage.getItem('csrf_token');
    if (!token) {
      token = this.storeCSRFToken();
    }
    return token;
  },

  // Validate origin for CORS
  validateOrigin(origin) {
    const allowedOrigins = ['http://localhost:3052', window.location.origin];
    return allowedOrigins.includes(origin);
  },

  // Check for suspicious patterns
  detectSuspiciousInput(input) {
    const suspiciousPatterns = [
      /<script[^>]*>[\s\S]*?<\/script>/gi, // Script tags
      /javascript:/gi, // JavaScript protocol
      /on\w+\s*=/gi, // Event handlers
      /<iframe/gi, // Iframe tags
      /data:text\/html/gi, // Data URLs
      /vbscript:/gi, // VBScript protocol
    ];

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(input)) {
        return {
          suspicious: true,
          message: 'Input contains potentially malicious content',
        };
      }
    }

    return { suspicious: false };
  },

  // Check for common/leaked passwords
  checkCommonPasswords(password) {
    const commonPasswords = [
      'password',
      '123456',
      '12345678',
      'qwerty',
      'abc123',
      'monkey',
      '1234567',
      'letmein',
      'trustno1',
      'dragon',
      'baseball',
      'iloveyou',
      'master',
      'sunshine',
      'ashley',
      'bailey',
      'passw0rd',
      'shadow',
      '123123',
      '654321',
      'password123',
      'admin',
      'welcome',
      'password1',
      '123456789',
      'qwerty123',
      'Password1',
      'P@ssw0rd',
      'Password123',
      '1q2w3e4r',
    ];

    const lowerPassword = password.toLowerCase();
    
    // Direct match check
    if (commonPasswords.some(common => lowerPassword === common.toLowerCase())) {
      return {
        isCommon: true,
        message: 'This password is too common and easily guessed'
      };
    }

    // Check for simple patterns
    if (/^(.)\1+$/.test(password)) {  // All same character
      return {
        isCommon: true,
        message: 'Password cannot be all the same character'
      };
    }

    if (/^(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)+$/i.test(password)) {
      return {
        isCommon: true,
        message: 'Password contains sequential patterns'
      };
    }

    return { isCommon: false };
  },

  // Generate strong password suggestion
  generateStrongPassword(length = 16) {
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const special = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    const allChars = lowercase + uppercase + numbers + special;
    let password = '';
    
    // Ensure at least one of each type
    password += lowercase[Math.floor(Math.random() * lowercase.length)];
    password += uppercase[Math.floor(Math.random() * uppercase.length)];
    password += numbers[Math.floor(Math.random() * numbers.length)];
    password += special[Math.floor(Math.random() * special.length)];
    
    // Fill the rest randomly
    for (let i = password.length; i < length; i++) {
      password += allChars[Math.floor(Math.random() * allChars.length)];
    }
    
    // Shuffle the password
    return password.split('').sort(() => Math.random() - 0.5).join('');
  },
};

// Create global validator instance
const validator = new FormValidator();

// Debounce utility function
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
