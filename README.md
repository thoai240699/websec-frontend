# BÁO CÁO DỰ ÁN WEBSEC FRONTEND

## I. TỔNG QUAN DỰ ÁN

WebSec Frontend là một ứng dụng quản lý nghiệp vụ bảo mật với kiểm soát truy cập dựa trên vai trò (Role-Based Access Control), được thiết kế và phát triển nhằm cung cấp giao diện người dùng hiện đại để tương tác với WebSec Backend API. Dự án được xây dựng với trọng tâm là ba yếu tố chính: bảo mật toàn diện, trải nghiệm người dùng tối ưu và khả năng phản hồi trên đa dạng các thiết bị từ mobile đến desktop.

## II. CHỨC NĂNG CHÍNH CỦA HỆ THỐNG

Dự án WebSec Frontend được xây dựng với chín nhóm chức năng chính, bao gồm hệ thống quản lý xác thực và phân quyền, quản lý hồ sơ người dùng, quản lý nghiệp vụ, dashboard quản trị, dashboard quản lý, nhật ký hoạt động, bảo mật và xác thực, giao diện và trải nghiệm người dùng, cùng với các tính năng nâng cao khác.

### 2.1. Hệ thống Quản lý Xác thực và Phân quyền

Hệ thống xác thực của dự án được thiết kế với cơ chế đăng ký tài khoản cho phép người dùng mới tạo tài khoản với xác thực mạnh mẽ. Tính năng đăng nhập người dùng sử dụng xác thực JWT (JSON Web Token) để đảm bảo bảo mật token trong suốt phiên làm việc. Đặc biệt, hệ thống cung cấp portal đăng nhập riêng biệt cho quản trị viên, giúp phân tách rõ ràng quyền hạn và nâng cao tính bảo mật. Quản lý phiên làm việc được tự động hóa với cơ chế logout tự động khi token hết hạn, đồng thời kiểm soát truy cập được phân quyền chặt chẽ theo vai trò gồm CUSTOMER, ADMIN, MANAGER và STAFF.

**Code minh họa - Authentication Utilities (`assets/js/auth.js`):**

```javascript
const Auth = {
  // Lưu thông tin xác thực
  saveAuth(token, userData, roles) {
    localStorage.setItem(STORAGE_KEYS.TOKEN, token);
    localStorage.setItem(STORAGE_KEYS.USER_DATA, JSON.stringify(userData));
    localStorage.setItem(STORAGE_KEYS.USER_ROLE, JSON.stringify(roles));
  },

  // Kiểm tra xác thực
  isAuthenticated() {
    return !!this.getToken();
  },

  // Kiểm tra vai trò
  hasRole(role) {
    const roles = this.getUserRoles();
    return roles.includes(role);
  },

  // Yêu cầu quyền Admin
  requireAdmin() {
    if (!this.isAuthenticated() || !this.hasRole('ADMIN')) {
      window.location.href = '/pages/admin-login.html';
      return false;
    }
    return true;
  },

  // Logout
  logout() {
    localStorage.removeItem(STORAGE_KEYS.TOKEN);
    localStorage.removeItem(STORAGE_KEYS.USER_DATA);
    localStorage.removeItem(STORAGE_KEYS.USER_ROLE);
    window.location.href = '/index.html';
  }
};
```

### 2.2. Module Quản lý Hồ sơ Người dùng

Module này cung cấp các chức năng cơ bản để người dùng xem và quản lý thông tin cá nhân. Người dùng có thể xem toàn bộ thông tin cá nhân bao gồm tên đăng nhập/email, họ tên đầy đủ, ngày sinh và vai trò trong hệ thống. Hệ thống cho phép cập nhật hồ sơ với các trường thông tin như họ tên và ngày sinh. Vai trò người dùng được hiển thị dưới dạng badge màu sắc phân biệt (ADMIN-đỏ, MANAGER-vàng, STAFF-xanh dương, CUSTOMER-xanh lá). Lưu ý: Tính năng upload avatar và hiển thị chi tiết quyền hạn đang trong giai đoạn phát triển.

### 2.3. Hệ thống Quản lý Nghiệp vụ (Business)

Module này cung cấp khung giao diện cơ bản cho quản lý nghiệp vụ với ba phân hệ chính. Hệ thống được tổ chức theo tab navigation bao gồm Product (Sản phẩm), Order (Đơn hàng) và Basement (Kho - chỉ hiển thị cho STAFF và ADMIN). Mỗi tab có kiểm tra quyền truy cập (Access Control) trước khi cho phép tương tác. Hiện tại, giao diện đã hoàn thiện việc phân quyền và kiểm soát truy cập cho từng module. **Lưu ý quan trọng**: Các tính năng CRUD (Create, Read, Update, Delete) đầy đủ cho sản phẩm, đơn hàng và quản lý kho; form nhập liệu chi tiết; bảng hiển thị danh sách; và lịch sử giao dịch đang trong giai đoạn phát triển và chưa được triển khai hoàn chỉnh.

### 2.4. Dashboard Quản trị (Admin)

Dashboard Admin cung cấp giao diện tổng quan với các tính năng quản lý cơ bản. **Đã triển khai**: Giao diện statistics cards hiển thị Total Users, Total Businesses, Pending Items và Completed Items với icons và màu sắc phân biệt; Module quản lý nghiệp vụ cho phép admin tạo mới business với form đầy đủ (name, type, amount, status, description) và xem danh sách business trong bảng với badge status; System Activity hiển thị 10 hoạt động gần nhất dưới dạng timeline với action badges và time ago format. **Đang phát triển**: Module quản lý người dùng (xem danh sách users, thông tin chi tiết); Tính năng cấp/thu hồi quyền admin cho users (API đã có, UI chưa triển khai); Báo cáo thống kê và phân tích với charts/graphs; Real-time statistics (hiện tại các số liệu statistics đang ở mức cơ bản).

### 2.5. Dashboard Quản lý (Manager)

Dashboard Manager được thiết kế hoàn chỉnh cho vai trò quản lý nhân sự và phân quyền. **Đã triển khai đầy đủ**: Form đăng ký nhân viên mới với các trường username, password, full name và email; Danh sách staff hiển thị trong bảng với các cột Username, Full Name, Email, Roles (badge màu sắc), Status (Active/Inactive badge) và nút Actions; Tính năng Grant Admin cho phép cấp quyền ADMIN cho staff thông qua modal xác nhận; Tính năng Revoke Admin để thu hồi quyền admin với modal xác nhận; Refresh button để tải lại danh sách staff; API integration hoàn chỉnh với getStaffList(), registerStaff(), grantAdminRole() và revokeAdminRole(). Người dùng cần có vai trò MANAGER để truy cập trang này.

### 2.6. Hệ thống Nhật ký Hoạt động (Activity Log)

Module Activity Log đã được triển khai hoàn chỉnh để theo dõi và ghi lại mọi thao tác trong hệ thống. **Đã triển khai đầy đủ**: Filter dropdown cho Action (All Actions, CREATE, READ, UPDATE, DELETE, LOGIN, LOGOUT) và Entity (All Entities, Admin, User, Business); Statistics cards hiển thị Total Activities, Today và This Hour với real-time counting; Timeline visualization với từng activity item hiển thị action badge màu sắc (success-xanh, info-xanh dương, warning-vàng, danger-đỏ, primary-xanh đậm), entity name, description, time ago format và user ID; Activity details modal hiển thị đầy đủ Basic Information (Action, Entity, User ID, Time, Description) và Before/After changes trong format JSON; Icon system với emoji cho từng loại action (➕ CREATE, 👁️ READ, ✏️ UPDATE, 🗑️ DELETE, 🔓 LOGIN, 🔒 LOGOUT); Refresh button để tải lại logs; API integration với getActivityLogs(). Chỉ MANAGER và ADMIN mới có quyền truy cập.

### 2.7. Hệ thống Bảo mật và Xác thực

Bảo mật là một trong những ưu tiên hàng đầu của dự án, được triển khai qua nhiều lớp bảo vệ toàn diện với 8 cơ chế bảo mật chính:

**1. JWT Authentication** - Xác thực dựa trên JSON Web Token với Bearer token được gửi trong Authorization header cho mọi request cần xác thực.

**2. CSRF Protection** - Token CSRF 256-bit được tạo bằng `crypto.getRandomValues()`, lưu trong sessionStorage và tự động đính kèm X-CSRF-Token header cho mọi request nhằm ngăn chặn Cross-Site Request Forgery.

**3. XSS Prevention** - Input sanitization nghiêm ngặt với HTML escaping tự động, phát hiện các pattern nguy hiểm (script tags, event handlers, javascript: protocol).

**4. Rate Limiting** - Giới hạn số lượng request trong time window để chống brute force và DDoS attacks (mặc định: 5 attempts/60 seconds).

**5. CSP Headers & Injection Detection** - Content Security Policy headers và pattern matching để phát hiện suspicious input (XSS, SQL injection, script injection).

**6. Entropy-based Password Strength** - Đánh giá độ mạnh mật khẩu theo công thức khoa học L × log₂(N), **ưu tiên độ dài hơn độ phức tạp** (12 ký tự đơn giản > 8 ký tự phức tạp).

**7. Common Password Detection** - Kiểm tra 30+ mật khẩu phổ biến/rò rỉ, phát hiện pattern đơn giản (sequential: 123/abc, repeated: aaa/111).

**8. Real-time Validation** - Input validation real-time với debounced validation (500ms delay) để tối ưu hiệu năng và UX.

**Code minh họa - CSRF Protection (`assets/js/validation.js` & `assets/js/api.js`):**

```javascript
// SecurityUtils - CSRF Token Management (validation.js)
const SecurityUtils = {
  // Generate CSRF token using crypto.getRandomValues
  generateCSRFToken() {
    const array = new Uint8Array(32);  // 256-bit token
    crypto.getRandomValues(array);
    return Array.from(array, (byte) => 
      byte.toString(16).padStart(2, '0')
    ).join('');
  },

  // Store CSRF token in sessionStorage
  storeCSRFToken() {
    const token = this.generateCSRFToken();
    sessionStorage.setItem('csrf_token', token);
    return token;
  },

  // Get CSRF token (create if not exists)
  getCSRFToken() {
    let token = sessionStorage.getItem('csrf_token');
    if (!token) {
      token = this.storeCSRFToken();
    }
    return token;
  }
};

// APIService - Auto-attach CSRF token to requests (api.js)
class APIService {
  getHeaders(includeAuth = false) {
    const headers = {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest', // CSRF protection marker
    };

    if (includeAuth) {
      const token = localStorage.getItem(STORAGE_KEYS.TOKEN);
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
    }

    // Auto-attach CSRF token to all requests
    if (typeof SecurityUtils !== 'undefined') {
      const csrfToken = SecurityUtils.getCSRFToken();
      if (csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;  // CSRF token header
      }
    }

    return headers;
  }
}

// Usage: CSRF token is automatically initialized and sent
// In signup.html, login.html, etc:
SecurityUtils.storeCSRFToken();  // Initialize on page load
// Then all API calls automatically include X-CSRF-Token header
```

**Cơ chế hoạt động:**
1. **Token Generation**: Tạo 256-bit random token bằng `crypto.getRandomValues()` (cryptographically secure)
2. **Storage**: Lưu trong `sessionStorage` (tự động xóa khi đóng tab/browser)
3. **Auto-attach**: Mọi request tự động thêm `X-CSRF-Token` header
4. **Validation**: Backend verify token để đảm bảo request hợp lệ
5. **Protection**: Ngăn chặn attacker gửi request giả mạo từ site khác

---

#### 2.7.1. XSS Prevention - Input Sanitization

**Code minh họa (`assets/js/validation.js`):**

```javascript
class FormValidator {
  // Sanitize input để ngăn chặn XSS attacks
  sanitizeInput(input) {
    if (typeof input !== 'string') return input;

    // Sử dụng browser's built-in HTML escaping
    const div = document.createElement('div');
    div.textContent = input;  // Tự động escape HTML entities
    return div.innerHTML;     // Trả về chuỗi đã escaped
  },

  // Sanitize HTML với whitelist tags được phép
  sanitizeHTML(html, allowedTags = []) {
    const div = document.createElement('div');
    div.innerHTML = html;

    if (allowedTags.length === 0) {
      return div.textContent || div.innerText || '';  // Strip toàn bộ HTML
    }

    // Xóa các tag không được phép
    const allElements = div.querySelectorAll('*');
    allElements.forEach((el) => {
      if (!allowedTags.includes(el.tagName.toLowerCase())) {
        el.replaceWith(el.textContent);  // Thay thế bằng text only
      }
    });

    return div.innerHTML;
  }
}
```

**Usage:**
```javascript
const userInput = '<script>alert("XSS")</script>Hello';
const safe = validator.sanitizeInput(userInput);  
// Result: "&lt;script&gt;alert(\"XSS\")&lt;/script&gt;Hello"
```

---

#### 2.7.2. Rate Limiting - Anti Brute Force & DDoS

**Code minh họa (`assets/js/validation.js`):**

```javascript
const SecurityUtils = {
  rateLimiter: new Map(),

  // Kiểm tra xem action có vượt quá rate limit không
  isRateLimited(action, maxAttempts = 5, timeWindow = 60000) {
    const now = Date.now();
    const key = action;

    if (!this.rateLimiter.has(key)) {
      this.rateLimiter.set(key, []);
    }

    const attempts = this.rateLimiter.get(key);
    
    // Xóa các attempts cũ ngoài time window
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
  }
};
```

**Usage trong API calls:**
```javascript
// Giới hạn 5 lần đăng nhập trong 60 giây
const rateLimitCheck = SecurityUtils.isRateLimited('login', 5, 60000);
if (rateLimitCheck.limited) {
  throw new Error(rateLimitCheck.message);
}
```

---

#### 2.7.3. Suspicious Input Detection - Anti Injection

**Code minh họa (`assets/js/validation.js`):**

```javascript
const SecurityUtils = {
  // Phát hiện các pattern nguy hiểm (XSS, injection)
  detectSuspiciousInput(input) {
    const suspiciousPatterns = [
      /<script[^>]*>[\s\S]*?<\/script>/gi,  // Script tags
      /javascript:/gi,                      // JavaScript protocol
      /on\w+\s*=/gi,                        // Event handlers (onclick, onerror...)
      /<iframe/gi,                          // Iframe tags
      /data:text\/html/gi,                  // Data URLs
      /vbscript:/gi,                        // VBScript protocol
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
  }
};
```

**Usage:**
```javascript
const check = SecurityUtils.detectSuspiciousInput(userInput);
if (check.suspicious) {
  alert(check.message);
  return false;
}
```

---

#### 2.7.4. Common/Leaked Password Detection

**Code minh họa (`assets/js/validation.js`):**

```javascript
const SecurityUtils = {
  checkCommonPasswords(password) {
    const commonPasswords = [
      'password', '123456', '12345678', 'qwerty', 'abc123',
      'Password1', 'P@ssw0rd', 'Password123', 'admin', 'welcome',
      '1q2w3e4r', 'letmein', 'monkey', 'dragon', 'iloveyou',
      // ... 30+ common passwords
    ];

    const lowerPassword = password.toLowerCase();
    
    // Kiểm tra trùng khớp trực tiếp
    if (commonPasswords.some(common => lowerPassword === common.toLowerCase())) {
      return {
        isCommon: true,
        message: 'This password is too common and easily guessed'
      };
    }

    // Kiểm tra repeated characters: aaaa, 1111
    if (/^(.)\1+$/.test(password)) {
      return {
        isCommon: true,
        message: 'Password cannot be all the same character'
      };
    }

    // Kiểm tra sequential patterns: 123, abc, 456
    if (/^(012|123|234|345|456|567|678|789|abc|bcd|cde)+$/i.test(password)) {
      return {
        isCommon: true,
        message: 'Password contains sequential patterns'
      };
    }

    return { isCommon: false };
  }
};
```

**Usage:**
```javascript
const check = SecurityUtils.checkCommonPasswords('Password123');
if (check.isCommon) {
  alert(check.message);  // "This password is too common and easily guessed"
}
```

---

#### 2.7.5. Real-time Validation với Debouncing

**Code minh họa (`assets/js/validation.js`):**

```javascript
class FormValidator {
  addLiveValidation(fieldElement, validationRules) {
    let feedbackElement = fieldElement.parentElement.querySelector('.form-feedback');
    if (!feedbackElement) {
      feedbackElement = this.createFeedbackElement();
      fieldElement.parentElement.appendChild(feedbackElement);
    }

    const validateField = () => {
      // Thực hiện validation logic...
      this.updateFieldValidation(fieldElement, feedbackElement, isValid, message);
    };

    // Validate ngay khi blur (immediate feedback)
    fieldElement.addEventListener('blur', validateField);
    
    // Validate khi typing với debounce 500ms (tối ưu performance)
    fieldElement.addEventListener('input', debounce(validateField, 500));
  }
}

// Debounce utility - Ngăn validate quá nhiều lần
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);  // Chờ 500ms sau lần gõ phím cuối
  };
}
```

**Benefits:**
- **Performance**: Giảm số lần validate từ hàng trăm xuống còn vài lần khi user typing
- **UX**: Không hiện error liên tục trong khi đang gõ, chỉ validate sau khi user dừng 500ms
- **Resource**: Tiết kiệm CPU và network requests

---

**Code minh họa - Password Validation với Entropy (`assets/js/validation.js`):**

```javascript
class FormValidator {
  // Tính toán độ mạnh mật khẩu bằng Entropy (Entropy-based Password Strength)
  calculatePasswordStrength(password) {
    const length = password.length;
    
    // Xác định kích thước bộ ký tự (N)
    const checks = {
      lowercase: /[a-z]/.test(password),     // 26 ký tự
      uppercase: /[A-Z]/.test(password),     // 26 ký tự
      number: /\d/.test(password),           // 10 ký tự
      special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(password), // 32 ký tự
      spaces: /\s/.test(password),           // 1 ký tự
    };

    let charsetSize = 0;
    if (checks.lowercase) charsetSize += 26;
    if (checks.uppercase) charsetSize += 26;
    if (checks.number) charsetSize += 10;
    if (checks.special) charsetSize += 32;
    if (checks.spaces) charsetSize += 1;

    // Công thức Entropy: L × log₂(N)
    // L = độ dài mật khẩu, N = kích thước bộ ký tự
    const entropy = length * Math.log2(charsetSize);

    // Phân loại độ mạnh dựa trên Entropy (bits):
    // < 40 bits: Very Weak (dễ bị brute force)
    // 40-59 bits: Weak (có thể crack được)
    // 60-79 bits: Medium (đủ cho hầu hết mục đích)
    // 80-99 bits: Strong (khó crack)
    // >= 100 bits: Very Strong (cực kỳ khó crack)
    
    let level = 'very-weak';
    let label = 'Very Weak';
    
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

    // Khuyến nghị cải thiện
    const recommendations = [];
    if (length < 12) {
      recommendations.push('Sử dụng ít nhất 12 ký tự (độ dài quan trọng nhất!)');
    }
    if (length < 14 && !checks.special) {
      recommendations.push('Thêm ký tự đặc biệt hoặc tăng độ dài');
    }

    return {
      entropy: Math.round(entropy * 10) / 10,
      level,
      label,
      charsetSize,
      length,
      checks,
      recommendations,
      estimatedCrackTime: this.estimateCrackTime(entropy)
    };
  }

  // Ước tính thời gian crack (giả định 10 tỷ lần thử/giây - GPU hiện đại)
  estimateCrackTime(entropy) {
    const guessesPerSecond = 10e9;
    const possibleCombinations = Math.pow(2, entropy);
    const secondsToCrack = possibleCombinations / (2 * guessesPerSecond);

    if (secondsToCrack < 1) return 'Ngay lập tức';
    if (secondsToCrack < 60) return `${Math.round(secondsToCrack)} giây`;
    if (secondsToCrack < 3600) return `${Math.round(secondsToCrack / 60)} phút`;
    if (secondsToCrack < 86400) return `${Math.round(secondsToCrack / 3600)} giờ`;
    if (secondsToCrack < 31536000) return `${Math.round(secondsToCrack / 86400)} ngày`;
    if (secondsToCrack < 31536000 * 100) return `${Math.round(secondsToCrack / 31536000)} năm`;
    
    return 'Hàng thế kỷ+';
  }

  // Kiểm tra mật khẩu phổ biến/rò rỉ
  checkCommonPasswords(password) {
    const commonPasswords = [
      'password', '123456', '12345678', 'qwerty', 'abc123',
      'Password1', 'P@ssw0rd', 'Password123', 'admin', 'welcome'
      // ... danh sách mật khẩu phổ biến
    ];

    const lowerPassword = password.toLowerCase();
    
    // Kiểm tra trùng khớp trực tiếp
    if (commonPasswords.some(common => lowerPassword === common.toLowerCase())) {
      return {
        isCommon: true,
        message: 'Mật khẩu này quá phổ biến và dễ đoán'
      };
    }

    // Kiểm tra pattern đơn giản (123456, abcdef, aaaa...)
    if (/^(.)\1+$/.test(password)) {
      return {
        isCommon: true,
        message: 'Mật khẩu không thể là tất cả cùng ký tự'
      };
    }

    if (/^(012|123|234|345|456|567|678|789|abc|bcd|cde)+$/i.test(password)) {
      return {
        isCommon: true,
        message: 'Mật khẩu chứa chuỗi tuần tự'
      };
    }

    return { isCommon: false };
  }
}
```

**Ví dụ So sánh Entropy:**

| Mật khẩu | Bộ ký tự (N) | Độ dài (L) | Entropy (bits) | Cấp độ |
|----------|--------------|------------|----------------|---------|
| `abcdefghijkl` (12 ký tự, chỉ chữ thường) | 26 | 12 | **56.4 bits** | Weak |
| `AbCdEfGhIjKl` (12 ký tự, hoa + thường) | 52 | 12 | **70.3 bits** | Medium |
| `P@ssw0rd` (8 ký tự, phức tạp) | 94 | 8 | **52.4 bits** | Weak |
| `MeoYeuNangMuaThu2025!` (21 ký tự, passphrase) | 94 | 21 | **137.5 bits** | Very Strong |

**Kết luận quan trọng**: Mật khẩu 12 ký tự chỉ có chữ cái (70.3 bits) **mạnh hơn** mật khẩu 8 ký tự phức tạp (52.4 bits) → **Độ dài quan trọng hơn độ phức tạp!**

### 2.8. Giao diện và Trải nghiệm Người dùng

Giao diện người dùng được thiết kế theo triết lý responsive design, đảm bảo tương thích hoàn hảo trên mọi thiết bị từ mobile, tablet đến desktop. Đối với thiết bị di động, ứng dụng cung cấp menu hamburger để tối ưu hóa không gian hiển thị. Thiết kế UI hiện đại lấy cảm hứng từ Material Design mang lại trải nghiệm thẩm mỹ cao. Các trạng thái loading với spinner và feedback giúp người dùng biết được hệ thống đang xử lý. Toast Messages hiển thị thông báo thành công hoặc lỗi một cách rõ ràng và thân thiện. Form Validation thực hiện xác thực trực tiếp khi người dùng đang nhập liệu, giúp phát hiện lỗi sớm. Tính năng Password Visibility cho phép toggle (chuyển đổi) giữa hiển thị và ẩn mật khẩu. Hệ thống còn hỗ trợ accessibility với keyboard navigation và screen reader cho người dùng khuyết tật.

#### 2.8.1. Hướng dẫn Test Giao diện và UX

**A. Test Responsive Design**

**Cách 1: Sử dụng Browser DevTools (Chrome/Firefox)**
```
1. Mở trang web cần test (ví dụ: http://localhost:8000/pages/login.html)
2. Nhấn F12 hoặc Ctrl+Shift+I (Windows) / Cmd+Option+I (Mac)
3. Click vào icon "Toggle device toolbar" (Ctrl+Shift+M)
4. Chọn thiết bị để test:
   - Mobile: iPhone SE (375px), iPhone 12 Pro (390px), Samsung Galaxy S20 (360px)
   - Tablet: iPad (768px), iPad Pro (1024px)
   - Desktop: 1366px, 1920px
5. Test cả chế độ Portrait (dọc) và Landscape (ngang)
```

**Cách 2: Test thủ công với Resize Browser**
```
1. Mở browser ở chế độ windowed (không full screen)
2. Kéo góc browser để thay đổi kích thước
3. Kiểm tra breakpoints:
   - < 480px: Mobile small (menu hamburger phải hiện)
   - 481-768px: Mobile/Tablet (2-column grid)
   - 769-1024px: Tablet (3-column grid)
   - > 1024px: Desktop (full features)
4. Verify:
   ✓ Không có horizontal scroll bar
   ✓ Text readable (không quá nhỏ hoặc quá lớn)
   ✓ Buttons đủ lớn để tap (min 44x44px trên mobile)
   ✓ Images scale properly
```

**Cách 3: Test trên thiết bị thật**
```
1. Lấy IP máy đang chạy server:
   - Windows: ipconfig | Tìm IPv4 Address
   - Mac/Linux: ifconfig | Tìm inet
2. Trên mobile/tablet, truy cập: http://[YOUR_IP]:8000
   Ví dụ: http://192.168.1.100:8000
3. Test toàn bộ features trên thiết bị thật
```

---

**B. Test Menu Hamburger (Mobile)**

```
Test Steps:
1. Resize browser xuống < 768px (mobile view)
2. Verify:
   ✓ Menu hamburger icon (☰) hiện thị ở góc trên
   ✓ Desktop navigation menu bị ẩn
   
3. Click vào hamburger icon
4. Verify:
   ✓ Menu slide out/dropdown xuất hiện
   ✓ Tất cả navigation links hiển thị đầy đủ
   ✓ Menu có overlay/backdrop (làm tối background)
   
5. Click vào một menu item
6. Verify:
   ✓ Navigate đến trang đúng
   ✓ Menu tự động đóng sau khi chọn
   
7. Click outside menu (vào overlay)
8. Verify:
   ✓ Menu đóng lại
```

---

**C. Test Loading States & Spinner**

```javascript
// Test trong Browser Console
// 1. Test loading state manually
const showLoadingTest = () => {
  const btn = document.querySelector('button[type="submit"]');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Loading...';
  
  setTimeout(() => {
    btn.disabled = false;
    btn.innerHTML = 'Submit';
  }, 3000);
};

showLoadingTest();  // Run test
```

**Checklist khi test Login/Signup:**
```
1. Click nút "Login" hoặc "Sign Up"
2. Verify trong khi đang gửi request:
   ✓ Button disabled (không click được nhiều lần)
   ✓ Spinner icon xuất hiện
   ✓ Text thay đổi thành "Loading..." hoặc "Processing..."
   ✓ User không thể submit form lần 2
   
3. Sau khi request hoàn tất:
   ✓ Button enabled trở lại
   ✓ Spinner biến mất
   ✓ Text trở về "Login"/"Sign Up"
```

---

**D. Test Toast Messages**

```javascript
// Test Toast trong Browser Console
// 1. Success Toast
if (typeof showToast === 'function') {
  showToast('Login successful!', 'success');
}

// 2. Error Toast
if (typeof showToast === 'function') {
  showToast('Invalid credentials', 'error');
}

// 3. Warning Toast
if (typeof showToast === 'function') {
  showToast('Session will expire soon', 'warning');
}

// 4. Info Toast
if (typeof showToast === 'function') {
  showToast('Profile updated', 'info');
}
```

**Manual Test Checklist:**
```
1. Trigger action gây ra toast (login, signup, update profile)
2. Verify toast hiển thị:
   ✓ Position: Top-right hoặc top-center
   ✓ Color: Success (green), Error (red), Warning (yellow), Info (blue)
   ✓ Icon: ✓ (success), ✗ (error), ⚠ (warning), ℹ (info)
   ✓ Message rõ ràng, dễ hiểu
   ✓ Auto-dismiss sau 3-5 giây
   
3. Test multiple toasts:
   ✓ Stack properly (không overlap)
   ✓ Dismiss theo thứ tự FIFO (First In First Out)
   
4. Test manual close:
   ✓ Click vào nút X để đóng
   ✓ Toast biến mất với animation smooth
```

---

**E. Test Form Validation (Real-time)**

**Test Password Field:**
```
1. Mở trang signup.html
2. Click vào password field
3. Bắt đầu gõ từng ký tự: "Pass"
4. Verify:
   ✓ Không có error message ngay lập tức (debounced 500ms)
   
5. Dừng gõ 500ms
6. Verify:
   ✓ Error hiển thị: "Password must be at least 12 characters"
   ✓ Field border chuyển màu đỏ (invalid state)
   
7. Tiếp tục gõ thành: "Password123!"
8. Verify:
   ✓ Password strength meter cập nhật real-time
   ✓ Entropy bits hiển thị (ví dụ: "72.5 bits")
   ✓ Crack time estimate hiển thị
   ✓ Strength bar thay đổi màu: red → yellow → green
   ✓ Strength label: "Weak" → "Medium" → "Strong"
   
9. Blur (click ra ngoài field)
10. Verify:
    ✓ Validation chạy ngay lập tức (immediate)
    ✓ Error/success message rõ ràng
```

**Test Email Field:**
```
1. Gõ email không hợp lệ: "test@"
2. Wait 500ms (debounce)
3. Verify:
   ✓ Error: "Please enter a valid email address"
   ✓ Border đỏ
   
4. Gõ email hợp lệ: "test@example.com"
5. Verify:
   ✓ Error biến mất
   ✓ Border xanh (valid state)
   ✓ Checkmark icon xuất hiện (optional)
```

---

**F. Test Password Visibility Toggle**

```
Test Steps:
1. Tìm password input field (login hoặc signup page)
2. Verify initial state:
   ✓ Input type="password" (text bị ẩn: ●●●●●●)
   ✓ Icon "eye" hoặc "eye-slash" hiển thị
   
3. Gõ password: "MySecretPass123!"
4. Verify:
   ✓ Hiển thị dưới dạng dots: ●●●●●●●●●●●●●●●●
   
5. Click vào icon "eye"
6. Verify:
   ✓ Input type chuyển thành "text"
   ✓ Password hiển thị rõ: "MySecretPass123!"
   ✓ Icon thay đổi thành "eye-slash"
   
7. Click lại icon "eye-slash"
8. Verify:
   ✓ Input type trở về "password"
   ✓ Text lại bị ẩn: ●●●●●●●●●●●●●●●●
   ✓ Icon thay đổi về "eye"
```

---

**G. Test Accessibility (A11y)**

**Test 1: Keyboard Navigation**
```
1. Mở trang login.html
2. Chỉ dùng keyboard (KHÔNG dùng chuột):
   
   - Tab: Di chuyển focus đến field tiếp theo
   - Shift+Tab: Di chuyển focus về field trước
   - Enter: Submit form hoặc click button đang focus
   - Space: Toggle checkbox/radio button
   - Esc: Đóng modal/dropdown
   
3. Verify:
   ✓ Focus outline rõ ràng (border xanh hoặc glow effect)
   ✓ Thứ tự focus logic (username → password → submit button)
   ✓ Không có "keyboard trap" (focus bị kẹt)
   ✓ Modal có thể đóng bằng Esc
   ✓ Dropdown navigate bằng Arrow keys
```

**Test 2: Screen Reader Support**
```
Sử dụng screen reader để test:
- Windows: NVDA (free) hoặc JAWS
- Mac: VoiceOver (built-in, Cmd+F5)
- Chrome Extension: ChromeVox

Test checklist:
1. Bật screen reader
2. Navigate qua form
3. Verify screen reader đọc:
   ✓ Label của từng input field
   ✓ Placeholder text
   ✓ Error messages
   ✓ Button text
   ✓ Link text (descriptive, không phải "click here")
   
4. Check ARIA attributes:
   ✓ aria-label cho icons
   ✓ aria-describedby cho error messages
   ✓ aria-live cho dynamic content (toast)
   ✓ role="alert" cho error messages
```

**Test 3: Color Contrast**
```
Sử dụng tools:
- Chrome DevTools: Lighthouse → Accessibility audit
- Browser Extension: "WAVE Evaluation Tool"
- Online: WebAIM Contrast Checker

Verify:
✓ Text contrast ratio ≥ 4.5:1 (normal text)
✓ Large text (18pt+) contrast ratio ≥ 3:1
✓ Link color khác với text thường
✓ Error messages color + icon (không chỉ dựa vào màu)
```

**Test 4: Focus Management**
```
1. Open modal/dialog
2. Verify:
   ✓ Focus tự động vào modal
   ✓ Tab chỉ di chuyển trong modal (focus trap)
   ✓ Background không interact được
   
3. Close modal
4. Verify:
   ✓ Focus quay về element đã trigger modal
```

---

**H. Test Material Design Elements**

```
Visual Checklist:
1. Cards:
   ✓ Shadow elevation (box-shadow)
   ✓ Rounded corners (border-radius)
   ✓ Hover effect (shadow tăng)
   
2. Buttons:
   ✓ Ripple effect khi click
   ✓ Hover state (background darker)
   ✓ Disabled state (opacity 0.5, not clickable)
   
3. Inputs:
   ✓ Floating labels (label di chuyển lên khi focus)
   ✓ Underline animation
   ✓ Error state (red underline + shake animation)
   
4. Transitions:
   ✓ Smooth (duration 200-300ms)
   ✓ Easing function (ease-in-out)
   ✓ No janky animations
```

---

**I. Performance Testing**

```javascript
// Test trong Browser Console
// 1. Measure page load time
console.time('Page Load');
window.addEventListener('load', () => {
  console.timeEnd('Page Load');
  // Target: < 3 seconds
});

// 2. Test debounce effectiveness
let validationCount = 0;
const originalValidate = validator.validatePassword;
validator.validatePassword = function(...args) {
  validationCount++;
  console.log('Validation called:', validationCount, 'times');
  return originalValidate.apply(this, args);
};

// Gõ nhanh vào password field → validation count phải thấp (< 5 lần)
```

**Browser DevTools Performance:**
```
1. Mở DevTools → Performance tab
2. Click Record
3. Interact với trang (type, click, scroll)
4. Stop recording
5. Analyze:
   ✓ FPS ≥ 60 (smooth animations)
   ✓ No long tasks (> 50ms)
   ✓ No layout thrashing
```

---

**J. Cross-Browser Testing**

```
Test trên các browsers:
1. Chrome (latest)
2. Firefox (latest)
3. Safari (latest) - Mac/iOS
4. Edge (latest)
5. Mobile browsers:
   - Safari iOS
   - Chrome Android
   - Samsung Internet

Checklist cho mỗi browser:
✓ Layout hiển thị đúng
✓ CSS animations hoạt động
✓ Form validation hoạt động
✓ JavaScript không có errors (check Console)
✓ API calls thành công
✓ Local/Session storage hoạt động
```

### 2.9. Các Tính năng Nâng cao

Dự án còn tích hợp nhiều tính năng nâng cao nhằm nâng cao hiệu suất và trải nghiệm người dùng. Auto-logout tự động đăng xuất người dùng khi session hết hạn để đảm bảo bảo mật. Request Caching giúp cache các GET request để tối ưu hiệu năng và giảm tải cho server. Debounced Validation giảm số lần thực hiện validate khi người dùng đang typing, tiết kiệm tài nguyên. Error Handling được xử lý toàn diện với các thông báo lỗi rõ ràng và hướng dẫn khắc phục. Prevent Double Submit ngăn chặn việc gửi form nhiều lần do người dùng click liên tục. Common Password Check cảnh báo khi người dùng sử dụng các mật khẩu phổ biến dễ bị tấn công. Suspicious Input Detection tự động phát hiện các input có dấu hiệu nguy hiểm và cảnh báo kịp thời.

## III. CẤU TRÚC TỔ CHỨC DỰ ÁN

```
websec-frontend/
├── index.html                    # Trang chủ landing page
├── pages/                        # Các trang chức năng
│   ├── login.html               # Đăng nhập người dùng
│   ├── signup.html              # Đăng ký tài khoản
│   ├── admin-login.html         # Đăng nhập admin
│   ├── dashboard.html           # Dashboard người dùng
│   ├── profile.html             # Trang hồ sơ cá nhân
│   ├── business.html            # Quản lý nghiệp vụ
│   ├── admin-dashboard.html     # Dashboard admin
│   ├── manager.html             # Dashboard manager
│   └── activity.html            # Nhật ký hoạt động
├── assets/
│   ├── css/
│   │   └── styles.css           # CSS chính (responsive, modern design)
│   ├── js/
│   │   ├── config.js            # Cấu hình API endpoint
│   │   ├── api.js               # API service với caching & security
│   │   ├── auth.js              # Utilities xác thực
│   │   ├── validation.js        # Form validation & security utils
│   │   └── main.js              # JavaScript utilities chung
│   └── img/
│       └── favicon/             # Icons và manifest
└── README.md
```

## IV. CÔNG NGHỆ VÀ KIẾN TRÚC KỸ THUẬT

Dự án WebSec Frontend được xây dựng trên nền tảng công nghệ web hiện đại, sử dụng các tiêu chuẩn và best practices trong ngành phát triển phần mềm.

**Code minh họa - API Configuration (`assets/js/config.js`):**

```javascript
const API_CONFIG = {
  BASE_URL: 'http://localhost:3052',
  ENDPOINTS: {
    // Auth endpoints
    SIGNUP: '/api/auth/signup',
    LOGIN: '/api/auth/login',
    ADMIN_LOGIN: '/api/admin/auth/login',
    
    // User endpoints
    USER_PROFILE: '/api/user/profile',
    
    // Business endpoints
    BUSINESS: '/api/business',
    BUSINESS_PRODUCT: '/api/business/product',
    BUSINESS_ORDER: '/api/business/order',
    BUSINESS_BASEMENT: '/api/business/basement',
    
    // Manager endpoints
    MANAGER_STAFF_LIST: '/api/manager/admins',
    MANAGER_REGISTER_STAFF: '/api/manager/add-staff',
    MANAGER_GRANT_ADMIN: '/api/manager/grant-admin',
    MANAGER_REVOKE_ADMIN: '/api/manager/revoke-admin',
    MANAGER_LOGS: '/api/manager/logs'
  }
};

// Storage keys
const STORAGE_KEYS = {
  TOKEN: 'websec_token',
  USER_DATA: 'websec_user',
  USER_ROLE: 'websec_role'
};
```

### 4.1. Nền tảng Frontend Core

Về mặt cốt lõi, dự án sử dụng HTML5 với semantic markup để đảm bảo tính accessibility (khả năng tiếp cận) cho người dùng khuyết tật. CSS3 được triển khai với các tính năng tiên tiến như custom properties (CSS variables), Flexbox và Grid layout để tạo bố cục linh hoạt, cùng với các animations mượt mà nâng cao trải nghiệm người dùng. Về phía lập trình, dự án sử dụng Vanilla JavaScript thuần túy với cú pháp ES6+ hiện đại, kết hợp Async/Await pattern và Fetch API để xử lý các tác vụ bất đồng bộ và giao tiếp với server một cách hiệu quả.

### 4.2. Thiết kế và Trải nghiệm Người dùng

Triết lý thiết kế của dự án tuân theo responsive design với cách tiếp cận mobile-first, đảm bảo giao diện hoạt động tối ưu trên thiết bị di động trước, sau đó mở rộng lên các màn hình lớn hơn. Hệ thống CSS Variables được xây dựng thành một theming system hoàn chỉnh, cho phép dễ dàng customize màu sắc và giao diện theo nhu cầu. Modern UI được thiết kế theo card-based layout với các smooth transitions tạo cảm giác mượt mà và chuyên nghiệp. Icon system kết hợp giữa emoji icons và font icons để đảm bảo hiển thị đa dạng và phong phú.

### 4.3. Kiến trúc Bảo mật

Về mặt bảo mật, dự án triển khai nhiều lớp bảo vệ khác nhau. JWT Authentication sử dụng Bearer token được gửi trong header của mọi request có yêu cầu xác thực. CSRF Tokens được tạo và gửi qua X-CSRF-Token header để ngăn chặn các cuộc tấn công Cross-Site Request Forgery. Input Sanitization được thực hiện nghiêm ngặt để phòng chống XSS (Cross-Site Scripting). CSP Headers (Content Security Policy) được cấu hình để kiểm soát nguồn tài nguyên được phép load vào trang. Rate Limiting được triển khai ở phía client-side như một lớp bảo vệ bổ sung, giới hạn số lượng request trong một khoảng thời gian nhất định.

**Code minh họa - API Service với Security (`assets/js/api.js`):**

```javascript
class APIService {
  constructor() {
    this.baseURL = API_CONFIG.BASE_URL;
    this.requestCache = new Map();
    this.cacheTimeout = 5 * 60 * 1000; // 5 phút
  }

  // Tạo headers với authentication và security
  getHeaders(includeAuth = false) {
    const headers = {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest' // CSRF protection
    };

    if (includeAuth) {
      const token = localStorage.getItem(STORAGE_KEYS.TOKEN);
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
    }

    // Thêm CSRF token
    if (typeof SecurityUtils !== 'undefined') {
      const csrfToken = SecurityUtils.getCSRFToken();
      if (csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;
      }
    }

    return headers;
  }

  // Request method với security enhancements
  async request(endpoint, options = {}) {
    try {
      // Kiểm tra rate limiting
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

      const url = `${this.baseURL}${endpoint}`;
      const response = await fetch(url, {
        ...options,
        headers: this.getHeaders(options.auth),
        credentials: 'omit'
      });

      const data = await response.json();

      if (!response.ok) {
        // Xử lý lỗi theo mã status
        if (response.status === 401) {
          if (typeof Auth !== 'undefined' && Auth.isAuthenticated()) {
            Auth.logout();
            throw new Error('Session expired. Please login again.');
          }
          throw new Error(data.message || 'Authentication failed');
        } else if (response.status === 403) {
          throw new Error('Access denied. Insufficient permissions.');
        } else if (response.status === 429) {
          throw new Error('Too many requests. Please try again later.');
        }
        throw new Error(data.message || 'Request failed');
      }

      return data;
    } catch (error) {
      console.error('API Error:', error);
      throw error;
    }
  }

  // Login user
  async login(credentials) {
    return this.request(API_CONFIG.ENDPOINTS.LOGIN, {
      method: 'POST',
      body: JSON.stringify(credentials),
      auth: false
    });
  }

  // Get user profile
  async getUserProfile() {
    return this.request(API_CONFIG.ENDPOINTS.USER_PROFILE, {
      method: 'GET',
      auth: true,
      useCache: true
    });
  }
}

const API = new APIService();
```

## V. YÊU CẦU HỆ THỐNG VÀ TRIỂN KHAI

### 5.1. Yêu cầu Hệ thống

Để triển khai và vận hành ứng dụng WebSec Frontend, hệ thống cần đảm bảo các yêu cầu sau: WebSec Backend phải được cài đặt và đang chạy ở địa chỉ mặc định http://localhost:3052 hoặc địa chỉ khác được cấu hình trong file config. Về phía trình duyệt, ứng dụng yêu cầu các phiên bản hiện đại như Chrome 90 trở lên, Firefox 88 trở lên, hoặc Safari 14 trở lên để đảm bảo tương thích với các tính năng JavaScript ES6+ và CSS3 hiện đại.

### 5.2. Quy trình Cài đặt

Quy trình cài đặt dự án bao gồm bốn bước chính. Đầu tiên, thực hiện clone repository từ GitHub về máy local bằng lệnh `git clone https://github.com/thoai240699/websec-frontend.git` và di chuyển vào thư mục dự án. Bước thứ hai là cấu hình API endpoint nếu backend không chạy ở địa chỉ mặc định, bằng cách chỉnh sửa file `assets/js/config.js` và thay đổi giá trị BASE_URL trong object API_CONFIG. Bước thứ ba là chạy ứng dụng, có hai phương án: phương án đơn giản là mở trực tiếp file index.html bằng trình duyệt (sử dụng lệnh `open index.html` trên MacOS hoặc `start index.html` trên Windows), hoặc phương án được khuyến nghị là sử dụng local server như Python HTTP Server (`python -m http.server 8000`), Node.js HTTP Server (`npx http-server -p 8000`), hoặc Live Server extension trong VS Code. Cuối cùng, truy cập ứng dụng thông qua địa chỉ http://localhost:8000 trên trình duyệt.

## VI. TÍCH HỢP API VÀ GIAO TIẾP BACKEND

Hệ thống WebSec Frontend tương tác với backend thông qua một tập hợp các API endpoints được thiết kế theo chuẩn RESTful. Các endpoints này được phân chia thành bốn nhóm chính tương ứng với các chức năng của hệ thống.

Nhóm Authentication bao gồm ba endpoints chính: endpoint POST `/api/auth/signup` cho phép đăng ký tài khoản mới, endpoint POST `/api/auth/login` thực hiện đăng nhập cho người dùng thông thường, và endpoint POST `/api/admin/auth/login` dành riêng cho việc đăng nhập của quản trị viên.

Nhóm User Management cung cấp hai endpoints yêu cầu xác thực: endpoint GET `/api/user/profile` để lấy thông tin profile của người dùng hiện tại, và endpoint PUT `/api/user/profile` cho phép cập nhật thông tin profile.

Nhóm Business Operations bao gồm bốn endpoints: endpoint GET `/api/business` lấy danh sách nghiệp vụ của người dùng, endpoint POST `/api/business` tạo nghiệp vụ mới, endpoint GET `/api/admin/business` cho phép admin quản lý toàn bộ nghiệp vụ trong hệ thống, và endpoint POST `/api/admin/business` để admin tạo nghiệp vụ với quyền hạn cao hơn.

Nhóm Manager Operations dành cho vai trò quản lý với năm endpoints: GET `/api/manager/admins` lấy danh sách nhân viên, POST `/api/manager/add-staff` đăng ký staff mới, PUT `/api/manager/grant-admin/:id` cấp quyền admin cho nhân viên, PUT `/api/manager/revoke-admin/:id` thu hồi quyền admin, và GET `/api/manager/logs` lấy nhật ký hoạt động của hệ thống.

## VII. HƯỚNG DẪN SỬ DỤNG HỆ THỐNG

### 7.1. Quy trình Đăng ký và Đăng nhập

Quy trình đăng ký và đăng nhập được thiết kế đơn giản và thân thiện với người dùng. Người dùng mới truy cập trang chủ và click vào nút "Sign Up" để bắt đầu quá trình đăng ký. Trong form đăng ký, người dùng cần điền username và password với yêu cầu tối thiểu 8 ký tự. Hệ thống sẽ tự động hiển thị password strength meter để người dùng đánh giá độ mạnh của mật khẩu đang nhập. Sau khi submit form đăng ký thành công, hệ thống tự động chuyển người dùng sang trang login để đăng nhập với tài khoản vừa được tạo.

**Code minh họa - Login Handler:**

```javascript
// Xử lý đăng nhập
async function handleLogin(event) {
  event.preventDefault();
  
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  
  // Validate input
  const validator = new FormValidator();
  const passwordCheck = validator.validatePassword(password);
  
  if (!passwordCheck.valid) {
    showError(passwordCheck.message);
    return;
  }
  
  try {
    showLoading(true);
    
    // Gọi API đăng nhập
    const response = await API.login({ username, password });
    
    // Lưu thông tin xác thực
    Auth.saveAuth(
      response.data.token,
      response.data.user,
      response.data.roles
    );
    
    // Chuyển hướng dựa trên vai trò
    if (Auth.hasRole('ADMIN')) {
      window.location.href = '/pages/admin-dashboard.html';
    } else {
      window.location.href = '/pages/dashboard.html';
    }
    
  } catch (error) {
    showError(error.message);
  } finally {
    showLoading(false);
  }
}
```

### 7.2. Quản lý Hồ sơ Cá nhân

Để quản lý hồ sơ cá nhân, người dùng truy cập vào Dashboard và chọn menu Profile. Tại đây, người dùng có thể xem đầy đủ thông tin cá nhân bao gồm username, fullname, date of birth và roles được gán. Để cập nhật thông tin, người dùng nhập họ tên đầy đủ vào trường fullname, chọn ngày sinh từ date picker, sau đó click nút "Update Profile" để lưu thay đổi.

### 7.3. Thực hiện Nghiệp vụ

Chức năng nghiệp vụ được truy cập từ Dashboard thông qua menu Business. Giao diện được chia thành ba tab chính: Tab "Product" cho phép tạo sản phẩm mới bằng cách nhập tên sản phẩm (name), giá (price) và số lượng (quantity); Tab "Order" dùng để tạo đơn hàng với các thông tin product_id và quantity; Tab "Basement" phục vụ quản lý kho với các trường location và capacity. Tất cả lịch sử giao dịch được hiển thị ở bảng phía dưới các tab để người dùng dễ dàng theo dõi.

### 7.4. Quy trình Quản lý (Manager)

Manager Dashboard cung cấp bốn chức năng chính đã được triển khai đầy đủ. Staff List hiển thị danh sách chi tiết tất cả nhân viên trong bảng với đầy đủ thông tin username, full name, email, roles badges và status. Register Staff cho phép đăng ký tài khoản staff mới thông qua form với validation cho các trường username (bắt buộc), password (bắt buộc), full name (tùy chọn) và email (tùy chọn). Grant Admin/Revoke Admin là tính năng quan trọng với modal xác nhận giúp manager cấp quyền hoặc thu hồi quyền admin cho nhân viên một cách an toàn. Activity Logs link đến trang activity.html cung cấp khả năng theo dõi chi tiết mọi hoạt động diễn ra trong hệ thống với timeline visualization và filters.

### 7.5. Chức năng Quản trị (Admin)

Admin Dashboard hiện cung cấp các chức năng cơ bản cho quản trị hệ thống. **Đã có**: Statistics Overview với 4 cards hiển thị Total Users, Total Businesses, Pending Items và Completed Items (hiện tại chưa kết nối API real-time); Business Management cho phép admin tạo mới business thông qua form với đầy đủ trường name, type, amount, status, description và xem danh sách business trong bảng với badge status; System Activity hiển thị 10 hoạt động gần nhất dưới dạng timeline với action badges và time ago format. **Đang phát triển**: User Management module để quản lý toàn bộ người dùng; Tính năng Grant/Revoke Admin trực tiếp từ Admin Dashboard (API đã có nhưng UI chưa triển khai); Reports & Analytics với charts/graphs; Real-time statistics API integration.

## VIII. CHIẾN LƯỢC BẢO MẬT

### 8.1. Luồng Xác thực (Authentication Flow)

Hệ thống xác thực được thiết kế theo bốn bước chặt chẽ. Bước đầu tiên, khi user đăng nhập thành công, server sẽ trả về một JWT token duy nhất cho phiên làm việc đó. Bước thứ hai, token này được lưu trữ an toàn trong localStorage của trình duyệt. Bước thứ ba, mỗi khi gửi request đến server, token sẽ được đính kèm trong header với format Authorization: Bearer <token>. Bước cuối cùng, khi token hết hạn và server trả về mã lỗi 401, hệ thống tự động thực hiện logout và redirect người dùng về trang login.

### 8.2. Các Tính năng Bảo mật

Dự án triển khai một hệ thống bảo mật đa lớp bao gồm nhiều tính năng quan trọng. Password hashing sử dụng thuật toán Bcrypt được thực hiện trên backend để bảo vệ mật khẩu người dùng. JWT tokens được cấu hình với expire time hợp lý và lưu trữ an toàn. CSRF protection thông qua token validation ngăn chặn các cuộc tấn công giả mạo request. XSS prevention được đảm bảo bằng input sanitization trên mọi dữ liệu đầu vào. SQL injection được ngăn chặn thông qua parameterized queries trên backend. Rate limiting được triển khai để ngăn chặn các cuộc tấn công brute force. CSP headers được cấu hình để ngăn chặn các injection attacks.

### 8.3. Best Practices trong Phát triển

Dự án tuân theo các best practices nghiêm ngặt về bảo mật. Thứ nhất, mọi input từ người dùng đều phải được sanitize thông qua hàm `validator.sanitizeInput(userInput)` trước khi xử lý. Thứ hai, dữ liệu luôn được validate trước khi gửi lên server bằng cách sử dụng `validator.validateForm(form, rules)` để kiểm tra tính hợp lệ và nhận về danh sách errors nếu có. Thứ ba, hệ thống kiểm tra suspicious input thông qua `SecurityUtils.detectSuspiciousInput(input)` để phát hiện các mẫu nguy hiểm. Thứ tư, rate limits được respect nghiêm ngặt thông qua `SecurityUtils.isRateLimited('action', 5, 60000)` để kiểm soát số lượng hành động trong khoảng thời gian cho phép.

## IX. TÍNH TƯƠNG THÍCH VÀ RESPONSIVE

### 9.1. Responsive Breakpoints

Hệ thống được thiết kế theo chiến lược Mobile First với bốn breakpoint chính. Mức default cho màn hình nhỏ hơn 480px sử dụng single column layout tối ưu cho thiết bị nhỏ. Mức mobile từ 481px đến 768px được tối ưu hóa đặc biệt cho điện thoại thông minh. Mức tablet từ 769px đến 1024px sử dụng 2-column layouts để tận dụng không gian màn hình trung bình. Mức desktop lớn hơn 1024px cung cấp đầy đủ tính năng với layout phức tạp và nhiều thông tin hiển thị cùng lúc.

**Code minh họa - Responsive CSS (`assets/css/styles.css`):**

```css
/* Mobile First - Default styles cho mobile */
.container {
  width: 100%;
  padding: 1rem;
  margin: 0 auto;
}

.card-grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: 1rem;
}

/* Tablet (481px - 768px) */
@media (min-width: 481px) {
  .container {
    max-width: 720px;
    padding: 1.5rem;
  }
  
  .card-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

/* Desktop (769px+) */
@media (min-width: 769px) {
  .container {
    max-width: 1200px;
    padding: 2rem;
  }
  
  .card-grid {
    grid-template-columns: repeat(3, 1fr);
    gap: 2rem;
  }
  
  /* Hide mobile menu, show desktop nav */
  .mobile-menu-toggle {
    display: none;
  }
  
  .nav-menu {
    display: flex;
    flex-direction: row;
  }
}

/* Form Responsive */
.form-group {
  margin-bottom: 1rem;
}

@media (min-width: 769px) {
  .form-row {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 1rem;
  }
}
```

### 9.2. Khả năng Tương thích Trình duyệt

Dự án đảm bảo tương thích đầy đủ với các trình duyệt hiện đại. Chrome từ phiên bản 90 trở lên được hỗ trợ hoàn toàn (Full Support). Firefox từ phiên bản 88 trở lên cũng được hỗ trợ đầy đủ. Safari từ phiên bản 14 trở lên hoạt động ổn định trên các thiết bị Apple. Microsoft Edge từ phiên bản 90 trở lên được hỗ trợ hoàn chình. Đặc biệt, Mobile Safari trên iOS 14 trở lên và Chrome Android từ phiên bản 90 trở lên đều được tối ưu hóa để đảm bảo trải nghiệm tốt nhất trên thiết bị di động.

## X. XỬ LÝ SỰ CỐ VÀ TROUBLESHOOTING

### 10.1. Vấn đề Kết nối API

Khi gặp vấn đề không kết nối được với API, cần thực hiện ba bước kiểm tra. Đầu tiên, xác minh backend đang chạy bằng cách truy cập trực tiếp địa chỉ http://localhost:3052 trên trình duyệt. Thứ hai, kiểm tra CORS settings trên backend để đảm bảo frontend được phép gửi request. Thứ ba, verify giá trị API_CONFIG.BASE_URL trong file config.js khớp với địa chỉ backend đang chạy.

### 10.2. Vấn đề Đăng nhập

Khi login không thành công, có ba phương pháp xử lý. Cách đầu tiên là clear localStorage bằng lệnh `localStorage.clear()` trong Console để xóa các token cũ có thể gây xung đột. Cách thứ hai là kiểm tra kỹ username và password đã nhập đúng chưa, lưu ý về chữ hoa chữ thường. Cách cuối cùng là mở Console của trình duyệt để xem các error message chi tiết giúp debug.

### 10.3. Vấn đề Token Hết hạn

Khi token hết hạn, hệ thống được thiết kế để tự động xử lý theo hai bước. Bước đầu tiên, hệ thống tự động thực hiện logout và xóa token cũ khỏi localStorage. Bước thứ hai, người dùng được redirect về trang login và cần đăng nhập lại để nhận token mới.

### 10.4. Lỗi Validation Form

Khi gặp lỗi validation form, cần thực hiện ba bước kiểm tra. Đầu tiên, check Console của trình duyệt để xem error message cụ thể. Thứ hai, đảm bảo file validation.js đã được load thành công bằng cách kiểm tra trong tab Network. Thứ ba, verify rằng dữ liệu input đáp ứng đầy đủ các yêu cầu về độ dài, format và các ràng buộc khác.

