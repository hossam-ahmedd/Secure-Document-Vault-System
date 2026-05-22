const API_URL = "https://localhost:3000";

/* =========================
   Helper Functions
========================= */

function showMessage(elementId, message, type) {
  const el = document.getElementById(elementId);
  if (!el) return;

  el.className = type === "success" ? "message-success" : "message-error";
  el.textContent = message;
}

function getToken() {
  return localStorage.getItem("token");
}

function getUser() {
  return JSON.parse(localStorage.getItem("user") || "{}");
}

function authHeaders() {
  return {
    Authorization: `Bearer ${getToken()}`
  };
}

function protectPage() {
  const token = getToken();

  if (!token) {
    window.location.href = "index.html";
  }
}

function logout() {
  localStorage.removeItem("token");
  localStorage.removeItem("user");
  window.location.href = "index.html";
}

const logoutBtn = document.getElementById("logoutBtn");

if (logoutBtn) {
  logoutBtn.addEventListener("click", logout);
}

/* =========================
   REGISTER
========================= */

const registerForm = document.getElementById("registerForm");

if (registerForm) {
  registerForm.addEventListener("submit", async function (e) {
    e.preventDefault();

    const name = document.getElementById("registerName").value;
    const email = document.getElementById("registerEmail").value;
    const password = document.getElementById("registerPassword").value;

    try {
      const res = await fetch(`${API_URL}/register`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          name,
          email,
          password
        })
      });

      const data = await res.json();

      if (!res.ok) {
        showMessage(
          "registerMessage",
          data.error || data.message || "Registration failed",
          "error"
        );
        return;
      }

      showMessage(
        "registerMessage",
        data.message || "Registered successfully",
        "success"
      );

      setTimeout(() => {
        window.location.href = "index.html";
      }, 1000);
    } catch (err) {
      showMessage("registerMessage", "Cannot connect to server", "error");
    }
  });
}

/* =========================
   LOGIN + MFA VERIFY LOGIN
========================= */

let pendingMfaUserId = null;

const loginForm = document.getElementById("loginForm");

if (loginForm) {
  loginForm.addEventListener("submit", async function (e) {
    e.preventDefault();

    const email = document.getElementById("loginEmail").value;
    const password = document.getElementById("loginPassword").value;
    const otpCode = document.getElementById("otpCode")?.value;
    const mfaBox = document.getElementById("mfaBox");

    try {
      if (pendingMfaUserId) {
        const res = await fetch(`${API_URL}/mfa/verify-login`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            userId: pendingMfaUserId,
            token: otpCode
          })
        });

        const data = await res.json();

        if (!res.ok) {
          showMessage(
            "loginMessage",
            data.error || data.message || "Invalid OTP",
            "error"
          );
          return;
        }

        localStorage.setItem("token", data.token);
        localStorage.setItem("user", JSON.stringify(data.user));

        window.location.href = "dashboard.html";
        return;
      }

      const res = await fetch(`${API_URL}/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          email,
          password
        })
      });

      const data = await res.json();

      if (!res.ok) {
        showMessage(
          "loginMessage",
          data.error || data.message || "Login failed",
          "error"
        );
        return;
      }

      if (data.requiresMFA) {
        pendingMfaUserId = data.userId;

        if (mfaBox) {
          mfaBox.style.display = "block";
        }

        showMessage(
          "loginMessage",
          "Enter OTP from your Authenticator app",
          "success"
        );

        return;
      }

      localStorage.setItem("token", data.token);
      localStorage.setItem("user", JSON.stringify(data.user));

      window.location.href = "dashboard.html";
    } catch (err) {
      showMessage("loginMessage", "Cannot connect to server", "error");
    }
  });
}

/* =========================
   DASHBOARD
========================= */

if (window.location.pathname.includes("dashboard.html")) {
  protectPage();

  const user = getUser();

  const welcomeText = document.getElementById("welcomeText");
  const userRole = document.getElementById("userRole");
  const adminLink = document.getElementById("adminLink");

  if (welcomeText) {
    welcomeText.textContent = `Welcome, ${user.name || "User"} 👋`;
  }

  if (userRole) {
    userRole.textContent = user.role || "user";
  }

  if (adminLink && user.role !== "admin") {
    adminLink.style.display = "none";
  }

  loadDocuments();
}

/* =========================
   MFA SETUP + ENABLE
========================= */

const setupMfaBtn = document.getElementById("setupMfaBtn");
const enableMfaBtn = document.getElementById("enableMfaBtn");

if (setupMfaBtn) {
  setupMfaBtn.addEventListener("click", async function () {
    try {
      const res = await fetch(`${API_URL}/mfa/setup`, {
        method: "POST",
        headers: authHeaders()
      });

      const data = await res.json();

      if (!res.ok) {
        showMessage(
          "mfaMessage",
          data.error || data.message || "MFA setup failed",
          "error"
        );
        return;
      }

      document.getElementById("mfaSetupBox").style.display = "block";
      document.getElementById("mfaQrCode").src = data.qrCodeUrl;

      showMessage("mfaMessage", "Scan QR code then enter OTP", "success");
    } catch (err) {
      showMessage("mfaMessage", "Cannot setup MFA", "error");
    }
  });
}

if (enableMfaBtn) {
  enableMfaBtn.addEventListener("click", async function () {
    const token = document.getElementById("mfaToken").value;

    if (!token) {
      showMessage("mfaMessage", "Please enter OTP code", "error");
      return;
    }

    try {
      const res = await fetch(`${API_URL}/mfa/enable`, {
        method: "POST",
        headers: {
          ...authHeaders(),
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          token
        })
      });

      const data = await res.json();

      if (!res.ok) {
        showMessage(
          "mfaMessage",
          data.error || data.message || "Invalid OTP",
          "error"
        );
        return;
      }

      showMessage(
        "mfaMessage",
        data.message || "MFA enabled successfully",
        "success"
      );

      const user = getUser();
      user.twoFactorEnabled = true;
      localStorage.setItem("user", JSON.stringify(user));
    } catch (err) {
      showMessage("mfaMessage", "Cannot enable MFA", "error");
    }
  });
}

/* =========================
   FILE UPLOAD
========================= */

const uploadForm = document.getElementById("uploadForm");

if (uploadForm) {
  uploadForm.addEventListener("submit", async function (e) {
    e.preventDefault();

    const fileInput = document.getElementById("fileInput");

    if (!fileInput.files[0]) {
      showMessage("uploadMessage", "Please select a file first", "error");
      return;
    }

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);

    try {
      const res = await fetch(`${API_URL}/upload`, {
        method: "POST",
        headers: authHeaders(),
        body: formData
      });

      const data = await res.json();

      if (!res.ok) {
        showMessage(
          "uploadMessage",
          data.error || data.message || "Upload failed",
          "error"
        );
        return;
      }

      showMessage(
        "uploadMessage",
        `${data.message} | Hash: ${data.hash}`,
        "success"
      );

      fileInput.value = "";
      loadDocuments();
    } catch (err) {
      showMessage("uploadMessage", "Cannot connect to server", "error");
    }
  });
}

/* =========================
   DOCUMENTS
========================= */

const refreshDocsBtn = document.getElementById("refreshDocsBtn");

if (refreshDocsBtn) {
  refreshDocsBtn.addEventListener("click", loadDocuments);
}

async function loadDocuments() {
  const documentsList = document.getElementById("documentsList");
  if (!documentsList) return;

  documentsList.innerHTML = "";

  try {
    const res = await fetch(`${API_URL}/documents`, {
      headers: authHeaders()
    });

    const data = await res.json();

    if (!res.ok) {
      documentsList.innerHTML = `
        <div class="doc-card">
          <h3>Documents Error</h3>
          <p>${data.message || "Could not load documents"}</p>
        </div>
      `;
      return;
    }

    if (data.length === 0) {
      documentsList.innerHTML = `
        <div class="doc-card">
          <h3>No documents found</h3>
          <p>Upload your first secure document.</p>
        </div>
      `;
      return;
    }

    data.forEach((doc) => {
      const card = document.createElement("div");
      card.className = "doc-card";

      card.innerHTML = `
        <h3>📄 ${doc.originalName}</h3>
        <p><strong>Encrypted:</strong> ${doc.encrypted ? "Yes" : "No"}</p>
        <p class="hash-text"><strong>Hash:</strong> ${doc.hash}</p>

        <div class="doc-actions">
          <button onclick="verifyDocument('${doc._id}')">Verify</button>
          <button onclick="downloadDocument('${doc._id}', '${doc.originalName}')">Download</button>
          <button class="danger" onclick="deleteDocument('${doc._id}')">Delete</button>
        </div>
      `;

      documentsList.appendChild(card);
    });
  } catch (err) {
    documentsList.innerHTML = `
      <div class="doc-card">
        <h3>Connection Error</h3>
        <p>Cannot connect to backend server.</p>
      </div>
    `;
  }
}

async function verifyDocument(id) {
  try {
    const res = await fetch(`${API_URL}/documents/${id}/verify`, {
      headers: authHeaders()
    });

    const data = await res.json();

    if (!res.ok) {
      showMessage(
        "documentsMessage",
        data.error || data.message || "Verification failed",
        "error"
      );
      return;
    }

    showMessage(
      "documentsMessage",
      `Result: ${data.result} | Hash Match: ${data.hashMatches} | Signature Valid: ${data.signatureValid}`,
      "success"
    );
  } catch (err) {
    showMessage("documentsMessage", "Cannot verify document", "error");
  }
}

async function downloadDocument(id, fileName) {
  try {
    const res = await fetch(`${API_URL}/documents/${id}/download`, {
      headers: authHeaders()
    });

    if (!res.ok) {
      showMessage("documentsMessage", "Download failed", "error");
      return;
    }

    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);

    const link = document.createElement("a");
    link.href = url;
    link.download = fileName || "document";
    document.body.appendChild(link);
    link.click();
    link.remove();

    window.URL.revokeObjectURL(url);
  } catch (err) {
    showMessage("documentsMessage", "Cannot download document", "error");
  }
}

async function deleteDocument(id) {
  const confirmDelete = confirm("Are you sure you want to delete this document?");

  if (!confirmDelete) return;

  try {
    const res = await fetch(`${API_URL}/documents/${id}`, {
      method: "DELETE",
      headers: authHeaders()
    });

    const data = await res.json();

    if (!res.ok) {
      showMessage(
        "documentsMessage",
        data.error || data.message || "Delete failed",
        "error"
      );
      return;
    }

    showMessage(
      "documentsMessage",
      data.message || "Document deleted successfully",
      "success"
    );

    loadDocuments();
  } catch (err) {
    showMessage("documentsMessage", "Cannot delete document", "error");
  }
}

/* =========================
   ADMIN PANEL
========================= */

if (window.location.pathname.includes("admin.html")) {
  protectPage();

  const user = getUser();

  if (user.role !== "admin") {
    alert("Access denied. Admin only.");
    window.location.href = "dashboard.html";
  }

  loadUsers();
}

const refreshUsersBtn = document.getElementById("refreshUsersBtn");

if (refreshUsersBtn) {
  refreshUsersBtn.addEventListener("click", loadUsers);
}

async function loadUsers() {
  const usersTable = document.getElementById("usersTable");
  if (!usersTable) return;

  usersTable.innerHTML = "";

  try {
    const res = await fetch(`${API_URL}/admin/users`, {
      headers: authHeaders()
    });

    const data = await res.json();

    if (!res.ok) {
      showMessage(
        "adminMessage",
        data.error || data.message || "Could not load users",
        "error"
      );
      return;
    }

    data.forEach((user) => {
      const row = document.createElement("tr");

      row.innerHTML = `
        <td>${user.name}</td>
        <td>${user.email}</td>
        <td>
          <span class="role-badge role-${user.role}">
            ${user.role}
          </span>
        </td>
        <td>
          <select onchange="changeUserRole('${user._id}', this.value)">
            <option value="user" ${user.role === "user" ? "selected" : ""}>user</option>
            <option value="manager" ${user.role === "manager" ? "selected" : ""}>manager</option>
            <option value="admin" ${user.role === "admin" ? "selected" : ""}>admin</option>
          </select>
        </td>
      `;

      usersTable.appendChild(row);
    });
  } catch (err) {
    showMessage("adminMessage", "Cannot connect to server", "error");
  }
}

async function changeUserRole(id, role) {
  try {
    const res = await fetch(`${API_URL}/admin/users/${id}/role`, {
      method: "PATCH",
      headers: {
        ...authHeaders(),
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ role })
    });

    const data = await res.json();

    if (!res.ok) {
      showMessage(
        "adminMessage",
        data.error || data.message || "Role update failed",
        "error"
      );
      return;
    }

    showMessage(
      "adminMessage",
      data.message || "Role updated successfully",
      "success"
    );

    loadUsers();
  } catch (err) {
    showMessage("adminMessage", "Cannot update role", "error");
  }
}