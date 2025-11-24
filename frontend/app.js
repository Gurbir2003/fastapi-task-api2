// Render the auth panel into the placeholder div
function renderAuthPanel() {
  const root = document.getElementById("auth-root");
  root.innerHTML = `
    <div class="grid auth-panel">
      <!-- Registration -->
      <div class="card auth-card">
        <h2 class="card-title">Register</h2>
        <p class="card-subtitle">Create a new Mini Insta account.</p>
        <form id="register-form">
          <label for="reg-username">Username</label>
          <input id="reg-username" name="username" required />

          <label for="reg-fullname">Full name</label>
          <input id="reg-fullname" name="full_name" placeholder="Optional" />

          <label for="reg-email">Email</label>
          <input id="reg-email" name="email" type="email" placeholder="you@example.com" />

          <label for="reg-dob">Date of birth</label>
          <input id="reg-dob" name="dob" type="date" />

          <label for="reg-bio">Bio</label>
          <input id="reg-bio" name="bio" placeholder="Tell us something about you" />

          <label for="reg-password">Password</label>
          <input id="reg-password" name="password" type="password" required />

          <button type="submit">Register</button>
        </form>
      </div>

      <!-- Login -->
      <div class="card auth-card">
        <h2 class="card-title">Login</h2>
        <p class="card-subtitle">Log in with your existing credentials.</p>
        <form id="login-form">
          <label for="login-username">Username</label>
          <input id="login-username" name="username" required />

          <label for="login-password">Password</label>
          <input id="login-password" name="password" type="password" required />

          <button type="submit">Login</button>
        </form>
      </div>
    </div>
  `;
}

// Render the component as soon as the script runs (script is at bottom of body)
renderAuthPanel();

const logEl = document.getElementById("log");
const tokenBox = document.getElementById("token-box");
const meOutput = document.getElementById("me-output");

let accessToken = null;

// Simple logger for the bottom log box
function log(message) {
  const timestamp = new Date().toLocaleTimeString();
  logEl.textContent += `[${timestamp}] ${message}\n`;
  logEl.scrollTop = logEl.scrollHeight;
}

// Handle registration form submission
document.getElementById("register-form").addEventListener("submit", async (e) => {
  e.preventDefault();

  const username = document.getElementById("reg-username").value.trim();
  const full_name = document.getElementById("reg-fullname").value.trim();
  const email = document.getElementById("reg-email").value.trim();
  const dob = document.getElementById("reg-dob").value;
  const bio = document.getElementById("reg-bio").value.trim();
  const password = document.getElementById("reg-password").value;

  if (!username || !password) {
    log("Registration: username and password required.");
    return;
  }

  try {
    // Backend expects:
    // - JSON body: { username, full_name, email, bio, dob }
    // - Query param: ?password=...
    const body = { username, full_name, email, bio, dob };
    const resp = await fetch(`/auth/register?password=${encodeURIComponent(password)}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });

    const data = await resp.json();

    if (!resp.ok) {
      log(`Registration failed: ${resp.status} ${JSON.stringify(data)}`);
    } else {
      log(`Registration OK: ${JSON.stringify(data)}`);
    }
  } catch (err) {
    console.error(err);
    log(`Registration error: ${err}`);
  }
});

// Handle login form submission
document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();

  const username = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value;

  if (!username || !password) {
    log("Login: username and password required.");
    return;
  }

  try {
    // OAuth2PasswordRequestForm expects form-encoded data
    const formData = new URLSearchParams();
    formData.append("username", username);
    formData.append("password", password);

    const resp = await fetch("/auth/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: formData.toString(),
    });

    const data = await resp.json();
    console.log(data);

    if (resp.ok) {
      accessToken = data.access_token;
      tokenBox.textContent = accessToken || "No token received.";
      log("Login OK – token received.");
      window.location.href = "/me";
    } else {
      log(`Login failed: ${resp.status} ${JSON.stringify(data)}`);
      accessToken = null;
      tokenBox.textContent = "No token (login failed).";
    }
  } catch (err) {
    console.error(err);
    log(`Login error: ${err}`);
  }
});

// Call /me and show the result in a log-style box
document.getElementById("me-button").addEventListener("click", async () => {
  if (!accessToken) {
    log("Cannot call /me: no access token (login first).");
    meOutput.textContent = "Please login first.";
    return;
  }

  try {
    const resp = await fetch("/me", {
      method: "GET",
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    const data = await resp.json();

    if (!resp.ok) {
      log(`/me failed: ${resp.status} ${JSON.stringify(data)}`);
      meOutput.textContent = JSON.stringify(data, null, 2);
    } else {
      log("/me OK");
      meOutput.textContent = JSON.stringify(data, null, 2);
    }
  } catch (err) {
    console.error(err);
    log(`/me error: ${err}`);
    meOutput.textContent = String(err);
  }
});