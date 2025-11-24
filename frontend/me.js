async function loadProfile() {
  const box = document.getElementById("profile-box");

  try {
    const resp = await fetch("/api/me");
    const data = await resp.json();

    if (!resp.ok) {
      box.textContent = "Unable to load profile: " + JSON.stringify(data, null, 2);
      return;
    }

    box.innerHTML = `
      <strong>Username:</strong> ${data.username}<br>
      <strong>Full name:</strong> ${data.full_name || "—"}<br>
      <strong>Email:</strong> ${data.email || "—"}<br>
      <strong>Date of birth:</strong> ${data.dob || "—"}<br>
      <strong>Bio:</strong> ${data.bio || "—"}<br>
    `;
  } catch (err) {
    box.textContent = "Error loading profile: " + err;
  }
}

document.getElementById("logout-button").addEventListener("click", () => {
  document.cookie = "access_token=; Max-Age=0; Path=/;";
  window.location.href = "/";
});

loadProfile();