// Call /api/me and show the result in a log-style box
document.getElementById("me-button").addEventListener("click", async () => {
  try {
    const resp = await fetch("/api/me");
    const data = await resp.json();

    if (!resp.ok) {
      log(`/api/me failed: ${resp.status} ${JSON.stringify(data)}`);
      meOutput.textContent = JSON.stringify(data, null, 2);
    } else {
      log("/api/me OK");
      meOutput.textContent = JSON.stringify(data, null, 2);
    }
  } catch (err) {
    console.error(err);
    log(`/api/me error: ${err}`);
    meOutput.textContent = String(err);
  }
});