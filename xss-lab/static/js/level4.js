// Level 4 — DOM-based XSS
//
// Source: window.location.hash  (e.g. #name=<payload>)
// Sink:   element.innerHTML
//
// INTENTIONAL VULNERABILITY:
// The fragment after #name= is decoded and written straight into the page
// using innerHTML. Fragments never reach the server, so this bug can only
// be found and fixed by reading the client-side JavaScript, not by
// inspecting server logs or responses.

function renderWelcome() {
    const hash = window.location.hash; // e.g. "#name=world"
    const match = hash.match(/name=(.*)$/);
    const rawName = match ? decodeURIComponent(match[1]) : "";

    const el = document.getElementById("welcome-box");
    if (!rawName) {
        el.textContent = "Welcome! Add #name=yourname to the URL to personalize this page.";
        return;
    }

    // INTENTIONAL VULNERABILITY: unsafe DOM sink.
    // A safe implementation would use `el.textContent = "Welcome, " + rawName;`
    el.innerHTML = "Welcome, " + rawName;
}

window.addEventListener("hashchange", renderWelcome);
window.addEventListener("DOMContentLoaded", renderWelcome);
