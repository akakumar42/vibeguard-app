// TaskPal demo app - a test fixture for the web scanner. Every problem below is deliberate.
// The keys are fake and do not work anywhere.
const STRIPE_SECRET_KEY = "sk_live_51NzQ8kLp4XwT9vB2mRcY7dHs";
const SUPABASE_URL = "https://taskpal-demo.supabase.co";
const SUPABASE_SERVICE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRhc2twYWwtZGVtbyIsInJvbGUiOiJzZXJ2aWNlX3JvbGUiLCJpYXQiOjE3MDAwMDAwMDB9.q8Xv2mT0bL4nR7sK1pW9yD3fH6jZ5cV8aE2gN4uQ0iM";

function showGreeting() {
  const name = new URLSearchParams(location.search).get("name") || "friend";
  document.getElementById("greeting").innerHTML = "Hello " + name + "!";
}

function calculate() {
  const expr = new URLSearchParams(location.search).get("calc");
  if (expr) {
    document.getElementById("out").textContent = eval(expr);
  }
}

async function login(email, password) {
  const res = await fetch("http://api.taskpal-demo.com/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  const data = await res.json();
  localStorage.setItem("auth_token", data.token);
  console.log("logged in", data.token);
}

async function loadTasks() {
  const res = await fetch(SUPABASE_URL + "/rest/v1/tasks", {
    headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: "Bearer " + SUPABASE_SERVICE_KEY },
  });
  return res.json();
}

window.addEventListener("message", (event) => {
  document.getElementById("out").innerHTML = event.data;
});

function notifyParent(state) {
  window.parent.postMessage(state, "*");
}

showGreeting();
calculate();
//# sourceMappingURL=app.js.map
