(() => {
  const toast = document.getElementById("toast");

  function showToast(msg) {
    if (!toast) return;
    toast.textContent = msg;
    toast.classList.add("show");
    window.clearTimeout(showToast._t);
    showToast._t = window.setTimeout(() => toast.classList.remove("show"), 3200);
  }

  async function post(url, body) {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: body ? JSON.stringify(body) : "{}",
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || (data.execution && data.execution.status === "failed")) {
      const err = (data.execution && data.execution.error) || "Request failed";
      throw new Error(err);
    }
    return data;
  }

  document.querySelectorAll("[data-approve]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-approve");
      btn.disabled = true;
      try {
        await post(`/api/approve/${encodeURIComponent(id)}`);
        showToast(`Approved ${id}`);
        window.setTimeout(() => window.location.reload(), 500);
      } catch (e) {
        showToast(e.message || "Approve failed");
        btn.disabled = false;
      }
    });
  });

  document.querySelectorAll("[data-reject]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-reject");
      btn.disabled = true;
      try {
        await post(`/api/reject/${encodeURIComponent(id)}`);
        showToast(`Rejected ${id}`);
        window.setTimeout(() => window.location.reload(), 500);
      } catch (e) {
        showToast(e.message || "Reject failed");
        btn.disabled = false;
      }
    });
  });

  const briefBtn = document.getElementById("btn-brief");
  if (briefBtn) {
    briefBtn.addEventListener("click", async () => {
      briefBtn.disabled = true;
      briefBtn.textContent = "Briefing...";
      try {
        await post("/api/brief", { provider: "offline" });
        showToast("Manager brief refreshed");
        window.setTimeout(() => window.location.reload(), 400);
      } catch (e) {
        showToast(e.message || "Brief failed");
        briefBtn.disabled = false;
        briefBtn.textContent = "Refresh brief";
      }
    });
  }

  const cycleBtn = document.getElementById("btn-cycle");
  if (cycleBtn) {
    cycleBtn.addEventListener("click", async () => {
      cycleBtn.disabled = true;
      cycleBtn.textContent = "Scanning...";
      showToast("Running Cloud agent (live AWS)...");
      try {
        // Live Cloud only — do not re-inject mock vulns from other agents.
        await post("/api/cycle", {
          roles: "cloud",
          mock: false,
          llm: true,
          provider: "offline",
        });
        showToast("Live Cloud cycle complete");
        window.setTimeout(() => window.location.reload(), 500);
      } catch (e) {
        showToast(e.message || "Cycle failed");
        cycleBtn.disabled = false;
        cycleBtn.textContent = "Run AI cycle";
      }
    });
  }

  const cisoBtn = document.getElementById("btn-ciso");
  if (cisoBtn) {
    cisoBtn.addEventListener("click", async () => {
      cisoBtn.disabled = true;
      cisoBtn.textContent = "Writing…";
      showToast("Generating CISO posture report...");
      try {
        const res = await post("/api/ciso-report", {});
        const id = (res && res.metadata && res.metadata.ciso_report && res.metadata.ciso_report.report_id) || "report";
        showToast("CISO report ready: " + id);
        window.setTimeout(() => window.location.reload(), 600);
      } catch (e) {
        showToast(e.message || "CISO report failed");
        cisoBtn.disabled = false;
        cisoBtn.textContent = "CISO report";
      }
    });
  }
})();
