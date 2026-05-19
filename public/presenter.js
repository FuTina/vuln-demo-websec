(function () {
  const stateKey = "dbsec.presenter.state";
  const controlsKey = "dbsec.presenter.controls";
  const path = location.pathname.replace(/\/+$/, "") || "/";
  const guidedControls = ["prepared", "encoding", "rbac", "audit", "network", "config"];
  const modules = {
    "/sqli.html": {
      step: 2,
      title: "Step 2: SQL injection + prepared statements",
      text: "Run a bypass example in Vulnerable mode. Then enable Protected mode to show that input can no longer change query logic.",
      primary: "Enable protected mode and continue",
      nextStep: 3,
      control: "prepared",
      click: "#protected-mode",
      href: "/xss.html",
      completeLabel: "Continue to XSS"
    },
    "/xss.html": {
      step: 3,
      title: "Step 3: XSS + output encoding",
      text: "Render one harmless demo payload in Vulnerable mode. Then enable Protected output to keep the same input as text.",
      primary: "Enable protected output and continue",
      nextStep: 4,
      control: "encoding",
      click: "#safe-render",
      href: "/users.html",
      completeLabel: "Continue to Data Masking"
    },
    "/users.html": {
      step: 4,
      title: "Step 4: Review RBAC/data masking",
      text: "Compare roles, briefly disable RBAC if you want to show the risk, then continue with RBAC and masking enabled.",
      primary: "Continue with RBAC + masking enabled",
      nextStep: 5,
      control: "rbac",
      clickAll: ["#rbac-toggle", "#mask-toggle"],
      href: "/audit.html",
      completeLabel: "Continue to Audit"
    },
    "/audit.html": {
      step: 5,
      title: "Step 5: Run audit events",
      text: "Trigger failed login, export, and privilege events. Continue when the evidence trail is visible.",
      primary: "Continue to Network",
      nextStep: 6,
      control: "audit",
      clickAll: ["#audit-toggle"],
      href: "/network.html",
      completeLabel: "Continue to Network"
    },
    "/network.html": {
      step: 6,
      title: "Step 6: Show network segmentation",
      text: "Run the connection tests in the risky state, then apply the secure network baseline before continuing.",
      primary: "Apply secure network and continue",
      nextStep: 7,
      control: "network",
      click: "#secure-preset",
      href: "/config.html",
      completeLabel: "Continue to Config"
    },
    "/config.html": {
      step: 7,
      title: "Step 7: Finish with secure configuration",
      text: "Apply the secure checklist, inspect the Postgres runtime tab, then finish back on the executive summary.",
      primary: "Apply config and finish",
      nextStep: 8,
      control: "config",
      click: "#apply-baseline",
      finish: true,
      href: "/",
      completeLabel: "Finish on Overview"
    }
  };

  function readState() {
    try {
      return JSON.parse(localStorage.getItem(stateKey)) || { active: false, step: 1 };
    } catch {
      return { active: false, step: 1 };
    }
  }

  function writeState(step) {
    localStorage.setItem(stateKey, JSON.stringify({ active: true, step }));
  }

  function updateControl(name, enabled) {
    let state = {};
    try {
      state = JSON.parse(localStorage.getItem(controlsKey)) || {};
    } catch {
      state = {};
    }
    state[name] = enabled;
    localStorage.setItem(controlsKey, JSON.stringify(state));
  }

  function readControls() {
    try {
      return JSON.parse(localStorage.getItem(controlsKey)) || {};
    } catch {
      return {};
    }
  }

  function dispatchChange(input) {
    input?.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function setCheckbox(selector, enabled) {
    const input = document.querySelector(selector);
    if (!input) return;
    input.checked = enabled;
    dispatchChange(input);
  }

  function ensureChecked(selector) {
    const input = document.querySelector(selector);
    if (!input) return;
    if (input.matches("input[type='checkbox']") && !input.checked) {
      input.checked = true;
      input.dispatchEvent(new Event("change", { bubbles: true }));
    } else if (!input.matches("input[type='checkbox']")) {
      input.click();
    }
  }

  function runPageAction(config) {
    if (config.click) ensureChecked(config.click);
    if (config.clickAll) config.clickAll.forEach(ensureChecked);
    if (config.control) updateControl(config.control, true);
    writeState(config.nextStep);
  }

  function syncControl(config, enabled) {
    if (config.control) updateControl(config.control, enabled);
    const state = readState();
    const currentStep = Number(state.step) || config.step;
    if (enabled && (!state.active || currentStep <= config.step)) {
      writeState(config.nextStep);
    } else if (!enabled && (!state.active || currentStep <= config.nextStep)) {
      writeState(config.step);
    }
    renderGuide(config, readState());
  }

  function isChecked(selector) {
    return Boolean(document.querySelector(selector)?.checked);
  }

  function syncNetwork(config) {
    const secure = !isChecked("#exposed-toggle") && isChecked("#internal-toggle") && isChecked("#firewall-toggle") && isChecked("#tls-toggle");
    syncControl(config, secure);
  }

  function syncConfig(config) {
    const checks = Array.from(document.querySelectorAll("#checklist input"));
    syncControl(config, checks.length > 0 && checks.every((input) => input.checked));
  }

  function syncUsers(config) {
    const secure = isChecked("#rbac-toggle") && isChecked("#mask-toggle");
    syncControl(config, secure);
  }

  function applyStoredControlState() {
    const controls = readControls();
    if (!Object.prototype.hasOwnProperty.call(controls, modules[path]?.control || "")) return;

    if (path === "/sqli.html") {
      document.getElementById(controls.prepared ? "protected-mode" : "vulnerable-mode")?.click();
    } else if (path === "/xss.html") {
      document.getElementById(controls.encoding ? "safe-render" : "vulnerable-render")?.click();
    } else if (path === "/users.html") {
      setCheckbox("#rbac-toggle", Boolean(controls.rbac));
      setCheckbox("#mask-toggle", Boolean(controls.rbac));
    } else if (path === "/audit.html") {
      setCheckbox("#audit-toggle", Boolean(controls.audit));
    } else if (path === "/network.html") {
      document.getElementById(controls.network ? "secure-preset" : "risky-preset")?.click();
    } else if (path === "/config.html") {
      document.getElementById(controls.config ? "apply-baseline" : "apply-risky")?.click();
    }
  }

  function bindManualSync(config) {
    if (path === "/sqli.html") {
      document.getElementById("protected-mode")?.addEventListener("click", () => syncControl(config, true));
      document.getElementById("vulnerable-mode")?.addEventListener("click", () => syncControl(config, false));
    } else if (path === "/xss.html") {
      document.getElementById("safe-render")?.addEventListener("click", () => syncControl(config, true));
      document.getElementById("vulnerable-render")?.addEventListener("click", () => syncControl(config, false));
    } else if (path === "/users.html") {
      document.getElementById("rbac-toggle")?.addEventListener("change", () => syncUsers(config));
      document.getElementById("mask-toggle")?.addEventListener("change", () => syncUsers(config));
    } else if (path === "/audit.html") {
      document.getElementById("audit-toggle")?.addEventListener("change", (event) => syncControl(config, event.currentTarget.checked));
    } else if (path === "/network.html") {
      ["#exposed-toggle", "#internal-toggle", "#firewall-toggle", "#tls-toggle"].forEach((selector) => {
        document.querySelector(selector)?.addEventListener("change", () => syncNetwork(config));
      });
      document.getElementById("secure-preset")?.addEventListener("click", () => window.setTimeout(() => syncNetwork(config), 0));
      document.getElementById("risky-preset")?.addEventListener("click", () => window.setTimeout(() => syncNetwork(config), 0));
    } else if (path === "/config.html") {
      document.getElementById("checklist")?.addEventListener("change", () => syncConfig(config));
      document.getElementById("apply-baseline")?.addEventListener("click", () => syncConfig(config));
      document.getElementById("apply-risky")?.addEventListener("click", () => syncConfig(config));
    }
  }

  function createLink(href, label, step, variant = "primary") {
    const link = document.createElement("a");
    link.className = `btn btn-${variant}`;
    link.href = href;
    link.textContent = label;
    link.addEventListener("click", () => writeState(step));
    return link;
  }

  function renderGuide(config, state) {
    const guide = document.createElement("details");
    guide.open = false;
    const currentStep = Number(state.step) || 1;
    const controls = readControls();
    const completedThisModule = Boolean(controls[config.control]);
    const previousControls = guidedControls.slice(0, Math.max(0, guidedControls.indexOf(config.control)));
    const previousControlsComplete = previousControls.every((control) => controls[control]);
    const completedSteps = Math.min(7, (state.active ? 1 : 0) + guidedControls.filter((control) => controls[control]).length);
    const progress = Math.round((completedSteps / 7) * 100);
    const navigationStep = completedThisModule ? Math.max(currentStep, config.nextStep) : currentStep;
    guide.className = `presenter-module-guide ${completedThisModule ? "is-complete" : "is-active"}`;
    const title = completedThisModule ? `${config.title} complete` : config.title;
    const text = completedThisModule
      ? previousControlsComplete
        ? "This step is complete because the matching control is already enabled. Continue with the next module or return to the overview."
        : "This configuration step is complete. Earlier Guided Mode steps are still open, so the overview will continue at the first missing control."
      : config.text;

    guide.innerHTML = `
      <summary aria-label="Open Guided Mode">
        <span class="guided-summary">
          <span class="guided-icon" aria-hidden="true">G</span>
          <span>Guided Mode</span>
        </span>
        <strong>${completedThisModule ? "Complete" : `Step ${config.step}/7`}</strong>
        <span class="guided-tooltip" role="tooltip">Guided demo flow: complete this page's control, then continue with the next module.</span>
      </summary>
      <div class="presenter-dock-body">
        <p class="module-kicker">Guided Mode</p>
        <h2>${title}</h2>
        <p>${text}</p>
        <div class="presenter-progress" aria-hidden="true"><span style="width: ${progress}%"></span></div>
      </div>
    `;

    const actions = document.createElement("div");
    actions.className = "toolbar-actions";
    actions.appendChild(createLink("/", "Back to Overview", navigationStep, "ghost"));

    if (completedThisModule && config.href) {
      actions.appendChild(createLink(config.href, config.completeLabel || "Continue", navigationStep));
    } else {
      const primary = document.createElement("button");
      primary.type = "button";
      primary.className = config.finish ? "btn btn-safe" : "btn btn-primary";
      primary.textContent = config.finish && !previousControlsComplete ? "Apply config and return to open steps" : config.primary;
      primary.addEventListener("click", () => {
        runPageAction(config);
        if (config.href) location.href = config.href;
        else renderGuide(config, readState());
      });
      actions.appendChild(primary);
    }

    guide.querySelector(".presenter-dock-body").appendChild(actions);
    document.querySelector(".presenter-module-guide")?.remove();
    document.querySelector(".app-header")?.after(guide);
  }

  const config = modules[path];
  if (!config) return;
  applyStoredControlState();
  bindManualSync(config);
  renderGuide(config, readState());
})();
