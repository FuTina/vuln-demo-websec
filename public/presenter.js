(function () {
  const stateKey = "dbsec.presenter.state";
  const controlsKey = "dbsec.presenter.controls";
  const evidenceKey = "dbsec.presenter.evidence";
  const sidekickPositionKey = "dbsec.presenter.sidekickPosition";
  const path = location.pathname.replace(/\/+$/, "") || "/";
  const guidedControls = ["prepared", "encoding", "rbac", "audit", "network", "config"];
  const sidekickStepClasses = ["step-1", "step-2", "step-3", "step-4", "step-5", "step-6", "step-complete"];
  const modules = {
    "/sqli.html": {
      step: 1,
      title: "Step 1: SQL injection + prepared statements",
      text: "Run a bypass example in Vulnerable mode. Then enable Protected mode to show that input can no longer change query logic.",
      primary: "Enable protected mode and continue",
      nextStep: 2,
      control: "prepared",
      evidenceText: "Run a login check in Vulnerable mode before completing this step.",
      click: "#protected-mode",
      href: "/xss.html",
      completeLabel: "Continue to XSS"
    },
    "/xss.html": {
      step: 2,
      title: "Step 2: XSS + output encoding",
      text: "Post one harmless demo payload in Vulnerable mode. Then enable Protected output to keep the same input as text.",
      primary: "Enable protected output and continue",
      nextStep: 3,
      control: "encoding",
      evidenceText: "Post a comment in Vulnerable mode before completing this step.",
      click: "#safe-render",
      href: "/users.html",
      completeLabel: "Continue to Data Masking"
    },
    "/users.html": {
      step: 3,
      title: "Step 3: Review RBAC/data masking",
      text: "Compare roles, briefly disable RBAC if you want to show the risk, then continue with RBAC and masking enabled.",
      primary: "Continue with RBAC + masking enabled",
      nextStep: 4,
      control: "rbac",
      evidenceText: "Change a role or toggle RBAC/masking to observe the data exposure before continuing.",
      clickAll: ["#rbac-toggle", "#mask-toggle"],
      href: "/audit.html",
      completeLabel: "Continue to Audit"
    },
    "/audit.html": {
      step: 4,
      title: "Step 4: Run audit events",
      text: "Trigger failed login, export, and privilege events. Continue when the evidence trail is visible.",
      primary: "Continue to Network",
      nextStep: 5,
      control: "audit",
      evidenceText: "Trigger at least one audit-relevant event before continuing.",
      clickAll: ["#audit-toggle"],
      href: "/network.html",
      completeLabel: "Continue to Network"
    },
    "/network.html": {
      step: 5,
      title: "Step 5: Show network segmentation",
      text: "Send a packet from the exposed baseline, then change the controls until direct database access is blocked.",
      primary: "Continue to Config",
      nextStep: 6,
      control: "network",
      evidenceText: "Send a packet while the database is exposed, then make the network segmented before continuing.",
      href: "/config.html",
      completeLabel: "Continue to Config"
    },
    "/config.html": {
      step: 6,
      title: "Step 6: Finish with secure configuration",
      text: "Build the config from blocks, review the live findings, inspect the Postgres runtime tab, then finish back on the executive summary.",
      primary: "Finish flow",
      nextStep: 7,
      control: "config",
      evidenceText: "Build or change at least one config block, then review the result before finishing.",
      finish: true,
      href: "/",
      completeLabel: "Finish on Overview"
    }
  };
  const modulesByControl = Object.fromEntries(
    Object.entries(modules).map(([route, config]) => [config.control, { ...config, route }])
  );
  const completeConfig = {
    step: 7,
    title: "Guided demo complete",
    text: "The secure baseline is applied. Use the overview as the closing summary.",
    primary: "Return to Overview",
    route: "/",
    href: "/",
    completeLabel: "Return to Overview"
  };

  function readState() {
    try {
      return JSON.parse(localStorage.getItem(stateKey)) || { active: true, step: 1 };
    } catch {
      return { active: true, step: 1 };
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

  function readEvidence() {
    try {
      return JSON.parse(localStorage.getItem(evidenceKey)) || {};
    } catch {
      return {};
    }
  }

  function writeEvidence(evidence) {
    localStorage.setItem(evidenceKey, JSON.stringify(evidence));
  }

  function hasEvidence(config) {
    return Boolean(readEvidence()[config.control]);
  }

  function isStepComplete(control, controls = readControls(), evidence = readEvidence()) {
    return Boolean(controls[control] && evidence[control]);
  }

  function nextOpenConfig(controls = readControls(), evidence = readEvidence()) {
    const openControl = guidedControls.find((control) => !isStepComplete(control, controls, evidence));
    return openControl ? modulesByControl[openControl] : completeConfig;
  }

  function markEvidence(config) {
    if (!config?.control) return;
    const evidence = readEvidence();
    evidence[config.control] = true;
    writeEvidence(evidence);
    renderGuide(config, readState());
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
    if (!hasEvidence(config)) {
      renderGuide(config, readState());
      return false;
    }
    if (config.click) ensureChecked(config.click);
    if (config.clickAll) config.clickAll.forEach(ensureChecked);
    if (config.control) updateControl(config.control, true);
    writeState(config.nextStep);
    return true;
  }

  function syncControl(config, enabled) {
    if (config.control) updateControl(config.control, enabled);
    const state = readState();
    const currentStep = Number(state.step) || config.step;
    if (enabled && hasEvidence(config) && (!state.active || currentStep <= config.step)) {
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
      const evidence = readEvidence();
      if (controls.network && !evidence.network) return;
      if (controls.network) {
        setCheckbox("#exposed-toggle", false);
        setCheckbox("#internal-toggle", true);
        setCheckbox("#firewall-toggle", true);
        setCheckbox("#tls-toggle", true);
      }
    }
  }

  function bindEvidence(config) {
    const mark = () => window.setTimeout(() => markEvidence(config), 0);

    if (path === "/sqli.html") {
      document.getElementById("login-form")?.addEventListener("submit", () => {
        if (document.getElementById("vulnerable-mode")?.getAttribute("aria-pressed") === "true") mark();
      });
    } else if (path === "/xss.html") {
      document.getElementById("comment-form")?.addEventListener("submit", () => {
        if (document.getElementById("vulnerable-render")?.getAttribute("aria-pressed") === "true") mark();
      });
    } else if (path === "/users.html") {
      document.querySelectorAll("[data-role], #rbac-toggle, #mask-toggle").forEach((item) => {
        item.addEventListener("click", mark);
        item.addEventListener("change", mark);
      });
    } else if (path === "/audit.html") {
      document.querySelectorAll("[data-event]").forEach((button) => button.addEventListener("click", mark));
    } else if (path === "/network.html") {
      document.getElementById("send-packet")?.addEventListener("click", () => {
        if (document.getElementById("exposed-toggle")?.checked) mark();
      });
    } else if (path === "/config.html") {
      document.querySelector("[data-config-tab='postgres']")?.addEventListener("click", mark);
      document.querySelector("[data-open-config-tab='postgres']")?.addEventListener("click", mark);
      document.getElementById("checklist")?.addEventListener("change", mark);
      document.getElementById("review-config")?.addEventListener("click", mark);
      document.querySelectorAll("[data-builder-slot], #builder-target-frame").forEach((item) => {
        item.addEventListener("drop", mark);
      });
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
    } else if (path === "/config.html") {
      document.getElementById("checklist")?.addEventListener("change", () => syncConfig(config));
      document.getElementById("apply-risky")?.addEventListener("click", () => syncConfig(config));
      document.getElementById("review-config")?.addEventListener("click", () => window.setTimeout(() => syncConfig(config), 0));
      document.querySelectorAll("[data-config-tab], [data-open-config-tab]").forEach((button) => {
        button.addEventListener("click", () => window.setTimeout(() => renderGuide(config, readState()), 0));
      });
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

  function stepActionLabel(config) {
    if (!config || config.step > guidedControls.length) return "Open Overview";
    return `Go to Step ${config.step}`;
  }

  function nextActionLabel(config) {
    if (!config || config.nextStep > guidedControls.length) return config.completeLabel || "Finish on Overview";
    return config.completeLabel || `Go to Step ${config.nextStep}`;
  }

  function animateOwl(sidekick) {
    const toggle = sidekick.querySelector(".sidekick-toggle");
    if (!toggle) return;
    const current = Number(sidekick.dataset.tapIndex || "0");
    let next = Math.floor(Math.random() * 3) + 1;
    if (next === current) next = (next % 3) + 1;
    sidekick.dataset.tapIndex = String(next);
    toggle.classList.remove("owl-tap-1", "owl-tap-2", "owl-tap-3");
    void toggle.offsetWidth;
    toggle.classList.add(`owl-tap-${next}`);
    window.setTimeout(() => toggle.classList.remove(`owl-tap-${next}`), 520);
  }

  function animateOwlTravel(sidekick) {
    const toggle = sidekick.querySelector(".sidekick-toggle");
    if (!toggle) return;
    toggle.classList.add("is-flying");
    window.setTimeout(() => toggle.classList.remove("is-flying"), 760);
  }

  function positionSidekick(sidekick, nextClass) {
    const previousClass = localStorage.getItem(sidekickPositionKey);
    const shouldTravel = previousClass && previousClass !== nextClass && sidekickStepClasses.includes(previousClass);
    const canTravel = shouldTravel && window.matchMedia("(min-width: 801px)").matches;
    sidekick.classList.remove(...sidekickStepClasses);
    sidekick.classList.add(canTravel ? previousClass : nextClass);
    if (canTravel) {
      window.requestAnimationFrame(() => {
        sidekick.classList.remove(...sidekickStepClasses);
        sidekick.classList.add(nextClass);
        localStorage.setItem(sidekickPositionKey, nextClass);
        animateOwlTravel(sidekick);
      });
    } else {
      localStorage.setItem(sidekickPositionKey, nextClass);
    }
  }

  function assistantText(config) {
    if (path === "/config.html" && document.body.dataset.configTab === "postgres") {
      return "Postgres runtime is only the reference view. Go back to Baseline review, build the Target config with drag and drop, then run Review configuration.";
    }
    const tips = {
      prepared: "Run the vulnerable login once first. Then switch to Protected and compare the query boundary.",
      encoding: "Post the demo comment in Vulnerable mode, then switch to Protected to see the same text contained.",
      rbac: "Switch roles and look at which fields disappear. Then leave RBAC and masking enabled.",
      audit: "Trigger one event and inspect whether there is enough evidence to investigate it.",
      network: "Send an Internet packet first. Then change Internal network, Firewall, and TLS until direct database access is blocked.",
      config: "Drag blocks into Target config. Watch Live findings turn red or green, then run Review configuration."
    };
    return tips[config.control] || config.evidenceText;
  }

  function renderGuide(config, state) {
    const sidekick = document.createElement("div");
    const controls = readControls();
    const evidence = readEvidence();
    const guideConfig = nextOpenConfig(controls, evidence);
    const guideIsComplete = guideConfig.step > guidedControls.length;
    const currentPageIsGuideStep = guideConfig.route === path;
    const configPostgresTabActive = path === "/config.html" && document.body.dataset.configTab === "postgres" && guideConfig.control === "config";
    const evidenceComplete = guideIsComplete || hasEvidence(guideConfig);
    const controlComplete = guideIsComplete || Boolean(controls[guideConfig.control]);
    const completedThisModule = guideIsComplete || (currentPageIsGuideStep && controlComplete && evidenceComplete);
    const completedSteps = guideIsComplete
      ? guidedControls.length
      : Math.min(guidedControls.length, guidedControls.filter((control) => controls[control] && evidence[control]).length);
    const progress = Math.round((completedSteps / guidedControls.length) * 100);
    const navigationStep = guideIsComplete ? 7 : guideConfig.step;
    const sidekickText = guideIsComplete
      ? "All steps are complete. Review the overview as your closing summary."
      : configPostgresTabActive
        ? "You are viewing the Postgres runtime reference. The step is completed in Baseline review with the drag-and-drop Target config."
        : currentPageIsGuideStep
        ? guideConfig.text.replace(/^Step \d+:\s*/, "")
        : `Next unfinished step: ${guideConfig.title.replace(/^Step \d+:\s*/, "")}.`;
    const sidekickTip = guideIsComplete
      ? "Nice work. The posture is now ready for the final walkthrough."
      : assistantText(guideConfig);

    const sidekickStepClass = guideIsComplete ? "step-complete" : `step-${Math.min(guidedControls.length, Math.max(1, guideConfig.step))}`;
    sidekick.className = `guide-sidekick ${guideIsComplete ? "is-complete" : completedThisModule ? "is-happy" : ""}`;
    sidekick.setAttribute("role", "region");
    sidekick.setAttribute("aria-label", guideIsComplete ? "Guided flow complete" : `Guided step ${guideConfig.step}`);
    sidekick.innerHTML = `
      <button type="button" class="sidekick-toggle" aria-label="Show guide tip">
        <span class="assistant-avatar assistant-avatar-large" aria-hidden="true"><i></i></span>
      </button>
      <div class="assistant-speech">
        <strong>${guideIsComplete ? "Party mode" : `Step ${guideConfig.step}/6`}</strong>
        <span data-sidekick-text>${sidekickText}</span>
        <div class="presenter-progress sidekick-progress" aria-hidden="true"><span style="width: ${progress}%"></span></div>
        <div class="sidekick-actions"></div>
      </div>
    `;
    const toggleTip = (animate = false) => {
      if (animate) animateOwl(sidekick);
      const textNode = sidekick.querySelector("[data-sidekick-text]");
      const showingTip = sidekick.classList.toggle("is-showing-tip");
      textNode.textContent = showingTip ? sidekickTip : sidekickText;
    };
    sidekick.querySelector(".sidekick-toggle").addEventListener("click", () => toggleTip(true));
    sidekick.querySelector(".assistant-speech").addEventListener("click", (event) => {
      if (!event.target.closest(".sidekick-actions")) toggleTip(false);
    });

    const actions = document.createElement("div");
    actions.className = "sidekick-actions";

    if (!currentPageIsGuideStep && !guideIsComplete) {
      actions.appendChild(createLink(guideConfig.route, stepActionLabel(guideConfig), guideConfig.step));
    } else if (guideIsComplete) {
      actions.appendChild(createLink("/", "Back to overview", 7, "safe"));
    } else if (configPostgresTabActive) {
      const back = document.createElement("button");
      back.type = "button";
      back.className = "btn btn-primary";
      back.textContent = "Back to config builder";
      back.addEventListener("click", () => {
        document.querySelector("[data-config-tab='baseline']")?.click();
        document.getElementById("config-builder")?.scrollIntoView({ behavior: "smooth", block: "start" });
        renderGuide(config, readState());
      });
      actions.appendChild(back);
    } else if (completedThisModule && guideConfig.href) {
      actions.appendChild(createLink(guideConfig.href, nextActionLabel(guideConfig), guideConfig.nextStep));
    } else {
      const primary = document.createElement("button");
      primary.type = "button";
      primary.className = guideConfig.finish ? "btn btn-safe" : "btn btn-primary";
      primary.textContent = guideConfig.primary;
      const requiresManualControl = !guideConfig.click && !guideConfig.clickAll && guideConfig.control;
      primary.disabled = !evidenceComplete || (requiresManualControl && !controlComplete);
      if (!evidenceComplete) primary.title = guideConfig.evidenceText;
      else if (requiresManualControl && !controlComplete) primary.title = "Enable the required control before continuing.";
      primary.addEventListener("click", () => {
        const completed = runPageAction(guideConfig);
        if (completed && guideConfig.href) location.href = guideConfig.href;
        else renderGuide(config, readState());
      });
      actions.appendChild(primary);
    }

    sidekick.querySelector(".sidekick-actions").replaceWith(actions);
    document.querySelector(".presenter-module-guide")?.remove();
    document.querySelector(".guide-sidekick")?.remove();
    document.body.appendChild(sidekick);
    positionSidekick(sidekick, sidekickStepClass);
  }

  const config = modules[path];
  if (!config) return;
  applyStoredControlState();
  bindEvidence(config);
  bindManualSync(config);
  renderGuide(config, readState());
})();
