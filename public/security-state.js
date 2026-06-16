(function () {
  const controlsKey = "dbsec.presenter.controls";
  const evidenceKey = "dbsec.presenter.evidence";
  const presenterStateKey = "dbsec.presenter.state";
  const guideDismissedKey = "dbsec.presenter.guideDismissed";
  const defaultControls = {
    prepared: true,
    rbac: true,
    encoding: true,
    audit: true,
    network: true,
    config: true
  };

  const controlModel = {
    prepared: {
      name: "Prepared Statements",
      category: "Authentication",
      points: 22,
      floor: 74,
      protected: "Protected",
      risk: "Vulnerable",
      enabled: "Prepared Statements enabled: user input can no longer manipulate SQL query structure.",
      disabled: "Prepared Statements disabled: user input can change SQL query structure in vulnerable paths.",
      missing: "SQL input can still alter query logic."
    },
    rbac: {
      name: "RBAC and Masking",
      category: "Data Protection",
      points: 18,
      floor: 58,
      protected: "Restricted",
      risk: "Unrestricted",
      enabled: "RBAC and masking enabled: records and sensitive fields are restricted by role.",
      disabled: "RBAC or masking disabled: roles can see more data than the task requires.",
      missing: "Role boundaries or sensitive-field reduction are incomplete."
    },
    encoding: {
      name: "Output Encoding",
      category: "Data Protection",
      points: 12,
      floor: 45,
      protected: "Protected",
      risk: "Unsafe",
      enabled: "Output Encoding enabled: untrusted content renders as text.",
      disabled: "Output Encoding disabled: untrusted content can become active page markup.",
      missing: "Untrusted content can become active markup."
    },
    audit: {
      name: "Audit Logging",
      category: "Monitoring",
      points: 8,
      floor: 0,
      protected: "Logged",
      risk: "Unlogged",
      enabled: "Audit Logging enabled: security-relevant actions are now traceable.",
      disabled: "Audit Logging disabled: security-relevant actions can occur without useful evidence.",
      missing: "Security events have limited investigation evidence."
    },
    network: {
      name: "Network Segmentation",
      category: "Network Security",
      points: 24,
      floor: 78,
      protected: "Segmented",
      risk: "Exposed",
      enabled: "Network Segmentation enabled: the database is no longer directly reachable from the Internet.",
      disabled: "Network Segmentation disabled: direct database exposure becomes the dominant risk.",
      missing: "Database access can bypass the intended application path."
    },
    config: {
      name: "Secure Configuration",
      category: "Data Protection",
      points: 20,
      floor: 72,
      protected: "Hardened",
      risk: "Unsafe",
      enabled: "Secure Configuration enabled: least privilege, secrets handling, TLS, and hardening are in scope.",
      disabled: "Secure Configuration disabled: risky defaults can undermine otherwise good controls.",
      missing: "Risky defaults, broad grants, weak secrets, or missing TLS can remain."
    }
  };

  const combinedFloors = [
    { controls: ["network", "config"], floor: 88 },
    { controls: ["network", "prepared"], floor: 90 },
    { controls: ["prepared", "rbac"], floor: 82 },
    { controls: ["config", "rbac"], floor: 78 }
  ];

  const categories = {
    Authentication: ["prepared", "rbac"],
    "Data Protection": ["rbac", "encoding", "config"],
    "Network Security": ["network", "config"],
    Monitoring: ["audit"]
  };
  const guidedControls = ["prepared", "encoding", "rbac", "audit", "network", "config"];

  function readControls() {
    try {
      const saved = JSON.parse(localStorage.getItem(controlsKey));
      return { ...defaultControls, ...(saved || {}) };
    } catch {
      return { ...defaultControls };
    }
  }

  function readEvidence() {
    try {
      return JSON.parse(localStorage.getItem(evidenceKey)) || {};
    } catch {
      return {};
    }
  }

  function writeControls(controls) {
    localStorage.setItem(controlsKey, JSON.stringify({ ...defaultControls, ...controls }));
  }

  function scoreControls(controls = readControls()) {
    const missing = Object.keys(controlModel).filter((control) => !controls[control]);
    const baseResidualRisk = 8;
    const additiveRisk = missing.reduce((total, control) => total + controlModel[control].points, 0);
    const singleControlFloor = missing.reduce((floor, control) => Math.max(floor, controlModel[control].floor), 0);
    const combinedControlFloor = combinedFloors.reduce((floor, rule) => {
      return rule.controls.every((control) => missing.includes(control)) ? Math.max(floor, rule.floor) : floor;
    }, 0);
    const score = Math.min(100, Math.max(baseResidualRisk + additiveRisk, singleControlFloor, combinedControlFloor));
    const posture = score >= 70 ? "High Risk" : score >= 35 ? "Medium Risk" : "Low Risk";
    return { score, posture, missing };
  }

  function ensureStoredControls() {
    if (!localStorage.getItem(controlsKey)) writeControls(defaultControls);
  }

  function stateClass(posture) {
    if (posture === "High Risk") return "danger";
    if (posture === "Medium Risk") return "warning";
    return "safe";
  }

  function nextGuideStep(controls, evidence) {
    const index = guidedControls.findIndex((control) => !controls[control] || !evidence[control]);
    return index === -1 ? guidedControls.length + 1 : index + 1;
  }

  function guideDismissed() {
    return localStorage.getItem(guideDismissedKey) === "true";
  }

  function setGuideDismissed(dismissed) {
    localStorage.setItem(guideDismissedKey, dismissed ? "true" : "false");
    window.dispatchEvent(new CustomEvent("dbsec:guide-visibility", { detail: { dismissed } }));
    window.setTimeout(renderPosture, 0);
  }

  function renderPosture() {
    const root = document.getElementById("global-security-posture");
    if (!root) return;
    const detailsOpen = root.querySelector(".posture-details")?.open || false;

    const controls = readControls();
    const evidence = readEvidence();
    const { score, posture, missing } = scoreControls(controls);
    const enabled = Object.keys(controlModel).filter((control) => controls[control]);
    const topMissing = missing
      .slice()
      .sort((left, right) => controlModel[right].points - controlModel[left].points)
      .slice(0, 4);
    const postureClass = stateClass(posture);

    const guideStep = nextGuideStep(controls, evidence);
    const guideLabel = guideStep > guidedControls.length ? "Complete" : `Step ${guideStep}/6`;

    root.className = `global-posture posture-${postureClass} posture-compact`;
    root.innerHTML = `
      <div class="posture-inner">
        <div class="posture-summary">
          <span class="posture-label">Risk score</span>
          <div class="posture-title-row">
            <strong class="posture-title">${score}/100</strong>
            <span class="badge badge-${postureClass === "danger" ? "danger" : postureClass === "warning" ? "warning" : "safe"}">${posture}</span>
          </div>
        </div>
        <div class="posture-stat">
          <span class="posture-label">Current step</span>
          <strong>${guideLabel}</strong>
        </div>
        <button type="button" class="btn btn-ghost posture-guide-toggle" data-guide-toggle>${guideDismissed() ? "Show guide" : "Hide guide"}</button>
        <details class="posture-details"${detailsOpen ? " open" : ""}>
          <summary>Status details</summary>
          <p class="posture-detail-note">Guide status: ${guideLabel}. ${enabled.length}/6 controls are currently enabled.</p>
          <div class="posture-columns">
            <div>
              <strong class="posture-label">Enabled protections</strong>
              <div class="posture-chip-row">
                ${enabled.map((control) => `<span class="badge badge-safe">${controlModel[control].protected}: ${controlModel[control].name}</span>`).join("") || '<span class="badge badge-warning">No controls enabled</span>'}
              </div>
            </div>
            <div>
              <strong class="posture-label">Active risks</strong>
              <div class="posture-chip-row">
                ${topMissing.map((control) => `<span class="badge badge-danger">${controlModel[control].risk}: ${controlModel[control].name}</span>`).join("") || '<span class="badge badge-safe">No active demo risks</span>'}
              </div>
            </div>
          </div>
          <div class="category-bars" aria-label="Security category coverage">
            ${Object.entries(categories).map(([name, items]) => {
              const complete = items.filter((control) => controls[control]).length;
              const percent = Math.round((complete / items.length) * 100);
              return `
                <div class="category-bar${percent === 100 ? " is-complete" : ""}">
                  <span>${name}</span>
                  <div class="category-track" aria-hidden="true"><i style="width:${percent}%"></i></div>
                  <strong>${percent}%</strong>
                </div>
              `;
            }).join("")}
          </div>
        </details>
      </div>
    `;
    root.querySelector("[data-guide-toggle]")?.addEventListener("click", () => {
      setGuideDismissed(!guideDismissed());
    });
    renderNavigationState(controls);
  }

  function renderNavigationState(controls = readControls()) {
    const evidence = readEvidence();
    document.querySelectorAll(".app-nav [data-nav-control]").forEach((link) => {
      const control = link.dataset.navControl;
      const complete = Boolean(controls[control] && evidence[control]);
      link.dataset.navComplete = String(complete);
      link.setAttribute("aria-label", `${link.textContent.trim()}${complete ? " completed" : " not completed"}`);
    });
  }

  function installPosture() {
    if (document.getElementById("global-security-posture")) return;
    const header = document.querySelector(".app-header");
    if (!header) return;
    const section = document.createElement("section");
    section.id = "global-security-posture";
    section.setAttribute("aria-live", "polite");
    header.insertAdjacentElement("afterend", section);
    renderPosture();
  }

  function setImpact(text, state = "info") {
    const panel = document.querySelector("[data-security-impact], #security-impact");
    if (!panel || !text) return;
    panel.className = `security-impact impact-${state}`;
    panel.innerHTML = `<strong>Security Impact</strong><span>${text}</span>`;
  }

  function updateControl(control, enabled, impactText) {
    const controls = readControls();
    controls[control] = Boolean(enabled);
    writeControls(controls);
    if (impactText) setImpact(impactText, enabled ? "safe" : "danger");
    renderPosture();
    window.dispatchEvent(new CustomEvent("dbsec:controls-changed", { detail: controls }));
  }

  const nativeSetItem = localStorage.setItem.bind(localStorage);
  localStorage.setItem = function patchedSetItem(key, value) {
    nativeSetItem(key, value);
    if (key === controlsKey) {
      window.setTimeout(renderPosture, 0);
      window.dispatchEvent(new Event("dbsec:controls-storage-updated"));
    } else if (key === evidenceKey) {
      window.setTimeout(() => renderNavigationState(), 0);
    }
  };

  window.DBSEC = {
    controlsKey,
    controlModel,
    readControls,
    readEvidence,
    writeControls,
    scoreControls,
    renderPosture,
    setImpact,
    updateControl
  };

  ensureStoredControls();
  installPosture();
  renderNavigationState();
  window.addEventListener("storage", (event) => {
    if (event.key === controlsKey) renderPosture();
    if (event.key === evidenceKey) renderNavigationState();
    if (event.key === presenterStateKey || event.key === guideDismissedKey) renderPosture();
  });
  window.addEventListener("dbsec:guide-visibility", renderPosture);
  window.addEventListener("dbsec:controls-changed", renderPosture);
  document.addEventListener("change", () => window.setTimeout(renderPosture, 0));
  document.addEventListener("click", () => window.setTimeout(renderPosture, 0));
})();
