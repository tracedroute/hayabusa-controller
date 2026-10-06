/**
 * First-run setup — dual video paths + looping background music.
 */
(function () {
  "use strict";

  var waitingEl = document.getElementById("setupWaiting");
  var wizardEl = document.getElementById("setupWizard");
  var choiceStep = document.getElementById("setupChoiceStep");
  var noviceConfirm = document.getElementById("setupNoviceConfirm");
  var advancedForm = document.getElementById("setupAdvancedForm");
  var lead = document.getElementById("setupLead");
  var noviceMsg = document.getElementById("noviceMsg");
  var advancedMsg = document.getElementById("advancedMsg");
  var music = document.getElementById("setupMusic");
  var videoNovice = document.getElementById("videoNovice");
  var videoAdvanced = document.getElementById("videoAdvanced");
  var chooseNovice = document.getElementById("chooseNovice");
  var chooseAdvanced = document.getElementById("chooseAdvanced");

  var leadDefault =
    "First administrator setup. Hover a path to bring it to life, then click to continue.";

  function show(el, on) {
    if (!el) return;
    el.hidden = !on;
  }

  function setMsg(el, text, isErr) {
    if (!el) return;
    if (!text) {
      el.hidden = true;
      el.textContent = "";
      el.classList.remove("is-error", "is-ok");
      return;
    }
    el.hidden = false;
    el.textContent = text;
    el.classList.toggle("is-error", !!isErr);
    el.classList.toggle("is-ok", !isErr);
  }

  function pauseVideo(v) {
    if (!v) return;
    try {
      v.pause();
    } catch (_) {}
  }

  function playVideo(v) {
    if (!v) return;
    var p = v.play();
    if (p && typeof p.catch === "function") {
      p.catch(function () {});
    }
  }

  function stopAllVideos() {
    pauseVideo(videoNovice);
    pauseVideo(videoAdvanced);
    if (chooseNovice) chooseNovice.classList.remove("is-active");
    if (chooseAdvanced) chooseAdvanced.classList.remove("is-active");
  }

  function activatePath(mode) {
    stopAllVideos();
    if (mode === "novice") {
      if (chooseNovice) chooseNovice.classList.add("is-active");
      playVideo(videoNovice);
      if (lead) lead.textContent = "Novice — simplified local Ansible / OpenTofu workspace.";
    } else if (mode === "advanced") {
      if (chooseAdvanced) chooseAdvanced.classList.add("is-active");
      playVideo(videoAdvanced);
      if (lead) lead.textContent = "Advanced — connect GitHub or GitLab as your source of truth.";
    } else if (lead) {
      lead.textContent = leadDefault;
    }
  }

  function clearPathHover() {
    stopAllVideos();
    if (lead) lead.textContent = leadDefault;
  }

  function showStep(step) {
    show(choiceStep, step === "choice");
    show(noviceConfirm, step === "novice");
    show(advancedForm, step === "advanced");
    if (step === "choice") {
      clearPathHover();
    } else {
      stopAllVideos();
    }
    startMusic();
  }

  function startMusic() {
    if (!music) return;
    music.loop = true;
    music.volume = 0.45;
    var p = music.play();
    if (p && typeof p.catch === "function") {
      p.catch(function () {
        // Browsers may block autoplay until a gesture — retry on first interaction.
        var unlock = function () {
          music.play().catch(function () {});
          document.removeEventListener("pointerdown", unlock, true);
          document.removeEventListener("keydown", unlock, true);
        };
        document.addEventListener("pointerdown", unlock, true);
        document.addEventListener("keydown", unlock, true);
      });
    }
  }

  function wireVideos() {
    [videoNovice, videoAdvanced].forEach(function (v) {
      if (!v) return;
      v.muted = true;
      v.loop = true;
      v.playsInline = true;
      // Show first frame while paused (seek slightly if needed).
      try {
        if (v.readyState >= 1) v.currentTime = 0.01;
      } catch (_) {}
      v.addEventListener("loadeddata", function () {
        try {
          if (v.paused) v.currentTime = 0.01;
        } catch (_) {}
      });
    });

    function bindPath(btn, mode) {
      if (!btn) return;
      btn.addEventListener("mouseenter", function () { activatePath(mode); });
      btn.addEventListener("mouseleave", function () { clearPathHover(); });
      btn.addEventListener("focus", function () { activatePath(mode); });
      btn.addEventListener("blur", function () { clearPathHover(); });
    }
    bindPath(chooseNovice, "novice");
    bindPath(chooseAdvanced, "advanced");
  }

  async function api(path, opts) {
    var res = await fetch(path, Object.assign({ credentials: "same-origin" }, opts || {}));
    var data = {};
    try {
      data = await res.json();
    } catch (_) {
      data = {};
    }
    if (!res.ok) {
      var err = new Error((data && data.error) || "Request failed (" + res.status + ")");
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  function defaultBase(provider) {
    return provider === "gitlab" ? "https://gitlab.com" : "https://github.com";
  }

  function wireAdvancedDefaults() {
    var provider = document.getElementById("advProvider");
    var base = document.getElementById("advBaseUrl");
    var authKey = document.getElementById("advAuthKey");
    if (!provider || !base) return;
    function sync() {
      var p = provider.value || "github";
      if (!base.value || base.value === "https://github.com" || base.value === "https://gitlab.com") {
        base.value = defaultBase(p);
      }
      if (authKey && (!authKey.dataset.touched || authKey.value === "gitops_github_pat" || authKey.value === "gitops_gitlab_token")) {
        authKey.value = p === "gitlab" ? "gitops_gitlab_token" : "gitops_github_pat";
      }
    }
    provider.addEventListener("change", sync);
    if (authKey) {
      authKey.addEventListener("input", function () {
        authKey.dataset.touched = "1";
      });
    }
    if (!base.value) base.value = defaultBase(provider.value || "github");
  }

  async function finish(body) {
    return api("/api/setup/complete", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body || {}),
    });
  }

  async function boot() {
    // Keep first-run setup behind the post-login risk acknowledgment.
    var st;
    try {
      st = await api("/api/setup/status");
    } catch (e) {
      if (e && e.data && e.data.code === "liability_ack_required") {
        if (typeof window.hayabusaWhenLiabilityAcked === "function") {
          window.hayabusaWhenLiabilityAcked(function () {
            boot();
          });
        }
        return;
      }
      if (lead) lead.textContent = (e && e.message) || "Unable to load setup status.";
      return;
    }
    if (st.completed) {
      window.location.href = "/";
      return;
    }
    if (!st.can_manage) {
      show(waitingEl, true);
      show(wizardEl, false);
      if (lead) {
        lead.textContent = "Only the administrator can finish first-run setup on this controller.";
      }
      return;
    }
    show(waitingEl, false);
    show(wizardEl, true);
    showStep("choice");
    wireAdvancedDefaults();
    wireVideos();
    startMusic();
  }

  function on(id, evt, fn) {
    var el = document.getElementById(id);
    if (el) el.addEventListener(evt, fn);
  }

  on("chooseNovice", "click", function () {
    showStep("novice");
    setMsg(noviceMsg, "");
  });
  on("chooseAdvanced", "click", function () {
    showStep("advanced");
    setMsg(advancedMsg, "");
  });
  on("noviceBackBtn", "click", function () {
    showStep("choice");
  });
  on("advancedBackBtn", "click", function () {
    showStep("choice");
  });

  on("noviceConfirmBtn", "click", async function () {
    var btn = document.getElementById("noviceConfirmBtn");
    setMsg(noviceMsg, "");
    if (btn) btn.disabled = true;
    try {
      await finish({ mode: "novice" });
      setMsg(noviceMsg, "Setup complete. Opening the controller…", false);
      window.location.href = "/";
    } catch (e) {
      setMsg(noviceMsg, (e && e.message) || "Setup failed", true);
      if (btn) btn.disabled = false;
    }
  });

  on("advancedForm", "submit", async function (ev) {
    ev.preventDefault();
    var btn = document.getElementById("advancedSubmitBtn");
    setMsg(advancedMsg, "");
    if (btn) btn.disabled = true;
    var body = {
      mode: "advanced",
      team_id: (document.getElementById("advTeamId") || {}).value
        ? document.getElementById("advTeamId").value.trim()
        : "",
      team_name: (document.getElementById("advTeamName") || {}).value
        ? document.getElementById("advTeamName").value.trim()
        : "",
      provider: document.getElementById("advProvider").value,
      base_url: document.getElementById("advBaseUrl").value.trim(),
      repo: document.getElementById("advRepo").value.trim(),
      ref: document.getElementById("advRef").value.trim() || "main",
      path_prefix: document.getElementById("advPathPrefix").value.trim(),
      ztp_repo: document.getElementById("advZtpRepo").value.trim(),
      ztp_ref: (document.getElementById("advZtpRef") || {}).value
        ? document.getElementById("advZtpRef").value.trim()
        : "",
      ztp_path_prefix: (document.getElementById("advZtpPathPrefix") || {}).value
        ? document.getElementById("advZtpPathPrefix").value.trim()
        : "",
      poll_seconds: Number(document.getElementById("advPoll").value) || 600,
      auth_secret_key: document.getElementById("advAuthKey").value.trim(),
      auth_token: document.getElementById("advAuthToken").value,
      webhook_secret_key: document.getElementById("advWebhookKey").value.trim(),
      webhook_secret: document.getElementById("advWebhookSecret").value,
    };
    if (!body.team_id && !body.team_name) {
      setMsg(advancedMsg, "Choose an existing team id or enter a new team name for the Git binding.", true);
      if (btn) btn.disabled = false;
      return;
    }
    if (!body.ztp_repo) {
      setMsg(advancedMsg, "ZTP scripts repository is required for Advanced mode.", true);
      if (btn) btn.disabled = false;
      return;
    }
    try {
      await finish(body);
      setMsg(advancedMsg, "GitOps configured. Opening the controller…", false);
      window.location.href = "/";
    } catch (e) {
      setMsg(advancedMsg, (e && e.message) || "Setup failed", true);
      if (btn) btn.disabled = false;
    }
  });

  // Do not reveal the setup wizard until the risk acknowledgment is accepted.
  if (typeof window.hayabusaWhenLiabilityAcked === "function") {
    window.hayabusaWhenLiabilityAcked(function () {
      boot();
    });
  } else {
    boot();
  }
})();
