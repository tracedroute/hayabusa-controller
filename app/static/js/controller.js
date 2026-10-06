(function () {
  function toast(message, kind) {
    var host = document.getElementById("toastHost");
    if (!host) {
      window.alert(message);
      return;
    }
    var el = document.createElement("div");
    el.className = "toast " + (kind === "err" ? "toast-err" : "toast-ok");
    el.textContent = message;
    host.appendChild(el);
    setTimeout(function () {
      el.remove();
    }, 4200);
  }

  async function api(path, opts) {
    var res = await fetch(path, Object.assign({
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
    }, opts || {}));
    var data = await res.json().catch(function () { return {}; });
    if (!res.ok) {
      throw new Error(data.message || data.error || res.statusText || "Request failed");
    }
    return data;
  }

  function setText(id, value) {
    var el = document.getElementById(id);
    if (el) el.textContent = value;
  }

  function setPill(id, kind, label) {
    var el = document.getElementById(id);
    if (!el) return;
    el.className = "pill pill-" + kind;
    el.textContent = label;
  }

  function paintGitopsNav(cfg) {
    var el = document.getElementById("gitopsNavHint");
    if (!el) return;
    if (!cfg || !cfg.enabled) {
      el.hidden = true;
      el.textContent = "";
      return;
    }
    var provider = String(cfg.provider || "").toLowerCase();
    var name = provider === "gitlab" ? "GitLab"
      : (provider === "github" ? "GitHub" : (provider ? provider.charAt(0).toUpperCase() + provider.slice(1) : "Git"));
    var base = String(cfg.base_url || "").replace(/\/+$/, "");
    el.hidden = false;
    el.textContent = "";
    el.appendChild(document.createTextNode("Connected to " + name + (base ? " · " : "")));
    if (base) {
      var a = document.createElement("a");
      a.href = base;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      a.textContent = base;
      el.appendChild(a);
    }
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c];
    });
  }

  function yn(v) {
    return v ? "yes" : "no";
  }

  var TAB_META = {
    overview: {
      title: "Overview",
      lead: "This node phones home to Hayabusa, joins its mesh privately, and keeps site services on the local LAN.",
    },
    connection: {
      title: "Connection",
      lead: "Enroll with Hayabusa, join the mesh VPN, and keep the control bridge granted.",
    },
    jobs: {
      title: "Job approvals",
      lead: "Approve Hayabusa job requests on this LAN. Approving grants permission and hydrates secret names into the playbook as it passes through — Hayabusa runs Ansible/OpenTofu (never the controller).",
    },
    blueprints: {
      title: "Gameplan & Blueprints",
      lead: "Saved visual orchestration graphs from Hayabusa Foundry. This controller is the source of truth; Ansible/OpenTofu trees are never modified by Gameplan.",
    },
    integrations: {
      title: "Integrations",
      lead: "Webhooks, builder apps, and automation jobs synced from Hayabusa when this controller branch is selected. URLs stay masked on the LAN UI.",
    },
    backups: {
      title: "Backup jobs",
      lead: "Host-to-host Ansible backups stored on this controller. The same jobs appear in Hayabusa Core when this controller branch is selected.",
    },
    access: {
      title: "Access",
      lead: "Your permissions on this controller, and sync owned playbooks to Hayabusa. Owners and admins manage roles under Administration.",
    },
    ztp: {
      title: "ZTP & DHCP",
      lead: "Hand out addresses and configuration when local hosts request an IP or network boot. LAN approval required — same flow as Ansible/OpenTofu.",
    },
    secrets: {
      title: "Secrets",
      lead: "Credentials for any host or system — network, VMs, DBs, cloud, IoT. Tag by category and target host. Catalog with read_secrets; edit values with manage_secrets.",
    },
    gitops: {
      title: "GitOps",
      lead: "GitLab/GitHub push updates this controller (via Hayabusa). Packaged default playbooks are never overwritten. Secrets and LAN approve stay here.",
    },
    tools: {
      title: "Tools",
      lead: "Apache Guacamole console for this site’s LAN, plus the Ansible / OpenTofu workspace stored on this controller.",
    },
  };

  function showTab(name) {
    var tab = TAB_META[name] ? name : "overview";
    document.querySelectorAll(".page-tab").forEach(function (btn) {
      btn.classList.toggle("is-active", btn.getAttribute("data-tab") === tab);
    });
    document.querySelectorAll(".tab-panel").forEach(function (panel) {
      var match = panel.getAttribute("data-panel") === tab;
      panel.classList.toggle("is-active", match);
      if (match) panel.removeAttribute("hidden");
      else panel.setAttribute("hidden", "");
    });
    var meta = TAB_META[tab];
    setText("pageTitle", meta.title);
    setText("pageLead", meta.lead);
    try {
      history.replaceState(null, "", "#" + tab);
    } catch (_) {}
    if (tab === "ztp" && typeof loadZtpPanel === "function") {
      loadZtpPanel();
    }
    if (tab === "jobs" && typeof loadJobsPanel === "function") {
      loadJobsPanel();
    }
    if (tab === "blueprints" && typeof loadGameplanPanel === "function") {
      loadGameplanPanel();
    }
    if (tab === "integrations" && typeof loadIntegrationsPanel === "function") {
      loadIntegrationsPanel();
    }
    if (tab === "backups" && typeof loadBackupsPanel === "function") {
      loadBackupsPanel();
    }
    if (tab === "access" && typeof loadAccessPanel === "function") {
      loadAccessPanel();
    }
    if (tab === "secrets" && typeof loadSecretsPanel === "function") {
      loadSecretsPanel();
    }
    if (tab === "gitops" && typeof loadGitopsPanel === "function") {
      loadGitopsPanel();
    }
    if (tab === "tools" && typeof loadGuacPanel === "function") {
      loadGuacPanel();
    }
  }

  function paintConnection(conn) {
    if (!conn || !conn.steps) return;
    var phase = conn.phase || "idle";
    var ready = !!conn.ready && !!conn.bridge_granted;
    setText("connPhase", ready ? "ready" : phase);
    var phaseLine = document.getElementById("connPhaseLine");
    if (phaseLine) {
      phaseLine.classList.toggle("is-ready", ready);
      phaseLine.classList.toggle("is-partial", !ready && (phase === "partial" || String(phase).indexOf("running") >= 0));
    }
    ["enroll", "mesh", "bridge"].forEach(function (step) {
      var info = conn.steps[step] || {};
      var state = info.state || "idle";
      var el = document.getElementById(
        step === "enroll" ? "stepEnroll" : step === "mesh" ? "stepMesh" : "stepBridge"
      );
      if (el) {
        el.className = "conn-step" + (
          state === "ok" ? " is-ok" :
          state === "running" || state === "pending" ? (state === "running" ? " is-running" : " is-pending") :
          state === "failed" || state === "error" ? " is-failed" : ""
        );
      }
      var stateId = step === "enroll" ? "stepEnrollState" : step === "mesh" ? "stepMeshState" : "stepBridgeState";
      var detailId = step === "enroll" ? "stepEnrollDetail" : step === "mesh" ? "stepMeshDetail" : "stepBridgeDetail";
      setText(stateId, state);
      setText(detailId, info.detail || "—");
    });
    // Overall Connection pill: mesh IP alone is never "ok/connected".
    if (ready) {
      setPill("enrollPillConn", "ok", "Linked");
    } else if (conn.mesh_connected && !conn.bridge_granted) {
      setPill("enrollPillConn", "warn", "Mesh only");
    } else if (conn.steps && conn.steps.enroll && conn.steps.enroll.state === "ok") {
      setPill("enrollPillConn", "warn", "Enrolled");
    } else {
      setPill("enrollPillConn", "idle", "Not linked");
    }
  }

  function paintStatus(st) {
    if (!st) return;

    if (st.connection) {
      paintConnection(st.connection);
    }

    if (st.enroll) {
      var enrolled = !!(st.enroll.enrolled || st.enroll.ok);
      setText("enrollOk", yn(enrolled));
      setText("enrollOkLabel", enrolled ? "Enrolled" : "Not enrolled");
      setPill("enrollPill", enrolled ? "ok" : "warn", enrolled ? "Enrolled" : "Pending");
      // enrollPillConn is owned by paintConnection (requires bridge grant for "Linked").
    }

    if (st.vpn) {
      setText("vpnConnected", yn(!!st.vpn.connected));
      setText("vpnHealth", st.vpn.health || (st.vpn.connected ? "connected" : (st.vpn.error ? "error" : "disconnected")));
      setText("vpnBackend", st.vpn.backend || "—");
      setText("vpnIp", st.vpn.ip || "—");
      setText("vpnIpOverview", st.vpn.ip || "—");
      setText("vpnServer", st.vpn.mesh_server || "—");
      setText("vpnError", st.vpn.error || "—");
      // Overview tile: mesh IP is informational; not a stand-in for full Hayabusa link.
      setText(
        "vpnIpLabel",
        st.vpn.connected && st.vpn.ip
          ? st.vpn.ip
          : (st.vpn.connected ? "Mesh up" : "Not connected")
      );
      var errEl = document.getElementById("vpnError");
      if (errEl) errEl.classList.toggle("err-text", !!st.vpn.error);
      var banner = document.getElementById("vpnFailBanner");
      if (banner) {
        // Never show join-failed when mesh is actually up (stale error / CSS hidden bugs).
        var meshUp = !!(st.vpn.connected || st.vpn.health === "connected" || (st.vpn.ip && String(st.vpn.ip).indexOf("100.") === 0));
        if (st.vpn.error && !meshUp) {
          banner.removeAttribute("hidden");
          setText("vpnFailCode", st.vpn.error_code || "");
          setText("vpnFailDetail", st.vpn.error);
          setText("vpnFailFix", st.vpn.fix ? ("Fix: " + st.vpn.fix) : "");
          setText("vpnFailTitle", st.vpn.error_code ? ("Mesh join failed (" + st.vpn.error_code + ")") : "Mesh join failed");
        } else {
          banner.setAttribute("hidden", "");
          if (meshUp) {
            setText("vpnFailCode", "");
            setText("vpnFailDetail", "");
            setText("vpnFailFix", "");
          }
        }
      }
    }

    if (st.bridge) {
      setText("brMode", st.bridge.mode || "—");
      setText("brConn", yn(!!st.bridge.connected));
      setText("brGrant", yn(!!st.bridge.granted));
      setText("brEvent", st.bridge.last_event || "—");
      setText("brError", st.bridge.last_error || "—");
      var wsUrl = String(st.bridge.ws_url || "");
      var pathLabel = "—";
      if (wsUrl.indexOf("100.64.") >= 0 || wsUrl.indexOf("ws://100.") === 0) {
        pathLabel = "Mesh VPN " + wsUrl + " (encrypted tunnel; ws:// is expected)";
      } else if (wsUrl.indexOf("wss://") === 0) {
        pathLabel = "Public TLS " + wsUrl;
      } else if (wsUrl) {
        pathLabel = wsUrl;
      }
      setText("brPath", pathLabel);
      setText("rpcOk", String(st.bridge.rpc_ok ?? 0));
      setText("rpcErr", String(st.bridge.rpc_err ?? 0));
      setText("rpcEvent", st.bridge.last_event || "—");
      setText("rpcOverview", (st.bridge.granted && st.bridge.connected) ? "Linked" : (st.bridge.granted ? "Granted" : "Waiting"));
      if (st.bridge.granted && st.bridge.connected) {
        setPill("rpcPill", "ok", "Linked");
      } else if (st.bridge.granted) {
        setPill("rpcPill", "warn", "Granted");
      } else {
        setPill("rpcPill", "idle", "Waiting");
      }
      if (st.bridge.granted) {
        setText("brGrantLabel", "Granted");
        setText("brOverview", "Granted");
        setPill("bridgePill", "ok", "Granted");
      } else if (st.bridge.connected) {
        setText("brGrantLabel", "Connected");
        setText("brOverview", "Connected");
        setPill("bridgePill", "warn", "Connected");
      } else if ((st.bridge.mode || "") === "live") {
        setText("brGrantLabel", "Reconnecting");
        setText("brOverview", "Reconnecting");
        setPill("bridgePill", "warn", "Live");
      } else {
        setText("brGrantLabel", "Standby");
        setText("brOverview", "Standby");
        setPill("bridgePill", "idle", "Standby");
      }
    }
    if (st.ztp_edge) {
      paintZtpSummary(st.ztp_edge);
    }

    if (st.secrets) {
      setText("secCount", String(st.secrets.count ?? 0));
      if (typeof paintSecretsCatalog === "function") {
        paintSecretsCatalog(st.secrets);
      }
    }

    if (st.hayabusa_public_url) {
      setText("introducerUrl", st.hayabusa_public_url);
      setText("introducerUrlConn", st.hayabusa_public_url);
    }
  }

  var enrollBtn = document.getElementById("enrollBtn");
  if (enrollBtn) {
    enrollBtn.addEventListener("click", async function () {
      enrollBtn.disabled = true;
      try {
        var res = await api("/api/vpn/enroll", { method: "POST", body: "{}" });
        paintStatus(res);
        paintStatus(await api("/api/status"));
        if (res.ok && res.bridge && res.bridge.granted) {
          toast("Enrolled and control bridge granted", "ok");
        } else if (res.vpn && res.vpn.connected && !(res.bridge && res.bridge.granted)) {
          var meshOnly =
            res.error ||
            "Mesh VPN is up, but the control bridge is not granted — not fully connected";
          if (res.fix) meshOnly += " — " + res.fix;
          toast(meshOnly, "err");
        } else {
          var detail = res.error || (res.vpn && res.vpn.error) || "Enrollment finished with errors";
          if (res.fix) detail += " — " + res.fix;
          toast(detail, "err");
        }
      } catch (err) {
        toast(err.message || "Enrollment failed", "err");
        try { paintStatus(await api("/api/status")); } catch (_) {}
      } finally {
        enrollBtn.disabled = false;
      }
    });
  }

  var vpnForm = document.getElementById("vpnForm");
  if (vpnForm) {
    vpnForm.addEventListener("submit", async function (e) {
      e.preventDefault();
      try {
        var fd = new FormData(vpnForm);
        await api("/api/vpn/configure", {
          method: "POST",
          body: JSON.stringify({
            mesh_server: fd.get("mesh_server"),
            preauth_key: fd.get("preauth_key"),
            hostname: fd.get("hostname"),
          }),
        });
        var joined = await api("/api/vpn/join", { method: "POST", body: "{}" });
        paintStatus(joined);
        paintStatus(await api("/api/status"));
        if (joined.ok === false || (joined.vpn && !joined.vpn.connected)) {
          toast((joined.vpn && joined.vpn.error) || joined.error || "Mesh join failed", "err");
        } else {
          toast("Mesh join succeeded", "ok");
        }
      } catch (err) {
        toast(err.message || "Mesh join failed", "err");
        try { paintStatus(await api("/api/status")); } catch (_) {}
      }
    });
  }

  var secretsState = {
    canManage: false,
    canRead: false,
    catalog: [],
    categories: [],
    kinds: [],
    editingKey: null,
  };

  function fillSecretSelects(categories, kinds) {
    var catSel = document.getElementById("secretFormCategory");
    var kindSel = document.getElementById("secretFormKind");
    var filterCat = document.getElementById("secretFilterCategory");
    if (catSel) {
      catSel.innerHTML = (categories || []).map(function (c) {
        return '<option value="' + escapeHtml(c.id) + '">' + escapeHtml(c.label || c.id) + "</option>";
      }).join("");
    }
    if (kindSel) {
      kindSel.innerHTML = (kinds || []).map(function (k) {
        return '<option value="' + escapeHtml(k.id) + '">' + escapeHtml(k.label || k.id) + "</option>";
      }).join("");
    }
    if (filterCat) {
      var cur = filterCat.value || "";
      filterCat.innerHTML = '<option value="">All categories</option>' + (categories || []).map(function (c) {
        return '<option value="' + escapeHtml(c.id) + '">' + escapeHtml(c.label || c.id) + "</option>";
      }).join("");
      filterCat.value = cur;
    }
  }

  function resetSecretForm() {
    var form = document.getElementById("secretForm");
    if (!form) return;
    form.reset();
    secretsState.editingKey = null;
    var keyInput = document.getElementById("secretFormKey");
    if (keyInput) {
      keyInput.readOnly = false;
      keyInput.disabled = false;
    }
    var val = document.getElementById("secretFormValue");
    if (val) val.required = true;
    var submit = document.getElementById("secretFormSubmit");
    if (submit) submit.textContent = "Store secret";
    var cancel = document.getElementById("secretFormCancel");
    if (cancel) cancel.hidden = true;
  }

  function paintSecretsCatalog(st) {
    st = st || {};
    secretsState.catalog = Array.isArray(st.catalog) ? st.catalog : [];
    if (Array.isArray(st.categories)) secretsState.categories = st.categories;
    if (Array.isArray(st.kinds)) secretsState.kinds = st.kinds;
    if (typeof st.can_manage === "boolean") secretsState.canManage = st.can_manage;
    if (typeof st.can_read === "boolean") secretsState.canRead = st.can_read;
    else if (secretsState.canManage) secretsState.canRead = true;
    fillSecretSelects(secretsState.categories, secretsState.kinds);

    var note = document.getElementById("secretsPermNote");
    var form = document.getElementById("secretForm");
    if (note) {
      if (secretsState.canManage) {
        note.textContent = "You can view the catalog and edit secret values.";
      } else if (secretsState.canRead) {
        note.textContent = "Read-only catalog (read_secrets). Values are hidden.";
      } else {
        note.textContent = "You do not have read_secrets or manage_secrets.";
      }
    }
    if (form) {
      form.hidden = !secretsState.canManage;
    }

    var body = document.getElementById("secretCatalogBody");
    if (!body) return;
    var catFilter = (document.getElementById("secretFilterCategory") || {}).value || "";
    var hostFilter = String((document.getElementById("secretFilterHost") || {}).value || "").trim().toLowerCase();
    var rows = secretsState.catalog.filter(function (row) {
      if (catFilter && row.category !== catFilter) return false;
      if (hostFilter && String(row.host || "").toLowerCase().indexOf(hostFilter) < 0) return false;
      return true;
    });
    if (!secretsState.canRead && !secretsState.canManage) {
      body.innerHTML = '<tr class="empty-row"><td colspan="6">No permission to view secrets</td></tr>';
      return;
    }
    if (!rows.length) {
      body.innerHTML = '<tr class="empty-row"><td colspan="6">No secrets match filters</td></tr>';
      return;
    }
    body.innerHTML = rows.map(function (row) {
      var actions = "";
      if (secretsState.canManage) {
        actions =
          '<button type="button" class="btn-ghost secret-edit-btn" data-key="' + escapeHtml(row.key) + '">Edit</button> ' +
          '<button type="button" class="btn-ghost btn-danger secret-del-btn" data-key="' + escapeHtml(row.key) + '">Delete</button>';
      }
      return (
        "<tr>" +
        "<td><code>" + escapeHtml(row.key) + "</code></td>" +
        "<td>" + escapeHtml(row.category_label || row.category || "—") + "</td>" +
        "<td>" + escapeHtml(row.kind_label || row.kind || "—") + "</td>" +
        '<td class="host-cell">' + escapeHtml(row.host || "—") + "</td>" +
        "<td>" + escapeHtml(row.label || "—") + "</td>" +
        '<td class="actions-cell">' + actions + "</td>" +
        "</tr>"
      );
    }).join("");
  }

  async function loadSecretsPanel() {
    try {
      var rbac = await api("/api/rbac");
      var perms = (rbac.me && rbac.me.permissions) || [];
      secretsState.canManage = perms.indexOf("manage_secrets") >= 0;
      secretsState.canRead = secretsState.canManage || perms.indexOf("read_secrets") >= 0;
      var data = await api("/api/secrets");
      paintSecretsCatalog(data);
    } catch (err) {
      toast(err.message || "Could not load secrets", "err");
    }
  }

  async function startSecretEdit(key) {
    if (!secretsState.canManage) return;
    try {
      var data = await api("/api/secrets/" + encodeURIComponent(key));
      secretsState.editingKey = key;
      var keyInput = document.getElementById("secretFormKey");
      if (keyInput) {
        keyInput.value = key;
        keyInput.readOnly = true;
      }
      var meta = data.meta || {};
      var cat = document.getElementById("secretFormCategory");
      if (cat) cat.value = meta.category || "general";
      var kind = document.getElementById("secretFormKind");
      if (kind) kind.value = meta.kind || "other";
      var host = document.getElementById("secretFormHost");
      if (host) host.value = meta.host || "";
      var label = document.getElementById("secretFormLabel");
      if (label) label.value = meta.label || "";
      var val = document.getElementById("secretFormValue");
      if (val) {
        val.value = data.value || "";
        val.required = false;
        val.placeholder = "Leave blank to keep current value";
      }
      var submit = document.getElementById("secretFormSubmit");
      if (submit) submit.textContent = "Save changes";
      var cancel = document.getElementById("secretFormCancel");
      if (cancel) cancel.hidden = false;
      document.getElementById("secretForm").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (err) {
      toast(err.message || "Could not load secret", "err");
    }
  }

  var secretForm = document.getElementById("secretForm");
  if (secretForm) {
    secretForm.addEventListener("submit", async function (e) {
      e.preventDefault();
      if (!secretsState.canManage) {
        toast("Missing manage_secrets permission", "err");
        return;
      }
      try {
        var fd = new FormData(secretForm);
        var key = String(fd.get("key") || "").trim();
        var payload = {
          category: String(fd.get("category") || "general"),
          kind: String(fd.get("kind") || "other"),
          host: String(fd.get("host") || ""),
          label: String(fd.get("label") || ""),
        };
        var val = String(fd.get("value") || "");
        if (secretsState.editingKey) {
          if (val) payload.value = val;
          await api("/api/secrets/" + encodeURIComponent(secretsState.editingKey), {
            method: "PATCH",
            body: JSON.stringify(payload),
          });
          toast("Secret updated", "ok");
        } else {
          payload.value = val;
          await api("/api/secrets/" + encodeURIComponent(key), {
            method: "PUT",
            body: JSON.stringify(payload),
          });
          toast("Secret stored", "ok");
        }
        resetSecretForm();
        loadSecretsPanel();
        paintStatus(await api("/api/status"));
      } catch (err) {
        toast(err.message || "Could not store secret", "err");
      }
    });
  }

  var secretFormCancel = document.getElementById("secretFormCancel");
  if (secretFormCancel) {
    secretFormCancel.addEventListener("click", function () {
      resetSecretForm();
    });
  }

  var secretsRefreshBtn = document.getElementById("secretsRefreshBtn");
  if (secretsRefreshBtn) {
    secretsRefreshBtn.addEventListener("click", loadSecretsPanel);
  }

  async function loadGitopsPanel() {
    try {
      var data = await api("/api/gitops/config");
      var can = !!data.can_manage;
      setText("gitopsPermNote", can
        ? "You can configure GitOps (manage_gitops)."
        : "View only — need manage_gitops to change settings.");
      var form = document.getElementById("gitopsForm");
      if (form) {
        Array.prototype.forEach.call(form.querySelectorAll("input, select, button"), function (el) {
          if (el.id === "gitopsRefreshBtn") return;
          if (el.type === "button" && el.id === "gitopsRefreshBtn") return;
          if (el.id === "gitopsSaveBtn" || el.id === "gitopsTestBtn" || el.id === "gitopsSyncBtn" || el.type === "submit") {
            el.disabled = !can;
          } else if (el.tagName !== "BUTTON") {
            el.disabled = !can;
          }
        });
      }
      var en = document.getElementById("gitopsEnabled");
      if (en) en.checked = !!data.enabled;
      setVal("gitopsProvider", data.provider || "github");
      setVal("gitopsBaseUrl", data.base_url || "");
      setVal("gitopsRepo", data.repo || "");
      setVal("gitopsRef", data.ref || "main");
      setVal("gitopsPathPrefix", data.path_prefix || "");
      setVal("gitopsZtpRepo", data.ztp_repo || "");
      setVal("gitopsZtpRef", data.ztp_ref || "");
      setVal("gitopsZtpPathPrefix", data.ztp_path_prefix || "");
      setVal("gitopsAuthKey", data.auth_secret_key || "");
      setVal("gitopsWebhookKey", data.webhook_secret_key || "");
      setVal("gitopsPoll", String(data.poll_seconds || 600));
      setText("gitopsNote", (data.ztp_source ? ("ZTP source: " + data.ztp_source + ". ") : "") + (data.webhook_note || ""));
      var ls = data.last_sync || {};
      var lsText = "never";
      if (ls.at) {
        lsText = (ls.ok ? "ok" : "failed") + " · " + new Date(Number(ls.at) * 1000).toLocaleString();
        if (ls.source) lsText += " · " + ls.source;
        if (ls.error) lsText += " · " + ls.error;
      }
      setText("gitopsLastSync", lsText);
      setText("gitopsSha", ls.sha || "—");
      paintGitopsNav(data);
      var wh = data.webhook_paths || {};
      setText("gitopsWebhookPaths", "GitHub: " + (wh.github || "—") + " · GitLab: " + (wh.gitlab || "—"));
      setText("gitopsBridge", data.bridge_connected ? "connected" : "disconnected");
      setText(
        "gitopsNote",
        (data.ztp_source ? ("ZTP source: " + data.ztp_source + ". ") : "") + (data.webhook_note || "")
      );
      await loadGitopsBindingsPanel();
    } catch (err) {
      toast(String(err.message || err), "err");
    }
  }

  async function loadGitopsBindingsPanel() {
    try {
      var data = await api("/api/gitops/team-bindings");
      var links = data.linked_accounts || {};
      var linkBits = Object.keys(links).map(function (p) {
        return p + ":" + (links[p].login || links[p].id || "linked");
      });
      setText("gitopsLinkedMe", "Linked accounts: " + (linkBits.length ? linkBits.join(", ") : "none — use OAuth Link below"));
      try {
        var st = await api("/api/gitops/oauth-link-status");
        var gl = document.getElementById("gitopsLinkGitlabBtn");
        var gh = document.getElementById("gitopsLinkGithubBtn");
        if (gl) {
          gl.href = (st.gitlab && st.gitlab.start_url) || "/auth/gitlab/start?link=1";
          gl.style.opacity = st.gitlab && st.gitlab.configured ? "1" : "0.55";
          gl.title = st.gitlab && st.gitlab.configured ? "OAuth against configured GitLab" : "GitLab OAuth app not configured yet";
        }
        if (gh) {
          gh.href = (st.github && st.github.start_url) || "/auth/github/start?link=1";
          gh.style.opacity = st.github && st.github.configured ? "1" : "0.55";
          gh.title = st.github && st.github.configured ? "OAuth against GitHub" : "GitHub OAuth not configured on this controller";
        }
        var declareBox = document.getElementById("gitopsDeclareLink");
        if (declareBox) {
          var anyDeclare =
            !!(st.declare_allowed) &&
            ((st.gitlab && st.gitlab.declare_allowed) || (st.github && st.github.declare_allowed) || st.declare_override);
          declareBox.style.display = anyDeclare ? "" : "none";
          var sel = document.getElementById("gitopsDeclareProvider");
          if (sel) {
            Array.prototype.forEach.call(sel.options || [], function (opt) {
              var p = (opt.value || "").toLowerCase();
              var allowed =
                st.declare_override ||
                (p === "gitlab" && st.gitlab && st.gitlab.declare_allowed) ||
                (p === "github" && st.github && st.github.declare_allowed);
              opt.disabled = !allowed;
            });
          }
        }
      } catch (_e) {}
      var ul = document.getElementById("gitopsBindingsList");
      var bindings = data.bindings || [];
      if (ul) {
        if (!bindings.length) {
          ul.innerHTML = '<li class="empty">No team Git bindings yet</li>';
        } else {
          ul.innerHTML = bindings
            .map(function (b) {
              return (
                "<li><code>" +
                escapeHtml(b.team_id || "") +
                "</code> → " +
                escapeHtml(b.provider || "") +
                " " +
                escapeHtml(b.repo || "") +
                ' <button type="button" class="btn btn-ghost btn-tiny" data-bind-pub="' +
                escapeHtml(b.id || "") +
                '">Preview &amp; publish</button>' +
                ' <button type="button" class="btn btn-ghost btn-tiny" data-bind-del="' +
                escapeHtml(b.id || "") +
                '">Remove</button></li>'
              );
            })
            .join("");
        }
      }
      var pubId = document.getElementById("gitopsPublishBindingId");
      if (pubId && bindings[0]) pubId.value = bindings[0].id || "";
      var form = document.getElementById("gitopsBindingForm");
      if (form) {
        Array.prototype.forEach.call(form.querySelectorAll("input, select, button[type=submit]"), function (el) {
          el.disabled = data.can_manage === false && el.id !== "gitopsPublishBtn";
        });
      }
    } catch (err) {
      setText("gitopsLinkedMe", "Could not load bindings: " + (err.message || err));
    }
  }

  function hidePublishPreview() {
    var box = document.getElementById("gitopsPublishPreview");
    if (box) box.style.display = "none";
    var list = document.getElementById("gitopsPublishFileList");
    if (list) list.innerHTML = "";
  }

  function showPublishPreview(out) {
    var box = document.getElementById("gitopsPublishPreview");
    var list = document.getElementById("gitopsPublishFileList");
    setText("gitopsPublishNote", out.message || (out.owned_file_count || 0) + " file(s) ready");
    if (list) {
      var files = out.files || [];
      list.innerHTML = files.length
        ? files
            .map(function (f) {
              return (
                "<li><code>" +
                escapeHtml(f.path || "") +
                "</code> → <code>" +
                escapeHtml(f.dest || "") +
                "</code> (" +
                Number(f.bytes || 0) +
                " B)</li>"
              );
            })
            .join("")
        : '<li class="empty">No files</li>';
    }
    if (box) box.style.display = "block";
  }

  async function previewPublishOwned(bindingId) {
    var out = await api("/api/gitops/publish-owned", {
      method: "POST",
      body: JSON.stringify({ binding_id: bindingId, dry_run: true }),
    });
    showPublishPreview(out);
    return out;
  }

  async function confirmPublishOwned(bindingId) {
    var out = await api("/api/gitops/publish-owned", {
      method: "POST",
      body: JSON.stringify({ binding_id: bindingId, confirm: true }),
    });
    hidePublishPreview();
    setText("gitopsPublishNote", out.message || "Published");
    toast(out.message || "Published owned files", out.ok ? "ok" : "err");
    return out;
  }

  function setVal(id, v) {
    var el = document.getElementById(id);
    if (el) el.value = v;
  }

  var gitopsForm = document.getElementById("gitopsForm");
  if (gitopsForm) {
    gitopsForm.addEventListener("submit", async function (e) {
      e.preventDefault();
      var body = {
        enabled: !!(document.getElementById("gitopsEnabled") || {}).checked,
        provider: (document.getElementById("gitopsProvider") || {}).value || "github",
        base_url: (document.getElementById("gitopsBaseUrl") || {}).value || "",
        repo: (document.getElementById("gitopsRepo") || {}).value || "",
        ref: (document.getElementById("gitopsRef") || {}).value || "main",
        path_prefix: (document.getElementById("gitopsPathPrefix") || {}).value || "",
        ztp_repo: (document.getElementById("gitopsZtpRepo") || {}).value || "",
        ztp_ref: (document.getElementById("gitopsZtpRef") || {}).value || "",
        ztp_path_prefix: (document.getElementById("gitopsZtpPathPrefix") || {}).value || "",
        auth_secret_key: (document.getElementById("gitopsAuthKey") || {}).value || "",
        webhook_secret_key: (document.getElementById("gitopsWebhookKey") || {}).value || "",
        poll_seconds: Number((document.getElementById("gitopsPoll") || {}).value || 600)
      };
      try {
        var out = await api("/api/gitops/config", { method: "PUT", body: JSON.stringify(body) });
        toast(out.warning || out.message || "GitOps saved", out.warning ? "warn" : "ok");
        loadGitopsPanel();
      } catch (err) {
        toast(String(err.message || err), "err");
      }
    });
  }
  var gitopsRefreshBtn = document.getElementById("gitopsRefreshBtn");
  if (gitopsRefreshBtn) gitopsRefreshBtn.addEventListener("click", loadGitopsPanel);
  var gitopsTestBtn = document.getElementById("gitopsTestBtn");
  if (gitopsTestBtn) {
    gitopsTestBtn.addEventListener("click", async function () {
      try {
        var out = await api("/api/gitops/test", { method: "POST", body: "{}" });
        toast(out.message || "Reachable", "ok");
      } catch (err) {
        toast(String(err.message || err), "err");
      }
    });
  }
  var gitopsSyncBtn = document.getElementById("gitopsSyncBtn");
  if (gitopsSyncBtn) {
    gitopsSyncBtn.addEventListener("click", async function () {
      try {
        var out = await api("/api/gitops/sync-now", { method: "POST", body: "{}" });
        toast(out.message || "Pull requested", "ok");
        setTimeout(loadGitopsPanel, 1500);
      } catch (err) {
        toast(String(err.message || err), "err");
      }
    });
  }

  var gitopsBindingForm = document.getElementById("gitopsBindingForm");
  if (gitopsBindingForm) {
    gitopsBindingForm.addEventListener("submit", async function (e) {
      e.preventDefault();
      var body = {
        team_id: (document.getElementById("gitopsBindTeam") || {}).value || "",
        provider: (document.getElementById("gitopsBindProvider") || {}).value || "github",
        base_url: (document.getElementById("gitopsBindBase") || {}).value || "",
        repo: (document.getElementById("gitopsBindRepo") || {}).value || "",
        ref: (document.getElementById("gitopsBindRef") || {}).value || "main",
        auth_secret_key: (document.getElementById("gitopsBindAuthKey") || {}).value || "",
        require_linked_provider: true,
      };
      try {
        var out = await api("/api/gitops/team-bindings", { method: "PUT", body: JSON.stringify(body) });
        toast(out.message || "Team binding saved", "ok");
        if (out.binding && out.binding.id) {
          var hid = document.getElementById("gitopsPublishBindingId");
          if (hid) hid.value = out.binding.id;
        }
        loadGitopsBindingsPanel();
      } catch (err) {
        toast(String(err.message || err), "err");
      }
    });
  }
  var gitopsPublishBtn = document.getElementById("gitopsPublishBtn");
  if (gitopsPublishBtn) {
    gitopsPublishBtn.addEventListener("click", async function () {
      var bid = (document.getElementById("gitopsPublishBindingId") || {}).value || "";
      if (!bid) {
        toast("Select or save a team binding first", "err");
        return;
      }
      try {
        await previewPublishOwned(bid);
        toast("Review the file list, then confirm publish", "ok");
      } catch (err) {
        toast(String(err.message || err), "err");
      }
    });
  }
  var gitopsPublishConfirmBtn = document.getElementById("gitopsPublishConfirmBtn");
  if (gitopsPublishConfirmBtn) {
    gitopsPublishConfirmBtn.addEventListener("click", async function () {
      var bid = (document.getElementById("gitopsPublishBindingId") || {}).value || "";
      if (!bid) return;
      try {
        await confirmPublishOwned(bid);
      } catch (err) {
        toast(String(err.message || err), "err");
      }
    });
  }
  var gitopsPublishCancelBtn = document.getElementById("gitopsPublishCancelBtn");
  if (gitopsPublishCancelBtn) {
    gitopsPublishCancelBtn.addEventListener("click", hidePublishPreview);
  }
  var gitopsLinkRefreshBtn = document.getElementById("gitopsLinkRefreshBtn");
  if (gitopsLinkRefreshBtn) {
    gitopsLinkRefreshBtn.addEventListener("click", async function () {
      try {
        await api("/api/gitops/linked-accounts/me", { method: "POST", body: "{}" });
        loadGitopsBindingsPanel();
        toast("Linked identity refreshed from this session", "ok");
      } catch (err) {
        toast(String(err.message || err), "err");
      }
    });
  }
  var gitopsDeclareLinkForm = document.getElementById("gitopsDeclareLinkForm");
  if (gitopsDeclareLinkForm) {
    gitopsDeclareLinkForm.addEventListener("submit", async function (e) {
      e.preventDefault();
      var provider = (document.getElementById("gitopsDeclareProvider") || {}).value || "gitlab";
      var login = (document.getElementById("gitopsDeclareLogin") || {}).value || "";
      try {
        await api("/api/gitops/linked-accounts/me", {
          method: "POST",
          body: JSON.stringify({ provider: provider, login: login }),
        });
        loadGitopsBindingsPanel();
        toast("Declared " + provider + " link for " + login, "ok");
      } catch (err) {
        toast(String(err.message || err), "err");
      }
    });
  }
  try {
    var qs = new URLSearchParams(window.location.search || "");
    if (qs.get("gitops_linked") === "1") toast("Git identity linked", "ok");
    if (qs.get("gitops_link_error")) toast(qs.get("gitops_link_error"), "err");
  } catch (_e) {}
  var gitopsBindingsList = document.getElementById("gitopsBindingsList");
  if (gitopsBindingsList) {
    gitopsBindingsList.addEventListener("click", async function (e) {
      var pub = e.target && e.target.closest ? e.target.closest("[data-bind-pub]") : null;
      if (pub) {
        var id = pub.getAttribute("data-bind-pub") || "";
        var hid = document.getElementById("gitopsPublishBindingId");
        if (hid) hid.value = id;
        if (gitopsPublishBtn) gitopsPublishBtn.click();
        return;
      }
      var del = e.target && e.target.closest ? e.target.closest("[data-bind-del]") : null;
      if (del) {
        var did = del.getAttribute("data-bind-del") || "";
        try {
          await api("/api/gitops/team-bindings/" + encodeURIComponent(did), { method: "DELETE" });
          toast("Binding removed", "ok");
          loadGitopsBindingsPanel();
        } catch (err) {
          toast(String(err.message || err), "err");
        }
      }
    });
  }

  var secretFilterCategory = document.getElementById("secretFilterCategory");
  if (secretFilterCategory) {
    secretFilterCategory.addEventListener("change", function () {
      paintSecretsCatalog({ catalog: secretsState.catalog, categories: secretsState.categories, kinds: secretsState.kinds, can_manage: secretsState.canManage });
    });
  }
  var secretFilterHost = document.getElementById("secretFilterHost");
  if (secretFilterHost) {
    secretFilterHost.addEventListener("input", function () {
      paintSecretsCatalog({ catalog: secretsState.catalog, categories: secretsState.categories, kinds: secretsState.kinds, can_manage: secretsState.canManage });
    });
  }

  var secretCatalogBody = document.getElementById("secretCatalogBody");
  if (secretCatalogBody) {
    secretCatalogBody.addEventListener("click", async function (e) {
      var editBtn = e.target && e.target.closest ? e.target.closest(".secret-edit-btn") : null;
      if (editBtn) {
        startSecretEdit(editBtn.getAttribute("data-key") || "");
        return;
      }
      var delBtn = e.target && e.target.closest ? e.target.closest(".secret-del-btn") : null;
      if (!delBtn || !secretsState.canManage) return;
      var key = delBtn.getAttribute("data-key") || "";
      if (!key || !window.confirm("Delete secret " + key + "?")) return;
      try {
        await api("/api/secrets/" + encodeURIComponent(key), { method: "DELETE" });
        toast("Secret deleted", "ok");
        resetSecretForm();
        loadSecretsPanel();
        paintStatus(await api("/api/status"));
      } catch (err) {
        toast(err.message || "Delete failed", "err");
      }
    });
  }

  var ztpState = { canApprove: false, busy: false };

  function ztpWarnEnable() {
    return window.confirm(
      "WARNING: Enabling ZTP/DHCP on this site LAN will hand out IP addresses and may network-boot " +
      "any device on that segment.\n\nDisable your router DHCP on this VLAN first.\n\nContinue?"
    );
  }

  function paintZtpPermNote() {
    var notes = [
      document.getElementById("ztpPermNote"),
      document.getElementById("adminZtpPermNote"),
    ];
    var switches = [
      document.getElementById("ztpEnableSwitch"),
      document.getElementById("adminZtpEnableSwitch"),
    ];
    var msg = ztpState.canApprove
      ? "Requires approve_ztp. On Windows, starting DHCP may need Run as administrator (UDP 67)."
      : "You need approve_ztp permission to enable site ZTP/DHCP.";
    notes.forEach(function (note) {
      if (!note) return;
      note.hidden = false;
      note.textContent = msg;
    });
    switches.forEach(function (sw) {
      if (sw) sw.disabled = !ztpState.canApprove || ztpState.busy;
    });
  }

  function paintZtpSummary(edge) {
    if (!edge) return;
    setText("ztpDns", yn(!!edge.dnsmasq_installed));
    setText("ztpRun", yn(!!edge.running));
    setText("ztpRunOverview", yn(!!edge.running));
    var leaseN = String(edge.lease_count ?? (edge.leases || []).length ?? 0);
    setText("ztpLeases", leaseN);
    setText("ztpLeasesOverview", leaseN);
    setText("ztpOverviewLabel", edge.running ? "DHCP up" : (edge.dnsmasq_installed ? "Ready" : "Unavailable"));
    var base = edge.public_base_url || (location.origin || "");
    setText("ztpFetchBase", base ? base.replace(/\/$/, "") + "/ztp/fetch/" : "/ztp/fetch/");
    var kind = edge.running ? "ok" : (edge.dnsmasq_installed ? "idle" : "warn");
    var label = edge.running ? "DHCP up" : (edge.dnsmasq_installed ? "Ready" : "No dnsmasq");
    setPill("ztpPill", kind, label);
    setPill("ztpPillMini", kind, label);
    if (Array.isArray(edge.leases)) {
      paintZtpLeases(edge.leases);
    }
    var enabled = !!(edge.running || edge.enabled);
    ["ztpEnableSwitch", "adminZtpEnableSwitch"].forEach(function (id) {
      var sw = document.getElementById(id);
      if (sw && !ztpState.busy) sw.checked = enabled;
    });
    var adminStatus = document.getElementById("adminZtpStatusLine");
    if (adminStatus) {
      var iface = (edge.config && edge.config.interface) || edge.interface || "—";
      adminStatus.textContent =
        (edge.running ? "DHCP running" : enabled ? "Enabled (not running)" : "Disabled") +
        " · interface " + iface +
        " · leases " + leaseN +
        (edge.dnsmasq_installed === false ? " · DHCP backend missing" : "");
    }
    paintZtpPermNote();
    var errText = edge.error
      ? edge.error + (edge.detail ? " — " + edge.detail : "")
      : "";
    ["ztpError", "adminZtpError"].forEach(function (id) {
      var errEl = document.getElementById(id);
      if (!errEl) return;
      if (errText) {
        errEl.hidden = false;
        errEl.textContent = errText;
      } else {
        errEl.hidden = true;
        errEl.textContent = "";
      }
    });
  }

  function paintZtpLeases(leases) {
    var body = document.getElementById("ztpLeasesBody");
    if (!body) return;
    if (!leases || !leases.length) {
      body.innerHTML = '<tr class="empty-row"><td colspan="4">No leases yet</td></tr>';
      return;
    }
    body.innerHTML = leases.map(function (L) {
      var exp = L.expiry || "";
      if (/^\d+$/.test(String(exp))) {
        try {
          exp = new Date(Number(exp) * 1000).toLocaleString();
        } catch (_) {}
      }
      return "<tr><td>" + escapeHtml(L.ip || "—") + "</td><td><code>" +
        escapeHtml(L.mac || "—") + "</code></td><td>" +
        escapeHtml(L.hostname || "—") + "</td><td>" +
        escapeHtml(exp || "—") + "</td></tr>";
    }).join("");
  }

  function fillZtpForm(cfg) {
    if (!cfg) return;
    var setVal = function (id, v) {
      var el = document.getElementById(id);
      if (el) el.value = v == null ? "" : String(v);
    };
    setVal("ztpSubnet", cfg.subnet);
    setVal("ztpNetmask", cfg.netmask);
    setVal("ztpRangeStart", cfg.range_start);
    setVal("ztpRangeEnd", cfg.range_end);
    setVal("ztpGateway", cfg.gateway);
    setVal("ztpDnsServers", Array.isArray(cfg.dns) ? cfg.dns.join(", ") : (cfg.dns || ""));
    setVal("ztpLeaseHours", cfg.lease_hours != null ? cfg.lease_hours : 12);
    setVal("ztpNextServer", cfg.next_server);
    setVal("ztpBootFilename", cfg.boot_filename || "undionly.kpxe");
    var tftp = document.getElementById("ztpEnableTftp");
    var pxe = document.getElementById("ztpEnablePxe");
    if (tftp) tftp.checked = !!cfg.enable_tftp;
    if (pxe) pxe.checked = !!cfg.enable_pxe;
    var sel = document.getElementById("ztpInterface");
    if (sel) {
      var want = String(cfg.interface || "");
      if (want && ![].some.call(sel.options, function (o) { return o.value === want; })) {
        var opt = document.createElement("option");
        opt.value = want;
        opt.textContent = want + " (saved)";
        sel.appendChild(opt);
      }
      sel.value = want;
    }
  }

  function readZtpForm() {
    var dnsRaw = String((document.getElementById("ztpDnsServers") || {}).value || "");
    var dns = dnsRaw.split(/[,\s]+/).map(function (s) { return s.trim(); }).filter(Boolean);
    return {
      interface: String((document.getElementById("ztpInterface") || {}).value || "").trim(),
      subnet: String((document.getElementById("ztpSubnet") || {}).value || "").trim(),
      netmask: String((document.getElementById("ztpNetmask") || {}).value || "").trim(),
      range_start: String((document.getElementById("ztpRangeStart") || {}).value || "").trim(),
      range_end: String((document.getElementById("ztpRangeEnd") || {}).value || "").trim(),
      gateway: String((document.getElementById("ztpGateway") || {}).value || "").trim(),
      dns: dns.length ? dns : ["1.1.1.1"],
      lease_hours: Number((document.getElementById("ztpLeaseHours") || {}).value || 12) || 12,
      next_server: String((document.getElementById("ztpNextServer") || {}).value || "").trim(),
      boot_filename: String((document.getElementById("ztpBootFilename") || {}).value || "undionly.kpxe").trim(),
      enable_tftp: !!(document.getElementById("ztpEnableTftp") || {}).checked,
      enable_pxe: !!(document.getElementById("ztpEnablePxe") || {}).checked,
    };
  }

  async function loadZtpPanel() {
    try {
      var catalog = await api("/api/rbac").catch(function () { return {}; });
      var perms = (catalog && catalog.me && catalog.me.permissions) || [];
      ztpState.canApprove = perms.indexOf("approve_ztp") >= 0;
      var [status, ifaces] = await Promise.all([
        api("/api/ztp/status"),
        api("/api/ztp/interfaces").catch(function () { return { interfaces: [] }; }),
      ]);
      var sel = document.getElementById("ztpInterface");
      if (sel && Array.isArray(ifaces.interfaces)) {
        var current = sel.value;
        sel.innerHTML = '<option value="">Auto (not recommended)</option>';
        ifaces.interfaces.forEach(function (iface) {
          var opt = document.createElement("option");
          opt.value = iface.name || iface;
          var label = iface.name || iface;
          if (iface.addrs && iface.addrs.length) label += " — " + iface.addrs.join(", ");
          opt.textContent = label;
          sel.appendChild(opt);
        });
        if (current) sel.value = current;
      }
      paintZtpSummary(status);
      fillZtpForm(status.config || {});
    } catch (err) {
      toast(err.message || "Could not load ZTP status", "err");
    }
  }

  async function saveZtpConfig() {
    var cfg = readZtpForm();
    var res = await api("/api/ztp/config", { method: "PUT", body: JSON.stringify(cfg) });
    fillZtpForm(res.config || cfg);
    return res;
  }

  function showZtpResult(res) {
    var text = "";
    if (res && res.ok === false) {
      text = (res.error || "DHCP failed") + (res.detail ? " — " + res.detail : "") +
        (res.hint ? " (" + res.hint + ")" : "");
    }
    ["ztpError", "adminZtpError"].forEach(function (id) {
      var errEl = document.getElementById(id);
      if (!errEl) return;
      if (text) {
        errEl.hidden = false;
        errEl.textContent = text;
      } else {
        errEl.hidden = true;
        errEl.textContent = "";
      }
    });
  }

  function setZtpSwitches(checked) {
    ["ztpEnableSwitch", "adminZtpEnableSwitch"].forEach(function (id) {
      var sw = document.getElementById(id);
      if (sw) sw.checked = !!checked;
    });
  }

  async function toggleZtpEnabled(wantOn, sourceSwitch) {
    if (ztpState.busy) return;
    if (!ztpState.canApprove) {
      setZtpSwitches(!wantOn);
      toast("Missing approve_ztp permission", "err");
      return;
    }
    if (wantOn && !ztpWarnEnable()) {
      setZtpSwitches(false);
      return;
    }
    ztpState.busy = true;
    paintZtpPermNote();
    try {
      if (wantOn) {
        var ifaceEl = document.getElementById("ztpInterface");
        var ifaceVal = ifaceEl ? String(ifaceEl.value || "").trim() : "";
        // Dashboard form present: require interface + save. Admin-only: use saved config.
        if (ifaceEl && !ifaceVal) {
          setZtpSwitches(false);
          toast("Pick a LAN interface on Dashboard → ZTP & DHCP first", "err");
          return;
        }
        if (document.getElementById("ztpForm")) {
          await saveZtpConfig();
        }
        var res = await api("/api/ztp/start", { method: "POST", body: "{}" });
        showZtpResult(res);
        if (res.ok) toast(res.already_running ? "ZTP already running" : "ZTP enabled on LAN", "ok");
        else {
          setZtpSwitches(false);
          toast(res.error || "Could not start ZTP", "err");
        }
      } else {
        var stopRes = await api("/api/ztp/stop", { method: "POST", body: "{}" });
        showZtpResult(stopRes);
        if (stopRes.ok) toast("ZTP disabled", "ok");
        else {
          setZtpSwitches(true);
          toast(stopRes.error || "Could not stop ZTP", "err");
        }
      }
      await loadZtpPanel();
      try {
        paintStatus(await api("/api/status"));
      } catch (_) {}
    } catch (err) {
      setZtpSwitches(!wantOn);
      toast(err.message || "ZTP toggle failed", "err");
    } finally {
      ztpState.busy = false;
      paintZtpPermNote();
    }
  }

  ["ztpEnableSwitch", "adminZtpEnableSwitch"].forEach(function (id) {
    var sw = document.getElementById(id);
    if (sw && !sw.dataset.bound) {
      sw.dataset.bound = "1";
      sw.addEventListener("change", function () {
        toggleZtpEnabled(!!sw.checked, sw);
      });
    }
  });

  var ztpForm = document.getElementById("ztpForm");
  if (ztpForm) {
    ztpForm.addEventListener("submit", async function (e) {
      e.preventDefault();
      try {
        await saveZtpConfig();
        toast("ZTP / DHCP configuration saved", "ok");
        await loadZtpPanel();
      } catch (err) {
        toast(err.message || "Save failed", "err");
      }
    });
  }

  ["ztpRefreshBtn", "adminZtpRefreshBtn"].forEach(function (id) {
    var btn = document.getElementById(id);
    if (btn && !btn.dataset.bound) {
      btn.dataset.bound = "1";
      btn.addEventListener("click", function () {
        loadZtpPanel();
      });
    }
  });

  async function loadGameplanPanel() {
    var list = document.getElementById("gameplanList");
    var preview = document.getElementById("gameplanPreview");
    if (!list) return;
    if (preview) {
      preview.style.display = "none";
      preview.textContent = "";
    }
    try {
      var data = await api("/api/gameplan/blueprints");
      var items = (data && data.blueprints) || [];
      setText("gameplanCountOverview", String(items.length));
      if (!items.length) {
        list.innerHTML =
          '<li class="empty">No blueprints yet — save one from Hayabusa Foundry → Gameplan &amp; Blueprints</li>';
        return;
      }
      list.innerHTML = items
        .map(function (bp) {
          var when = bp.updated_at
            ? new Date(Number(bp.updated_at) * 1000).toLocaleString()
            : "—";
          var base =
            window.__hayabusaPublicUrl ||
            (document.getElementById("introducerUrl") &&
              document.getElementById("introducerUrl").textContent) ||
            "";
          base = String(base || "").trim().replace(/\/$/, "");
          var openHref = base ? base + "/gameplan?id=" + encodeURIComponent(bp.id || "") : "";
          return (
            '<li class="job-pending-item" data-gp-id="' +
            escapeHtml(bp.id) +
            '">' +
            "<div><strong>" +
            escapeHtml(bp.name || "Untitled") +
            "</strong> · " +
            escapeHtml(String(bp.node_count || 0)) +
            " nodes · " +
            escapeHtml(String(bp.edge_count || 0)) +
            " edges</div>" +
            '<div class="section-desc" style="margin:0.25rem 0 0.55rem;">Updated ' +
            escapeHtml(when) +
            " · <code>" +
            escapeHtml(bp.id || "") +
            "</code></div>" +
            '<div class="row">' +
            (openHref
              ? '<a class="btn btn-primary btn-sm" href="' +
                escapeHtml(openHref) +
                '" target="_blank" rel="noopener">Open on Hayabusa</a> '
              : "") +
            '<button type="button" class="btn btn-secondary btn-sm" data-gp-view="' +
            escapeHtml(bp.id) +
            '">View JSON</button> ' +
            '<button type="button" class="btn btn-ghost btn-sm" data-gp-delete="' +
            escapeHtml(bp.id) +
            '">Delete</button>' +
            "</div></li>"
          );
        })
        .join("");
    } catch (err) {
      list.innerHTML =
        '<li class="empty">' + escapeHtml((err && err.message) || "Failed to load") + "</li>";
    }
  }

  function _igHayabusaBase() {
    var base =
      window.__hayabusaPublicUrl ||
      (document.getElementById("introducerUrl") &&
        document.getElementById("introducerUrl").textContent) ||
      "";
    return String(base || "").trim().replace(/\/$/, "");
  }

  function _igEmpty(msg) {
    return '<li class="empty">' + escapeHtml(msg) + "</li>";
  }

  function _igDeleteBtn(kind, id) {
    return (
      '<button type="button" class="btn btn-ghost btn-sm" data-ig-delete-kind="' +
      escapeHtml(kind) +
      '" data-ig-delete-id="' +
      escapeHtml(id) +
      '">Delete</button>'
    );
  }

  async function loadIntegrationsPanel() {
    var webhookList = document.getElementById("igWebhookList");
    var platformList = document.getElementById("igPlatformList");
    var appList = document.getElementById("igAppList");
    var jobList = document.getElementById("igJobList");
    var meta = document.getElementById("igSyncMeta");
    if (!webhookList) return;
    try {
      var data = await api("/api/integrations");
      var counts = (data && data.counts) || {};
      setText("igWebhookCountOverview", String(counts.webhooks != null ? counts.webhooks : "—"));
      setText("igAppCountOverview", String(counts.apps != null ? counts.apps : "—"));
      setText("igJobCountOverview", String(counts.automation_jobs != null ? counts.automation_jobs : "—"));
      if (meta) {
        meta.textContent =
          "Owner " +
          (data.owner || "—") +
          (data.updated_at ? " · last sync " + data.updated_at : " · not synced yet") +
          " · " +
          (counts.webhooks || 0) +
          " webhooks · " +
          (counts.platforms || 0) +
          " platforms · " +
          (counts.apps || 0) +
          " apps · " +
          (counts.automation_jobs || 0) +
          " jobs";
      }
      var base = _igHayabusaBase();
      var openIg = base ? base + "/integrations" : "";

      var webhooks = data.webhooks || [];
      webhookList.innerHTML = webhooks.length
        ? webhooks
            .map(function (w) {
              return (
                '<li class="job-pending-item">' +
                "<div><strong>" +
                escapeHtml(w.name || w.id || "Webhook") +
                "</strong> · " +
                escapeHtml(String(w.platform || "")) +
                " · " +
                escapeHtml(String(w.status || "")) +
                "</div>" +
                '<div class="section-desc" style="margin:0.25rem 0 0.55rem;"><code>' +
                escapeHtml(w.id || "") +
                "</code>" +
                (w.webhook_url_masked
                  ? " · " + escapeHtml(w.webhook_url_masked)
                  : " · no URL") +
                "</div>" +
                '<div class="row">' +
                (openIg
                  ? '<a class="btn btn-secondary btn-sm" href="' +
                    escapeHtml(openIg) +
                    '" target="_blank" rel="noopener">Open on Hayabusa</a> '
                  : "") +
                _igDeleteBtn("webhook", w.id) +
                "</div></li>"
              );
            })
            .join("")
        : _igEmpty("No webhook library projects yet — save one from Hayabusa Integrations → Webhooks");

      var platforms = data.platforms || [];
      if (platformList) {
        platformList.innerHTML = platforms.length
          ? platforms
              .map(function (p) {
                return (
                  '<li class="job-pending-item">' +
                  "<div><strong>" +
                  escapeHtml(String(p.platform || p.id || "")) +
                  "</strong> · " +
                  escapeHtml(String(p.status || "")) +
                  "</div>" +
                  '<div class="section-desc" style="margin:0.25rem 0 0.55rem;">' +
                  (p.webhook_url_masked
                    ? escapeHtml(p.webhook_url_masked)
                    : "No URL bound") +
                  "</div>" +
                  '<div class="row">' +
                  _igDeleteBtn("platform", p.id) +
                  "</div></li>"
                );
              })
              .join("")
          : _igEmpty("No platform webhook configs stored on this controller");
      }

      var apps = data.apps || [];
      if (appList) {
        appList.innerHTML = apps.length
          ? apps
              .map(function (a) {
                return (
                  '<li class="job-pending-item">' +
                  "<div><strong>" +
                  escapeHtml(a.name || a.id || "App") +
                  "</strong> · " +
                  escapeHtml(String(a.platform || "")) +
                  " · " +
                  escapeHtml(String(a.status || "")) +
                  (a.code_approved ? " · approved" : " · not approved") +
                  "</div>" +
                  '<div class="section-desc" style="margin:0.25rem 0 0.55rem;"><code>' +
                  escapeHtml(a.id || "") +
                  "</code> · " +
                  escapeHtml(String(a.code_lines || 0)) +
                  " lines</div>" +
                  '<div class="row">' +
                  (openIg
                    ? '<a class="btn btn-secondary btn-sm" href="' +
                      escapeHtml(openIg) +
                      '" target="_blank" rel="noopener">Open builder</a> '
                    : "") +
                  _igDeleteBtn("app", a.id) +
                  "</div></li>"
                );
              })
              .join("")
          : _igEmpty("No builder apps yet — save from Hayabusa Integrations → Builder");
      }

      var jobs = data.automation_jobs || [];
      if (jobList) {
        jobList.innerHTML = jobs.length
          ? jobs
              .map(function (j) {
                var state = j.paused ? "paused" : j.enabled === false ? "disabled" : "active";
                return (
                  '<li class="job-pending-item">' +
                  "<div><strong>" +
                  escapeHtml(j.name || "Job") +
                  "</strong> · every " +
                  escapeHtml(String(j.interval_minutes || "?")) +
                  " min · " +
                  escapeHtml(state) +
                  "</div>" +
                  '<div class="section-desc" style="margin:0.25rem 0 0.55rem;"><code>' +
                  escapeHtml(j.command_preview || "") +
                  "</code></div>" +
                  '<div class="section-desc" style="margin:0 0 0.55rem;">Next ' +
                  escapeHtml(j.next_run || "—") +
                  (j.last_status ? " · last " + escapeHtml(String(j.last_status)) : "") +
                  "</div>" +
                  '<div class="row">' +
                  (openIg
                    ? '<a class="btn btn-secondary btn-sm" href="' +
                      escapeHtml(openIg) +
                      '" target="_blank" rel="noopener">Open automation</a> '
                    : "") +
                  _igDeleteBtn("job", j.id) +
                  "</div></li>"
                );
              })
              .join("")
          : _igEmpty("No automation jobs yet — Schedule from Workstations, then Sync controller");
      }
    } catch (err) {
      var msg = _igEmpty((err && err.message) || "Failed to load integrations");
      webhookList.innerHTML = msg;
      if (platformList) platformList.innerHTML = msg;
      if (appList) appList.innerHTML = msg;
      if (jobList) jobList.innerHTML = msg;
      if (meta) meta.textContent = (err && err.message) || "Failed to load";
    }
  }

  var igRefreshBtn = document.getElementById("igRefreshBtn");
  if (igRefreshBtn) {
    igRefreshBtn.addEventListener("click", function () {
      loadIntegrationsPanel();
    });
  }

  ["igWebhookList", "igPlatformList", "igAppList", "igJobList"].forEach(function (listId) {
    var el = document.getElementById(listId);
    if (!el) return;
    el.addEventListener("click", async function (ev) {
      var btn = ev.target && ev.target.closest && ev.target.closest("[data-ig-delete-id]");
      if (!btn) return;
      var kind = btn.getAttribute("data-ig-delete-kind") || "";
      var id = btn.getAttribute("data-ig-delete-id") || "";
      if (!kind || !id) return;
      if (!window.confirm("Delete this " + kind + " from this controller’s store?")) return;
      try {
        await api("/api/integrations/" + encodeURIComponent(kind) + "/" + encodeURIComponent(id), {
          method: "DELETE",
        });
        loadIntegrationsPanel();
      } catch (err) {
        window.alert((err && err.message) || "Delete failed");
      }
    });
  });

  async function loadJobsPanel() {
    var list = document.getElementById("pendingJobsList");
    if (!list) return;
    try {
      var catalog = await api("/api/rbac");
      var canApprovePb = !!(
        catalog && catalog.me && Array.isArray(catalog.me.permissions) &&
        (catalog.me.permissions.indexOf("approve_jobs") !== -1 ||
          catalog.me.permissions.indexOf("approve_playbooks") !== -1)
      );
      var canApproveZtp = !!(
        catalog && catalog.me && Array.isArray(catalog.me.permissions) &&
        catalog.me.permissions.indexOf("approve_ztp") !== -1
      );
      function canApproveJob(kind) {
        var k = String(kind || "").toLowerCase();
        if (k === "ztp" || k === "ztp-dhcp-start" || k === "ztp-dhcp-stop") return canApproveZtp;
        return canApprovePb;
      }
      var data = await api("/api/jobs?status=pending_approval");
      var jobs = data.jobs || [];
      setText("pendingJobsOverview", String(jobs.length));
      if (!jobs.length) {
        list.innerHTML = '<li class="empty">No jobs waiting for LAN approval</li>';
      } else {
        list.innerHTML = jobs.map(function (job) {
          var who = (job.requested_by && (job.requested_by.username || job.requested_by.email)) || "Hayabusa";
          var keys = (job.secret_keys || []).join(", ") || "(none named)";
          var args = (job.args || []).join(" ");
          var files = (job.extra_file_paths || []).join(", ");
          var meta = job.metadata || {};
          var backupLabel = meta.hayabusa_backup_job_name || meta.hayabusa_backup_job_id || "";
          var title = backupLabel
            ? ("Backup · " + backupLabel)
            : (job.kind || "job");
          return (
            '<li class="job-pending-item" data-id="' + escapeHtml(job.id) + '">' +
              '<div><strong>' + escapeHtml(title) + '</strong> · ' + escapeHtml(who) + '</div>' +
              (backupLabel
                ? '<div class="muted">Disaster Prep backup' +
                    (meta.source_ip && meta.dest_ip
                      ? (' · ' + escapeHtml(String(meta.source_ip)) + ' → ' + escapeHtml(String(meta.dest_ip)))
                      : '') +
                  '</div>'
                : '') +
              '<div class="muted">args: <code>' + escapeHtml(args || "—") + '</code></div>' +
              (files ? '<div class="muted">from Hayabusa: <code>' + escapeHtml(files) + '</code></div>' : '') +
              '<div class="muted">secret names: <code>' + escapeHtml(keys) + '</code></div>' +
              '<div class="row" style="margin-top:0.6rem;gap:0.5rem;">' +
                (canApproveJob(job.kind)
                  ? '<button type="button" class="btn btn-primary job-approve" data-id="' + escapeHtml(job.id) + '">Approve &amp; pass</button>' +
                    '<button type="button" class="btn btn-ghost job-deny" data-id="' + escapeHtml(job.id) + '">Deny</button>'
                  : '<span class="muted">Awaiting ' +
                    ((String(job.kind || "").toLowerCase().indexOf("ztp") >= 0) ? "ZTP" : "job") +
                    " approver</span>") +
              '</div>' +
            '</li>'
          );
        }).join("");
        list.querySelectorAll(".job-approve").forEach(function (btn) {
          btn.addEventListener("click", async function () {
            var id = btn.getAttribute("data-id");
            btn.disabled = true;
            try {
              var res = await api("/api/jobs/" + encodeURIComponent(id) + "/approve", {
                method: "POST",
                body: "{}",
              });
              toast(
                res.ok || res.status === "hydrated"
                  ? "Approved — hydrated and passed through for Hayabusa"
                  : (res.error || "Finished with errors"),
                res.ok || res.status === "hydrated" ? "ok" : "err"
              );
              await loadJobsPanel();
              await loadJobResultsPanel();
            } catch (err) {
              toast(err.message || "Approve failed", "err");
              btn.disabled = false;
            }
          });
        });
        list.querySelectorAll(".job-deny").forEach(function (btn) {
          btn.addEventListener("click", async function () {
            var id = btn.getAttribute("data-id");
            btn.disabled = true;
            try {
              await api("/api/jobs/" + encodeURIComponent(id) + "/deny", {
                method: "POST",
                body: JSON.stringify({ reason: "Denied on LAN" }),
              });
              toast("Job denied", "ok");
              await loadJobsPanel();
              await loadJobResultsPanel();
            } catch (err) {
              toast(err.message || "Deny failed", "err");
              btn.disabled = false;
            }
          });
        });
      }
    } catch (err) {
      list.innerHTML = '<li class="empty">' + escapeHtml(err.message || "Could not load jobs") + '</li>';
    }
    await loadJobResultsPanel();
  }

  async function loadJobResultsPanel() {
    var list = document.getElementById("jobResultsList");
    if (!list) return;
    try {
      var data = await api("/api/jobs?status=completed,failed&limit=40");
      var jobs = data.jobs || [];
      if (!jobs.length) {
        list.innerHTML = '<li class="empty">No completed or failed jobs yet</li>';
        return;
      }
      list.innerHTML = jobs.map(function (job) {
        var who = (job.requested_by && (job.requested_by.username || job.requested_by.email)) || "Hayabusa";
        var args = (job.args || []).join(" ");
        var result = job.result || {};
        var stdout = String(result.stdout || "");
        var stderr = String(result.stderr || "");
        var preview = (stdout || stderr || result.error || "").slice(0, 240);
        var status = String(job.status || "");
        var pill = status === "completed" ? "ok" : "err";
        var meta = job.metadata || {};
        var backupLabel = meta.hayabusa_backup_job_name || meta.hayabusa_backup_job_id || "";
        var title = backupLabel ? ("Backup · " + backupLabel) : (job.kind || "job");
        return (
          '<li class="job-result-item" data-id="' + escapeHtml(job.id) + '">' +
            '<div class="row" style="justify-content:space-between;gap:0.5rem;flex-wrap:wrap;">' +
              '<div><strong>' + escapeHtml(title) + '</strong> · ' +
                '<span class="pill pill-' + pill + '">' + escapeHtml(status) + '</span> · ' +
                escapeHtml(who) +
              '</div>' +
              '<button type="button" class="btn btn-ghost job-result-toggle" data-id="' + escapeHtml(job.id) + '">Show output</button>' +
            '</div>' +
            '<div class="muted">args: <code>' + escapeHtml(args || "—") + '</code></div>' +
            (preview
              ? '<div class="muted" style="margin-top:0.35rem;white-space:pre-wrap;max-height:4.5em;overflow:hidden;">' +
                  escapeHtml(preview) + (preview.length >= 240 ? "…" : "") +
                '</div>'
              : '') +
            '<pre class="job-result-body" id="job-result-body-' + escapeHtml(job.id) + '" hidden style="margin-top:0.6rem;max-height:320px;overflow:auto;white-space:pre-wrap;font-size:12px;background:#0b1220;color:#d7e3ff;padding:0.75rem;border-radius:6px;"></pre>' +
          '</li>'
        );
      }).join("");
      list.querySelectorAll(".job-result-toggle").forEach(function (btn) {
        btn.addEventListener("click", async function () {
          var id = btn.getAttribute("data-id");
          var body = document.getElementById("job-result-body-" + id);
          if (!body) return;
          if (!body.hidden && body.textContent) {
            body.hidden = true;
            btn.textContent = "Show output";
            return;
          }
          btn.disabled = true;
          try {
            var detail = await api("/api/jobs/" + encodeURIComponent(id));
            var r = (detail && detail.result) || detail || {};
            var bits = [];
            bits.push("status=" + (detail.status || ""));
            if (r.cmd) bits.push("cmd: " + r.cmd);
            if (r.returncode != null) bits.push("returncode=" + r.returncode);
            if (r.stdout) bits.push(r.stdout);
            if (r.stderr) bits.push("--- stderr ---\n" + r.stderr);
            if (r.error) bits.push("error: " + r.error);
            body.textContent = bits.join("\n") || "(no output)";
            body.hidden = false;
            btn.textContent = "Hide output";
          } catch (err) {
            toast(err.message || "Could not load result", "err");
          } finally {
            btn.disabled = false;
          }
        });
      });
    } catch (err) {
      list.innerHTML = '<li class="empty">' + escapeHtml(err.message || "Could not load results") + '</li>';
    }
  }

  var jobsRefreshBtn = document.getElementById("jobsRefreshBtn");
  if (jobsRefreshBtn) {
    jobsRefreshBtn.addEventListener("click", function () {
      loadJobsPanel();
    });
  }
  var jobResultsRefreshBtn = document.getElementById("jobResultsRefreshBtn");
  if (jobResultsRefreshBtn) {
    jobResultsRefreshBtn.addEventListener("click", function () {
      loadJobResultsPanel();
    });
  }
  var gameplanRefreshBtn = document.getElementById("gameplanRefreshBtn");
  if (gameplanRefreshBtn) {
    gameplanRefreshBtn.addEventListener("click", function () {
      loadGameplanPanel();
    });
  }
  var gameplanListEl = document.getElementById("gameplanList");
  if (gameplanListEl) {
    gameplanListEl.addEventListener("click", async function (ev) {
      var viewBtn = ev.target.closest("[data-gp-view]");
      var delBtn = ev.target.closest("[data-gp-delete]");
      if (viewBtn) {
        var vid = viewBtn.getAttribute("data-gp-view");
        try {
          var got = await api("/api/gameplan/blueprints/" + encodeURIComponent(vid));
          var preview = document.getElementById("gameplanPreview");
          if (preview) {
            preview.style.display = "block";
            preview.textContent = JSON.stringify(got.blueprint || got, null, 2);
          }
        } catch (err) {
          toast((err && err.message) || "View failed", "err");
        }
        return;
      }
      if (delBtn) {
        var did = delBtn.getAttribute("data-gp-delete");
        if (!confirm("Delete blueprint " + did + " from this controller?")) return;
        try {
          await api("/api/gameplan/blueprints/" + encodeURIComponent(did), { method: "DELETE" });
          toast("Blueprint deleted", "ok");
          loadGameplanPanel();
        } catch (err) {
          toast((err && err.message) || "Delete failed", "err");
        }
      }
    });
  }

  async function loadAccessPanel() {
    /* Slim Access tab — personal permissions + sync only. */
    try {
      var data = await api("/api/rbac");
      var me = data.me || {};
      setText(
        "accessMe",
        "Signed in as " +
          (me.display_name || me.email || me.username || me.user_key || "—") +
          " · roles: " +
          ((me.roles || []).join(", ") || "(none)") +
          " · rank " +
          (me.highest_rank != null ? me.highest_rank : "—") +
          " · permissions: " +
          ((me.permissions || []).join(", ") || "(none)")
      );
    } catch (err) {
      toast(err.message || "Could not load access", "err");
    }
  }

  async function loadAdminPanel() {
    try {
      var data = await api("/api/rbac");
      var me = data.me || {};
      var perms = me.permissions || [];
      var canManageRbac =
        !!me.is_owner_or_admin &&
        (!!me.can_manage_rbac || perms.indexOf("manage_rbac") >= 0);
      window.__adminCanManage = canManageRbac;
      window.__adminMe = me;
      setText(
        "rbacMe",
        (me.display_name || me.email || me.username || me.user_key || "Signed in") +
          " · rank " +
          (me.highest_rank != null ? me.highest_rank : "—") +
          " · can grant ≤ " +
          (me.grant_ceiling != null ? me.grant_ceiling : "—")
      );
      var hier = (data.hierarchy && data.hierarchy.note) || "";
      setText("rbacHierarchyNote", hier);

      renderRbacRoles(data, me, canManageRbac);
      populateGrantableRoleSelect(me.grantable_roles || [], data.roles || {});

      var userForm = document.getElementById("rbacUserForm");
      if (userForm) userForm.hidden = !canManageRbac;
      var newRoleBtn = document.getElementById("adminNewRoleBtn");
      if (newRoleBtn) newRoleBtn.hidden = !canManageRbac;
      setText(
        "rbacUserFormHint",
        canManageRbac
          ? "Right-click a user to change their role."
          : "View only"
      );
      var hint = document.getElementById("rbacUserFormHint");
      if (hint) hint.hidden = false;

      try {
        var site = await api("/api/controller/site-name");
        var siteForm = document.getElementById("siteNameForm");
        var siteReadonly = document.getElementById("siteNameReadonly");
        var siteInput = document.getElementById("siteNameInput");
        var siteDisplay = document.getElementById("siteNameDisplay");
        var display = String(site.display_name || "").trim();
        if (siteDisplay) siteDisplay.textContent = display || "—";
        if (siteInput && display) siteInput.value = display;
        if (siteForm) siteForm.hidden = !canManageRbac;
        if (siteReadonly) siteReadonly.hidden = canManageRbac;
      } catch (siteErr) {
        setText("siteNameStatus", siteErr.message || "Could not load site name");
      }

      window.__adminUsers = data.users || [];
      window.__adminTeamsMeta = {};
      (data.teams || []).forEach(function (t) {
        window.__adminTeamsMeta[t.id || t.name] = t;
      });
      window.__adminRolesMeta = data.roles || {};
      renderAdminUsersList();

      var teams = data.teams || [];
      var tl = document.getElementById("rbacTeamsList");
      if (tl) {
        tl.innerHTML = teams.length
          ? teams.map(function (t) {
              return "<li><strong>" + escapeHtml(t.name || t.id) + "</strong> · members: " +
                escapeHtml((t.member_keys || []).join(", ") || "(none)") + "</li>";
            }).join("")
          : '<li class="empty">No teams yet</li>';
      }
      var owners = data.playbook_owners || {};
      var ol = document.getElementById("rbacOwnersList");
      if (ol) {
        var keys = Object.keys(owners);
        ol.innerHTML = keys.length
          ? keys.map(function (p) {
              var o = owners[p] || {};
              return "<li><code>" + escapeHtml(p) + "</code> → " + escapeHtml(o.owner_type || "") + ":" + escapeHtml(o.owner_id || "") + "</li>";
            }).join("")
          : '<li class="empty">No ownership records yet</li>';
      }
      await loadSetupRedoPanel();
      await loadLocalPasswordPanel();
      await loadSignInAllowlistPanel();
      await loadMeshConnectPanel();
    } catch (err) {
      toast(err.message || "Could not load administration", "err");
    }
  }

  var SIGNIN_PLATFORM_LABELS = {
    google: "Google",
    github: "GitHub",
    discord: "Discord",
    slack: "Slack",
    microsoft: "Microsoft / Teams",
    totp: "Hayabusa Auth (TOTP)",
    manual: "Manual password (break-glass — controlled by toggle above)",
  };

  function _signinListToText(arr) {
    return (arr || []).join("\n");
  }

  function _signinTextToList(text) {
    return String(text || "")
      .split(/[\n,;]+/)
      .map(function (s) {
        return s.trim();
      })
      .filter(Boolean);
  }

  async function loadLocalPasswordPanel() {
    var chk = document.getElementById("localPasswordEnabledChk");
    var meta = document.getElementById("localPasswordMeta");
    var status = document.getElementById("localPasswordStatus");
    if (!chk) return;
    try {
      var data = await api("/api/admin/local-password-login");
      chk.checked = !!data.enabled;
      chk.disabled = !window.__adminCanManage;
      if (meta) {
        var bits = [];
        bits.push(data.enabled ? "Currently enabled" : "Currently disabled");
        if (data.username) bits.push("username " + data.username);
        if (data.other_signin_methods_ready) {
          bits.push("another allowlisted method is ready");
        } else {
          bits.push("no other allowlisted method yet — disable carefully");
        }
        if (data.updated_at) bits.push("last changed " + formatAdminWhen(data.updated_at));
        if (data.updated_by) bits.push("by " + data.updated_by);
        meta.textContent = bits.join(" · ");
      }
      if (status) status.textContent = "";
    } catch (err) {
      if (meta) meta.textContent = err.message || "Could not load local password setting";
    }
    await loadRequire2faPanel();
  }

  async function loadRequire2faPanel() {
    var chk = document.getElementById("require2faChk");
    var meta = document.getElementById("require2faMeta");
    var status = document.getElementById("require2faStatus");
    if (!chk) return;
    try {
      var data = await api("/api/admin/require-2fa");
      chk.checked = !!data.enabled;
      chk.disabled = !window.__adminCanManage;
      if (meta) {
        var bits = [];
        bits.push(data.enabled ? "2FA required for allowlisted OAuth sign-ins" : "2FA not required for later OAuth sign-ins");
        if (data.updated_at) bits.push("last changed " + formatAdminWhen(data.updated_at));
        if (data.updated_by) bits.push("by " + data.updated_by);
        meta.textContent = bits.join(" · ");
      }
      if (status) status.textContent = "";
    } catch (err) {
      if (meta) meta.textContent = err.message || "Could not load 2FA setting";
    }
  }

  async function loadMeshConnectPanel() {
    var meta = document.getElementById("meshConnectMeta");
    var status = document.getElementById("meshConnectStatus");
    var loginEl = document.getElementById("meshLoginServer");
    var hostEl = document.getElementById("meshHostname");
    var keyEl = document.getElementById("meshAuthKey");
    if (!loginEl || !keyEl) return;
    try {
      var data = await api("/api/admin/mesh-connect");
      window.__meshConnect = data;
      if (!loginEl.value || data.login_server) loginEl.value = data.login_server || loginEl.value || "";
      if (hostEl && (!hostEl.value || data.hostname)) hostEl.value = data.hostname || hostEl.value || "";
      if (!keyEl.value || data.auth_key) keyEl.value = data.auth_key || keyEl.value || "";
      keyEl.type = "password";
      var revealBtn = document.getElementById("meshAuthKeyRevealBtn");
      if (revealBtn) revealBtn.textContent = "Show";

      var bits = [];
      bits.push(data.enrolled ? "Enrolled with Hayabusa" : "Not enrolled yet");
      bits.push(data.auth_key_set ? "auth key on file" : "no auth key yet");
      var vpn = data.vpn || {};
      if (vpn.connected && vpn.ip) bits.push("mesh IP " + vpn.ip);
      bits.push("platform " + (data.platform || "unknown"));
      if (meta) meta.textContent = bits.join(" · ");

      var winBlock = document.getElementById("meshWindowsBlock");
      var linuxHint = document.getElementById("meshLinuxHint");
      var isWin = String(data.platform || "") === "windows";
      if (winBlock) {
        if (isWin) winBlock.removeAttribute("hidden");
        else winBlock.setAttribute("hidden", "");
      }
      if (linuxHint) {
        if (isWin) linuxHint.setAttribute("hidden", "");
        else linuxHint.removeAttribute("hidden");
      }

      var cmdEl = document.getElementById("meshWindowsCommands");
      if (cmdEl) cmdEl.value = data.windows_commands || "";

      var dl = document.getElementById("meshTailscaleDownloadLink");
      if (dl) {
        if (data.download_url) {
          dl.href = data.download_url;
          dl.removeAttribute("hidden");
        } else {
          dl.setAttribute("hidden", "");
        }
      }

      var tsLine = document.getElementById("meshTailscaleStatusLine");
      if (tsLine) {
        var ts = data.tailscale || {};
        if (!isWin) {
          tsLine.textContent = "Use Get key from Hayabusa or paste an auth key, then Save & connect.";
        } else if (ts.ok || ts.bundled) {
          tsLine.textContent = ts.ok
            ? "Bundled mesh client ready (userspace, shields-up on connect)."
            : "Bundled mesh client present but not ready — " + (ts.error || "starting") + ".";
        } else if (ts.installed) {
          tsLine.textContent =
            "System Tailscale detected. Prefer the bundled client; you can still Save & connect.";
        } else {
          tsLine.textContent =
            "Mesh client not detected. Reinstall the Controller (includes open-source tailscaled), then Get key and Save & connect.";
        }
      }
      if (status && !status.dataset.busy) status.textContent = data.hint || "";
    } catch (err) {
      if (meta) meta.textContent = err.message || "Could not load mesh credentials";
    }
  }

  async function meshFetchKeyFromHayabusa() {
    var status = document.getElementById("meshConnectStatus");
    var btn = document.getElementById("meshFetchKeyBtn");
    if (!window.__adminCanManage) {
      toast("Only Owner/admin can fetch mesh keys", "err");
      return;
    }
    if (btn) btn.disabled = true;
    if (status) {
      status.dataset.busy = "1";
      status.textContent = "Requesting auth key from Hayabusa…";
    }
    try {
      var res = await api("/api/admin/mesh-connect", {
        method: "POST",
        body: { action: "fetch" },
      });
      var loginEl = document.getElementById("meshLoginServer");
      var hostEl = document.getElementById("meshHostname");
      var keyEl = document.getElementById("meshAuthKey");
      if (loginEl && res.login_server) loginEl.value = res.login_server;
      if (hostEl && res.hostname) hostEl.value = res.hostname;
      if (keyEl && res.auth_key) {
        keyEl.value = res.auth_key;
        keyEl.type = "password";
      }
      if (res.ok) {
        toast("Auth key loaded from Hayabusa", "ok");
        if (status) status.textContent = "Key loaded. Click Save & connect to join the mesh.";
      } else {
        toast(res.error || "Could not fetch key", "err");
        if (status) status.textContent = res.error || "Could not fetch key";
      }
      await loadMeshConnectPanel();
    } catch (err) {
      toast(err.message || "Fetch failed", "err");
      if (status) status.textContent = err.message || "Fetch failed";
    } finally {
      if (btn) btn.disabled = false;
      if (status) delete status.dataset.busy;
    }
  }

  async function meshSaveAndConnect() {
    var status = document.getElementById("meshConnectStatus");
    var btn = document.getElementById("meshConnectBtn");
    var loginEl = document.getElementById("meshLoginServer");
    var hostEl = document.getElementById("meshHostname");
    var keyEl = document.getElementById("meshAuthKey");
    if (!window.__adminCanManage) {
      toast("Only Owner/admin can connect mesh", "err");
      return;
    }
    var login_server = (loginEl && loginEl.value || "").trim();
    var auth_key = (keyEl && keyEl.value || "").trim();
    var hostname = (hostEl && hostEl.value || "").trim();
    if (!login_server || !auth_key) {
      toast("Login server and auth key are required", "err");
      return;
    }
    if (btn) btn.disabled = true;
    if (status) {
      status.dataset.busy = "1";
      status.textContent = "Connecting to Hayabusa mesh…";
    }
    try {
      var res = await api("/api/admin/mesh-connect", {
        method: "POST",
        body: {
          action: "connect",
          login_server: login_server,
          auth_key: auth_key,
          hostname: hostname,
        },
      });
      if (res.ok) {
        var ip = (res.vpn && res.vpn.ip) || "";
        toast(ip ? "Mesh connected (" + ip + ")" : "Mesh connected", "ok");
        if (status) {
          status.textContent = ip
            ? "Connected. Mesh IP " + ip + ". Check Bridge on the Controller page."
            : "Connected. Check Bridge on the Controller page.";
        }
      } else {
        toast(res.error || "Connect failed", "err");
        if (status) {
          status.textContent =
            (res.error || "Connect failed") + (res.fix ? " — " + res.fix : "");
        }
      }
      await loadMeshConnectPanel();
    } catch (err) {
      toast(err.message || "Connect failed", "err");
      if (status) status.textContent = err.message || "Connect failed";
    } finally {
      if (btn) btn.disabled = false;
      if (status) delete status.dataset.busy;
    }
  }

  async function saveLocalPasswordSetting() {
    var chk = document.getElementById("localPasswordEnabledChk");
    var status = document.getElementById("localPasswordStatus");
    if (!chk) return;
    if (!window.__adminCanManage) {
      toast("Only Owner/admin can change local password login", "err");
      return;
    }
    var enabled = !!chk.checked;
    if (!enabled) {
      var ok = window.confirm(
        "Disable local password sign-in?\n\n" +
          "Make sure you can still sign in with an allowlisted method " +
          "(Google / Hayabusa Auth / etc.). You can re-enable this later while signed in as Owner/admin."
      );
      if (!ok) {
        chk.checked = true;
        return;
      }
    }
    if (status) status.textContent = "Saving…";
    try {
      var body = { enabled: enabled };
      if (!enabled) body.acknowledge_lockout = true;
      await api("/api/admin/local-password-login", {
        method: "POST",
        body: JSON.stringify(body),
      });
      if (status) {
        status.textContent = enabled
          ? "Local password login enabled."
          : "Local password login disabled.";
      }
      toast(enabled ? "Local password login enabled" : "Local password login disabled", "ok");
      await loadLocalPasswordPanel();
      await loadSignInAllowlistPanel();
    } catch (err) {
      if (status) status.textContent = err.message || "Save failed";
      toast(err.message || "Could not save password login setting", "err");
      await loadLocalPasswordPanel();
    }
  }

  async function saveRequire2faSetting() {
    var chk = document.getElementById("require2faChk");
    var status = document.getElementById("require2faStatus");
    if (!chk) return;
    if (!window.__adminCanManage) {
      toast("Only Owner/admin can change the 2FA requirement", "err");
      return;
    }
    var enabled = !!chk.checked;
    if (status) status.textContent = "Saving…";
    try {
      await api("/api/admin/require-2fa", {
        method: "POST",
        body: JSON.stringify({ enabled: enabled }),
      });
      if (status) {
        status.textContent = enabled ? "2FA required for OAuth sign-ins." : "2FA not required for later OAuth sign-ins.";
      }
      toast(enabled ? "2FA requirement enabled" : "2FA requirement disabled", "ok");
      await loadRequire2faPanel();
    } catch (err) {
      if (status) status.textContent = err.message || "Save failed";
      toast(err.message || "Could not save 2FA setting", "err");
      await loadRequire2faPanel();
    }
  }

  async function loadSignInAllowlistPanel() {
    var host = document.getElementById("signinAllowlistPlatforms");
    if (!host) return;
    try {
      var data = await api("/api/admin/signin-allowlist");
      var plats = data.platforms || {};
      var keys = data.platform_keys || Object.keys(SIGNIN_PLATFORM_LABELS);
      var meta = document.getElementById("signinAllowlistMeta");
      if (meta) {
        var updated = data.updated_at
          ? "Last saved " + formatAdminWhen(data.updated_at)
          : "Never saved (default deny — empty lists)";
        if (data.updated_by) updated += " · by " + data.updated_by;
        meta.textContent = updated;
      }
      host.innerHTML = keys
        .map(function (key) {
          var entry = plats[key] || {};
          var label = SIGNIN_PLATFORM_LABELS[key] || key;
          var disabled = key === "manual" ? " disabled" : "";
          var note =
            key === "manual"
              ? '<p class="section-desc admin-note">Use the Local password login toggle above to enable or disable hub password sign-in. These whitelist fields are informational only.</p>'
              : "";
          return (
            '<div class="signin-platform-card" data-platform="' +
            escapeHtml(key) +
            '">' +
            "<h3>" +
            escapeHtml(label) +
            "</h3>" +
            note +
            '<label class="field">Emails (one per line)' +
            '<textarea name="emails" rows="3" placeholder="user@example.com"' +
            disabled +
            ">" +
            escapeHtml(_signinListToText(entry.emails)) +
            "</textarea></label>" +
            '<label class="field">Usernames (one per line)' +
            '<textarea name="usernames" rows="2" placeholder="login name"' +
            disabled +
            ">" +
            escapeHtml(_signinListToText(entry.usernames)) +
            "</textarea></label>" +
            '<label class="field">OAuth user ids (one per line)' +
            '<textarea name="user_ids" rows="2" placeholder="provider subject / id"' +
            disabled +
            ">" +
            escapeHtml(_signinListToText(entry.user_ids)) +
            "</textarea></label>" +
            "</div>"
          );
        })
        .join("");
    } catch (err) {
      host.innerHTML =
        '<p class="section-desc">' +
        escapeHtml(err.message || "Could not load sign-in allowlist") +
        "</p>";
    }
  }

  async function saveSignInAllowlist() {
    var host = document.getElementById("signinAllowlistPlatforms");
    var status = document.getElementById("signinAllowlistStatus");
    if (!host) return;
    if (!window.__adminCanManage) {
      toast("Only Owner/admin can edit the sign-in allowlist", "err");
      return;
    }
    var platforms = {};
    host.querySelectorAll(".signin-platform-card").forEach(function (card) {
      var key = card.getAttribute("data-platform");
      if (!key || key === "manual") return;
      var emailsEl = card.querySelector('textarea[name="emails"]');
      var usersEl = card.querySelector('textarea[name="usernames"]');
      var idsEl = card.querySelector('textarea[name="user_ids"]');
      platforms[key] = {
        emails: _signinTextToList(emailsEl && emailsEl.value),
        usernames: _signinTextToList(usersEl && usersEl.value),
        user_ids: _signinTextToList(idsEl && idsEl.value),
      };
    });
    if (status) status.textContent = "Saving…";
    try {
      await api("/api/admin/signin-allowlist", {
        method: "POST",
        body: JSON.stringify({ platforms: platforms }),
      });
      if (status) status.textContent = "Allowlist saved. Default deny remains for empty platforms.";
      toast("Sign-in allowlist saved", "ok");
      await loadSignInAllowlistPanel();
    } catch (err) {
      if (status) status.textContent = err.message || "Save failed";
      toast(err.message || "Could not save allowlist", "err");
    }
  }

  function formatAdminWhen(ts) {
    var n = Number(ts || 0);
    if (!n) return "—";
    try {
      return new Date(n * 1000).toLocaleString();
    } catch (_) {
      return "—";
    }
  }

  function providerLabel(p) {
    var v = String(p || "unknown").toLowerCase();
    if (v === "manual") return "Manual";
    if (v === "google") return "Google";
    if (v === "discord") return "Discord";
    if (v === "github") return "GitHub";
    if (v === "microsoft" || v === "teams") return "Microsoft";
    if (v === "slack") return "Slack";
    if (v === "oauth") return "OAuth";
    return v.charAt(0).toUpperCase() + v.slice(1);
  }

  function sortAdminUsers(users, mode) {
    var list = (users || []).slice();
    function teamKey(u) {
      var ids = u.team_ids || [];
      return ids.length ? String(ids[0]).toLowerCase() : "";
    }
    list.sort(function (a, b) {
      if (mode === "provider") {
        var pa = providerLabel(a.provider).toLowerCase();
        var pb = providerLabel(b.provider).toLowerCase();
        if (pa !== pb) return pa.localeCompare(pb);
      } else if (mode === "team") {
        var ta = teamKey(a);
        var tb = teamKey(b);
        if (ta !== tb) return ta.localeCompare(tb);
      } else if (mode === "joined") {
        return Number(b.created_at || b.joined_at || 0) - Number(a.created_at || a.joined_at || 0);
      } else if (mode === "name") {
        var na = String(a.display_name || a.email || a.username || "").toLowerCase();
        var nb = String(b.display_name || b.email || b.username || "").toLowerCase();
        if (na !== nb) return na.localeCompare(nb);
      } else {
        // activity (default)
        return Number(b.last_seen_at || b.updated_at || 0) - Number(a.last_seen_at || a.updated_at || 0);
      }
      var na2 = String(a.display_name || a.email || "").toLowerCase();
      var nb2 = String(b.display_name || b.email || "").toLowerCase();
      return na2.localeCompare(nb2);
    });
    return list;
  }

  function renderAdminUsersList() {
    var ul = document.getElementById("rbacUsersList");
    if (!ul) return;
    var sortEl = document.getElementById("rbacUsersSort");
    var mode = sortEl ? sortEl.value : "activity";
    var users = sortAdminUsers(window.__adminUsers || [], mode);
    var canManage = !!window.__adminCanManage;
    if (!users.length) {
      ul.innerHTML = '<li class="empty">No users yet</li>';
      return;
    }
    ul.innerHTML = users.map(function (u) {
      var name = u.display_name || u.email || u.username || "User";
      var email = u.email || "";
      var uname = u.username && u.username !== email ? u.username : "";
      var roles = (u.roles || []).join(", ") || "(none)";
      var teams = (u.team_ids || []).join(", ") || "—";
      return (
        '<li class="admin-user-row" data-user-key="' + escapeHtml(u.user_key || "") + '" tabindex="0">' +
          '<div class="admin-user-main">' +
            '<strong class="admin-user-name">' + escapeHtml(name) + "</strong>" +
            (email && email !== name ? '<span class="admin-user-email">' + escapeHtml(email) + "</span>" : "") +
            (uname && uname !== name ? '<span class="admin-user-uname">@' + escapeHtml(uname) + "</span>" : "") +
          "</div>" +
          '<div class="admin-user-meta">' +
            '<span class="hierarchy-chip">' + escapeHtml(providerLabel(u.provider)) + "</span>" +
            '<span class="hierarchy-chip is-rank">' + escapeHtml(roles) + "</span>" +
            '<span class="hierarchy-chip">team: ' + escapeHtml(teams) + "</span>" +
          "</div>" +
          '<div class="admin-user-times">' +
            "<span>Joined " + escapeHtml(formatAdminWhen(u.created_at || u.joined_at)) + "</span>" +
            "<span>Active " + escapeHtml(formatAdminWhen(u.last_seen_at)) + "</span>" +
            (canManage ? '<span class="admin-user-hint">Right-click to change role</span>' : "") +
          "</div>" +
        "</li>"
      );
    }).join("");

    ul.querySelectorAll(".admin-user-row").forEach(function (row) {
      row.addEventListener("contextmenu", function (e) {
        e.preventDefault();
        openAdminUserCtxMenu(e.clientX, e.clientY, row.getAttribute("data-user-key"));
      });
    });
  }

  function hideAdminUserCtxMenu() {
    var menu = document.getElementById("adminUserCtxMenu");
    if (menu) {
      menu.hidden = true;
      menu.innerHTML = "";
    }
  }

  function openAdminUserCtxMenu(x, y, userKey) {
    var menu = document.getElementById("adminUserCtxMenu");
    if (!menu || !userKey) return;
    if (!window.__adminCanManage) {
      toast("Only Owner/admin can change roles", "err");
      return;
    }
    var users = window.__adminUsers || [];
    var user = null;
    for (var i = 0; i < users.length; i++) {
      if (users[i].user_key === userKey) {
        user = users[i];
        break;
      }
    }
    if (!user) return;
    var me = window.__adminMe || {};
    var grantable = me.grantable_roles || [];
    var rolesMeta = window.__adminRolesMeta || {};
    if (!grantable.length) {
      grantable = Object.keys(rolesMeta).filter(function (id) { return id !== "admin"; });
    }
    var current = (user.roles || [])[0] || "";
    var label = user.display_name || user.email || user.username || userKey;
    var html = '<div class="admin-ctx-title">' + escapeHtml(label) + "</div>";
    html += '<div class="admin-ctx-sub">Set role</div>';
    html += grantable.map(function (id) {
      var meta = rolesMeta[id] || {};
      var active = id === current ? " is-active" : "";
      return (
        '<button type="button" class="admin-ctx-item' + active + '" data-role="' +
        escapeHtml(id) +
        '" role="menuitem">' +
        escapeHtml(meta.label || id) +
        (meta.rank != null ? ' <span class="admin-ctx-rank">rank ' + escapeHtml(String(meta.rank)) + "</span>" : "") +
        "</button>"
      );
    }).join("");
    menu.innerHTML = html;
    menu.hidden = false;
    var pad = 8;
    var mw = menu.offsetWidth || 220;
    var mh = menu.offsetHeight || 160;
    var left = Math.min(x, window.innerWidth - mw - pad);
    var top = Math.min(y, window.innerHeight - mh - pad);
    menu.style.left = Math.max(pad, left) + "px";
    menu.style.top = Math.max(pad, top) + "px";

    menu.querySelectorAll("[data-role]").forEach(function (btn) {
      btn.addEventListener("click", async function () {
        var role = btn.getAttribute("data-role");
        hideAdminUserCtxMenu();
        try {
          await api("/api/rbac/users", {
            method: "POST",
            body: JSON.stringify({
              user_key: user.user_key,
              username: user.username || user.display_name || "",
              email: user.email || "",
              sub: user.sub || "",
              roles: [role],
            }),
          });
          toast("Role updated to " + role, "ok");
          loadAdminPanel();
        } catch (err) {
          toast(err.message || "Could not update role", "err");
        }
      });
    });
  }

  function populateGrantableRoleSelect(grantable, rolesMeta) {
    var sel = document.getElementById("rbacUserRoleSelect");
    if (!sel) return;
    var list = Array.isArray(grantable) ? grantable.slice() : [];
    if (!list.length) {
      list = Object.keys(rolesMeta || {}).filter(function (id) {
        return id !== "admin";
      });
    }
    sel.innerHTML = list.map(function (id) {
      var meta = (rolesMeta && rolesMeta[id]) || {};
      var label = meta.label || id;
      var rank = meta.rank != null ? meta.rank : "?";
      return '<option value="' + escapeHtml(id) + '">' + escapeHtml(label) + " (" + escapeHtml(id) + ", rank " + rank + ")</option>";
    }).join("");
  }

  function renderRbacPermChecks(selected) {
    var host = document.getElementById("rbacPermChecks");
    if (!host) return;
    var selectedSet = {};
    (selected || []).forEach(function (p) { selectedSet[p] = true; });
    var catalog = window.__rbacPermissionCatalog || [];
    host.innerHTML = catalog.map(function (p) {
      var id = p.id || p;
      var desc = p.description || "";
      var checked = selectedSet[id] ? " checked" : "";
      return (
        '<label style="display:flex;gap:0.4rem;align-items:flex-start;font-size:0.9rem;">' +
        '<input type="checkbox" name="perm" value="' + escapeHtml(id) + '"' + checked + ' />' +
        "<span><code>" + escapeHtml(id) + "</code><br/><span class=\"section-desc\">" + escapeHtml(desc) + "</span></span>" +
        "</label>"
      );
    }).join("");
  }

  function selectedRolePerms() {
    var host = document.getElementById("rbacPermChecks");
    if (!host) return [];
    return Array.prototype.slice.call(host.querySelectorAll('input[name="perm"]:checked')).map(function (el) {
      return el.value;
    });
  }

  function openRoleDrawer(mode) {
    var drawer = document.getElementById("roleDrawer");
    if (!drawer) return;
    drawer.hidden = false;
    drawer.setAttribute("aria-hidden", "false");
    var kicker = document.getElementById("roleDrawerKicker");
    var title = document.getElementById("roleDrawerTitle");
    if (mode === "edit") {
      if (kicker) kicker.textContent = "Edit role";
      if (title) title.textContent = "Permissions & details";
    } else {
      if (kicker) kicker.textContent = "New role";
      if (title) title.textContent = "Create custom role";
    }
  }

  function closeRoleDrawer() {
    var drawer = document.getElementById("roleDrawer");
    if (!drawer) return;
    drawer.hidden = true;
    drawer.setAttribute("aria-hidden", "true");
    resetRoleForm();
  }

  function resetRoleForm() {
    var editId = document.getElementById("rbacRoleEditId");
    var nameEl = document.getElementById("rbacRoleName");
    var labelEl = document.getElementById("rbacRoleLabel");
    var rankEl = document.getElementById("rbacRoleRank");
    var resetBtn = document.getElementById("rbacRoleResetBtn");
    var saveBtn = document.getElementById("rbacRoleSaveBtn");
    if (editId) editId.value = "";
    if (nameEl) {
      nameEl.value = "";
      nameEl.disabled = false;
    }
    if (labelEl) labelEl.value = "";
    if (rankEl) {
      var ceiling = window.__adminMe && window.__adminMe.grant_ceiling != null
        ? Number(window.__adminMe.grant_ceiling)
        : 10;
      rankEl.value = String(Math.min(10, ceiling));
      rankEl.max = String(ceiling);
    }
    if (resetBtn) resetBtn.hidden = true;
    if (saveBtn) saveBtn.textContent = "Create role";
    renderRbacPermChecks(["read_infrastructure"]);
  }

  function setHierarchyDirty(dirty) {
    window.__hierarchyDirty = !!dirty;
    var bar = document.getElementById("hierarchySaveBar");
    if (bar) bar.hidden = !dirty;
  }

  function currentHierarchyOrder() {
    var list = document.getElementById("rbacRolesList");
    if (!list) return [];
    return Array.prototype.slice.call(list.querySelectorAll(".hierarchy-item")).map(function (el) {
      return el.getAttribute("data-role");
    }).filter(Boolean);
  }

  function renderRbacRoles(data, me, canManageRbac) {
    window.__rbacPermissionCatalog = data.permissions || [];
    window.__rbacRolesMeta = data.roles || {};
    var list = document.getElementById("rbacRolesList");
    if (!list) return;
    var roles = data.roles || {};
    var ids = Object.keys(roles).sort(function (a, b) {
      var ra = Number((roles[a] && roles[a].rank) || 0);
      var rb = Number((roles[b] && roles[b].rank) || 0);
      if (rb !== ra) return rb - ra;
      return a.localeCompare(b);
    });
    window.__hierarchySavedOrder = ids.slice();
    setHierarchyDirty(false);

    var ceiling = me.grant_ceiling != null ? Number(me.grant_ceiling) : 0;
    var myRank = me.highest_rank != null ? Number(me.highest_rank) : 0;
    if (!ids.length) {
      list.innerHTML = '<li class="hierarchy-empty">No roles</li>';
      return;
    }

    list.innerHTML = ids.map(function (id) {
      var r = roles[id] || {};
      var rank = r.rank != null ? r.rank : 0;
      var pinned = rank >= myRank || id === "admin";
      var canDrag = canManageRbac && !pinned;
      var canEdit = canManageRbac && !r.builtin && rank < myRank;
      var canDelete = canEdit;
      var perms = (r.permissions || []).join(", ") || "(none)";
      var chips = '<span class="hierarchy-chip is-rank">rank ' + escapeHtml(String(rank)) + "</span>";
      if (r.builtin) chips += '<span class="hierarchy-chip is-builtin">builtin</span>';
      else chips += '<span class="hierarchy-chip">custom</span>';
      if (rank <= ceiling) chips += '<span class="hierarchy-chip">grantable</span>';
      if (pinned) chips += '<span class="hierarchy-chip">pinned</span>';

      var actions = "";
      if (canEdit) {
        actions +=
          '<button type="button" class="btn btn-ghost rbac-role-edit" data-role="' +
          escapeHtml(id) +
          '">Edit</button>';
      }
      if (canDelete) {
        actions +=
          '<button type="button" class="btn btn-ghost rbac-role-del" data-role="' +
          escapeHtml(id) +
          '">Delete</button>';
      }

      return (
        '<li class="hierarchy-item' +
        (canDrag ? " is-draggable" : "") +
        (pinned ? " is-pinned" : "") +
        '" data-role="' +
        escapeHtml(id) +
        '" draggable="' +
        (canDrag ? "true" : "false") +
        '">' +
        '<div class="hierarchy-handle" title="' +
        (canDrag ? "Drag to reorder" : "Pinned") +
        '" aria-hidden="true">' +
        (canDrag ? "⋮⋮" : "★") +
        "</div>" +
        '<div class="hierarchy-body">' +
        '<div class="hierarchy-title-row">' +
        '<p class="hierarchy-title">' +
        escapeHtml(r.label || id) +
        "</p>" +
        '<span class="hierarchy-id">' +
        escapeHtml(id) +
        "</span>" +
        "</div>" +
        '<div class="hierarchy-meta">' +
        chips +
        "</div>" +
        '<p class="hierarchy-perms">' +
        escapeHtml(perms) +
        "</p>" +
        "</div>" +
        '<div class="hierarchy-actions">' +
        actions +
        "</div>" +
        "</li>"
      );
    }).join("");

    bindHierarchyDrag(list, canManageRbac);

    list.querySelectorAll(".rbac-role-edit").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var id = btn.getAttribute("data-role");
        var r = (window.__rbacRolesMeta || {})[id] || {};
        var editId = document.getElementById("rbacRoleEditId");
        var nameEl = document.getElementById("rbacRoleName");
        var labelEl = document.getElementById("rbacRoleLabel");
        var rankEl = document.getElementById("rbacRoleRank");
        var resetBtn = document.getElementById("rbacRoleResetBtn");
        var saveBtn = document.getElementById("rbacRoleSaveBtn");
        if (editId) editId.value = id;
        if (nameEl) {
          nameEl.value = id;
          nameEl.disabled = true;
        }
        if (labelEl) labelEl.value = r.label || id;
        if (rankEl) {
          rankEl.value = String(r.rank != null ? r.rank : 0);
          if (me.grant_ceiling != null) rankEl.max = String(me.grant_ceiling);
        }
        if (resetBtn) resetBtn.hidden = false;
        if (saveBtn) saveBtn.textContent = "Save role";
        renderRbacPermChecks(r.permissions || []);
        openRoleDrawer("edit");
      });
    });
    list.querySelectorAll(".rbac-role-del").forEach(function (btn) {
      btn.addEventListener("click", async function () {
        var id = btn.getAttribute("data-role");
        if (!window.confirm("Delete role '" + id + "'? Users with only this role become visitors.")) return;
        try {
          await api("/api/rbac/roles/" + encodeURIComponent(id), { method: "DELETE" });
          toast("Role deleted", "ok");
          loadAdminPanel();
        } catch (err) {
          toast(err.message || "Delete failed", "err");
        }
      });
    });
  }

  function bindHierarchyDrag(list, canManageRbac) {
    if (!list || !canManageRbac) return;
    var dragId = null;

    list.querySelectorAll(".hierarchy-item.is-draggable").forEach(function (item) {
      item.addEventListener("dragstart", function (e) {
        dragId = item.getAttribute("data-role");
        item.classList.add("is-dragging");
        try {
          e.dataTransfer.effectAllowed = "move";
          e.dataTransfer.setData("text/plain", dragId || "");
        } catch (_) {}
      });
      item.addEventListener("dragend", function () {
        item.classList.remove("is-dragging");
        list.querySelectorAll(".is-drop-target").forEach(function (el) {
          el.classList.remove("is-drop-target");
        });
        dragId = null;
        var order = currentHierarchyOrder();
        var saved = window.__hierarchySavedOrder || [];
        setHierarchyDirty(order.join("|") !== saved.join("|"));
      });
    });

    list.querySelectorAll(".hierarchy-item").forEach(function (item) {
      item.addEventListener("dragover", function (e) {
        if (!dragId) return;
        var targetId = item.getAttribute("data-role");
        if (!targetId || targetId === dragId) return;
        if (item.classList.contains("is-pinned") && targetId === "admin") return;
        e.preventDefault();
        item.classList.add("is-drop-target");
        try {
          e.dataTransfer.dropEffect = "move";
        } catch (_) {}
      });
      item.addEventListener("dragleave", function () {
        item.classList.remove("is-drop-target");
      });
      item.addEventListener("drop", function (e) {
        e.preventDefault();
        item.classList.remove("is-drop-target");
        var fromId = dragId || (e.dataTransfer && e.dataTransfer.getData("text/plain"));
        var toId = item.getAttribute("data-role");
        if (!fromId || !toId || fromId === toId) return;
        var fromEl = list.querySelector('.hierarchy-item[data-role="' + CSS.escape(fromId) + '"]');
        if (!fromEl || fromEl.classList.contains("is-pinned")) return;

        if (item.classList.contains("is-pinned")) {
          // Never place a movable role above pinned roles.
          if (item.nextSibling) list.insertBefore(fromEl, item.nextSibling);
          else list.appendChild(fromEl);
        } else {
          var rect = item.getBoundingClientRect();
          var before = e.clientY < rect.top + rect.height / 2;
          if (before) list.insertBefore(fromEl, item);
          else if (item.nextSibling) list.insertBefore(fromEl, item.nextSibling);
          else list.appendChild(fromEl);
        }
        // Keep Owner pinned at top
        var owner = list.querySelector('.hierarchy-item[data-role="admin"]');
        if (owner && list.firstElementChild !== owner) {
          list.insertBefore(owner, list.firstElementChild);
        }
        var order = currentHierarchyOrder();
        var saved = window.__hierarchySavedOrder || [];
        setHierarchyDirty(order.join("|") !== saved.join("|"));
      });
    });
  }

  async function saveHierarchyOrder() {
    var order = currentHierarchyOrder();
    if (!order.length) return;
    var btn = document.getElementById("hierarchySaveBtn");
    if (btn) btn.disabled = true;
    try {
      var out = await api("/api/rbac/roles/order", {
        method: "PUT",
        body: JSON.stringify({ order: order }),
      });
      toast("Hierarchy saved", "ok");
      window.__hierarchySavedOrder = (out.order || order).slice();
      setHierarchyDirty(false);
      loadAdminPanel();
    } catch (err) {
      toast(err.message || "Could not save hierarchy", "err");
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function loadSetupRedoPanel() {
    var section = document.getElementById("setupRedoSection");
    var line = document.getElementById("setupStatusLine");
    var btn = document.getElementById("setupRedoBtn");
    if (!section) return;
    try {
      var st = await api("/api/setup/status");
      var can = !!st.can_manage;
      section.hidden = !can;
      if (!can) return;
      var mode = st.mode ? String(st.mode) : "—";
      var by = st.completed_by ? String(st.completed_by) : "—";
      if (line) {
        line.textContent = st.completed
          ? ("Setup completed (" + mode + ")" + (by && by !== "—" ? " by " + by : "") + ".")
          : "Setup is not marked complete — opening Redo will take you to the wizard.";
      }
      if (btn) btn.disabled = false;
    } catch (err) {
      section.hidden = false;
      if (line) line.textContent = (err && err.message) || "Could not load setup status.";
    }
  }

  var rbacRefreshBtn = document.getElementById("rbacRefreshBtn");
  if (rbacRefreshBtn) rbacRefreshBtn.addEventListener("click", loadAdminPanel);
  var accessRefreshBtn = document.getElementById("accessRefreshBtn");
  if (accessRefreshBtn) accessRefreshBtn.addEventListener("click", loadAccessPanel);

  var setupRedoBtn = document.getElementById("setupRedoBtn");
  if (setupRedoBtn) {
    setupRedoBtn.addEventListener("click", async function () {
      var statusEl = document.getElementById("setupRedoStatus");
      if (
        !window.confirm(
          "Redo first-run setup?\n\nYou will return to the Novice / Advanced wizard. Existing users, secrets, and playbooks are kept."
        )
      ) {
        return;
      }
      setupRedoBtn.disabled = true;
      if (statusEl) statusEl.textContent = "Resetting setup…";
      try {
        var out = await api("/api/setup/reset", {
          method: "POST",
          headers: { "Content-Type": "application/json", Accept: "application/json" },
          body: "{}",
        });
        if (statusEl) statusEl.textContent = "Opening setup wizard…";
        toast("Setup reset — opening wizard", "ok");
        window.location.href = (out && out.redirect) || "/setup";
      } catch (err) {
        if (statusEl) statusEl.textContent = (err && err.message) || "Could not reset setup";
        toast((err && err.message) || "Could not reset setup", "err");
        setupRedoBtn.disabled = false;
      }
    });
  }

  var siteNameForm = document.getElementById("siteNameForm");
  if (siteNameForm) {
    siteNameForm.addEventListener("submit", async function (e) {
      e.preventDefault();
      var input = document.getElementById("siteNameInput");
      var name = input && input.value ? String(input.value).trim() : "";
      if (!name) {
        toast("Enter a controller name", "err");
        return;
      }
      try {
        var res = await api("/api/controller/site-name", {
          method: "POST",
          body: JSON.stringify({ name: name }),
        });
        setText("siteNameStatus", "Saved — Hayabusa branch picker will show \"" + (res.display_name || name) + "\".");
        var siteDisplay = document.getElementById("siteNameDisplay");
        if (siteDisplay) siteDisplay.textContent = res.display_name || name;
        toast("Controller name saved", "ok");
      } catch (err) {
        toast(err.message || "Save failed", "err");
        setText("siteNameStatus", err.message || "Save failed");
      }
    });
  }

  var syncBtn = document.getElementById("syncHayabusaBtn");
  if (syncBtn) {
    syncBtn.addEventListener("click", async function () {
      syncBtn.disabled = true;
      setText("syncHayabusaStatus", "Syncing…");
      try {
        var res = await api("/api/playbooks/sync-hayabusa", { method: "POST", body: "{}" });
        setText("syncHayabusaStatus", "Synced " + (res.count || 0) + " file(s) to Hayabusa.");
        toast("Synced to Hayabusa", "ok");
      } catch (err) {
        setText("syncHayabusaStatus", err.message || "Sync failed");
        toast(err.message || "Sync failed", "err");
      } finally {
        syncBtn.disabled = false;
      }
    });
  }

  var userForm = document.getElementById("rbacUserForm");
  if (userForm) {
    userForm.addEventListener("submit", async function (e) {
      e.preventDefault();
      var fd = new FormData(userForm);
      try {
        await api("/api/rbac/users", {
          method: "POST",
          body: JSON.stringify({
            username: fd.get("username"),
            email: fd.get("email"),
            roles: [fd.get("role")],
          }),
        });
        toast("User saved", "ok");
        userForm.reset();
        loadAdminPanel();
      } catch (err) {
        toast(err.message || "Save failed", "err");
      }
    });
  }

  var roleForm = document.getElementById("rbacRoleForm");
  if (roleForm) {
    roleForm.addEventListener("submit", async function (e) {
      e.preventDefault();
      var editId = (document.getElementById("rbacRoleEditId") || {}).value || "";
      var name = (document.getElementById("rbacRoleName") || {}).value || "";
      var label = (document.getElementById("rbacRoleLabel") || {}).value || "";
      var rankRaw = (document.getElementById("rbacRoleRank") || {}).value;
      var body = {
        name: name,
        label: label,
        rank: rankRaw === "" ? undefined : Number(rankRaw),
        permissions: selectedRolePerms(),
      };
      try {
        if (editId) {
          await api("/api/rbac/roles/" + encodeURIComponent(editId), {
            method: "PATCH",
            body: JSON.stringify({
              label: body.label,
              rank: body.rank,
              permissions: body.permissions,
            }),
          });
          toast("Role updated", "ok");
        } else {
          await api("/api/rbac/roles", {
            method: "POST",
            body: JSON.stringify(body),
          });
          toast("Role created", "ok");
        }
        resetRoleForm();
        closeRoleDrawer();
        loadAdminPanel();
      } catch (err) {
        toast(err.message || "Role save failed", "err");
      }
    });
  }
  var roleResetBtn = document.getElementById("rbacRoleResetBtn");
  if (roleResetBtn) {
    roleResetBtn.addEventListener("click", function () {
      closeRoleDrawer();
    });
  }

  var teamForm = document.getElementById("rbacTeamForm");
  if (teamForm) {
    teamForm.addEventListener("submit", async function (e) {
      e.preventDefault();
      var fd = new FormData(teamForm);
      try {
        await api("/api/rbac/teams", {
          method: "POST",
          body: JSON.stringify({ name: fd.get("name") }),
        });
        toast("Team created", "ok");
        teamForm.reset();
        loadAdminPanel();
      } catch (err) {
        toast(err.message || "Create failed", "err");
      }
    });
  }

  var ownerForm = document.getElementById("rbacOwnerForm");
  if (ownerForm) {
    ownerForm.addEventListener("submit", async function (e) {
      e.preventDefault();
      var fd = new FormData(ownerForm);
      try {
        await api("/api/rbac/playbook-owner", {
          method: "POST",
          body: JSON.stringify({
            path: fd.get("path"),
            owner_type: fd.get("owner_type"),
            owner_id: fd.get("owner_id"),
          }),
        });
        toast("Owner set", "ok");
        ownerForm.reset();
        loadAdminPanel();
      } catch (err) {
        toast(err.message || "Owner failed", "err");
      }
    });
  }

  // Tabs (dashboard only); administration page loads its own panel
  var isAdminPage = document.body && document.body.getAttribute("data-page") === "administration";
  if (isAdminPage) {
    loadAdminPanel();

    document.querySelectorAll("[data-admin-section]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var name = btn.getAttribute("data-admin-section") || "hierarchy";
        document.querySelectorAll(".admin-rail-btn").forEach(function (b) {
          b.classList.toggle("is-active", b.getAttribute("data-admin-section") === name);
        });
        document.querySelectorAll(".admin-section").forEach(function (panel) {
          var match = panel.getAttribute("data-admin-panel") === name;
          panel.classList.toggle("is-active", match);
          if (match) panel.removeAttribute("hidden");
          else panel.setAttribute("hidden", "");
        });
        if (name === "ztp" && typeof loadZtpPanel === "function") {
          loadZtpPanel();
        }
      });
    });

    var newRoleBtn = document.getElementById("adminNewRoleBtn");
    if (newRoleBtn) {
      newRoleBtn.addEventListener("click", function () {
        if (!window.__adminCanManage) {
          toast("Only Owner/admin can create roles", "err");
          return;
        }
        resetRoleForm();
        openRoleDrawer("create");
      });
    }
    var drawerClose = document.getElementById("roleDrawerClose");
    if (drawerClose) drawerClose.addEventListener("click", closeRoleDrawer);
    var drawerBackdrop = document.getElementById("roleDrawerBackdrop");
    if (drawerBackdrop) drawerBackdrop.addEventListener("click", closeRoleDrawer);
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") closeRoleDrawer();
    });

    var hierarchySaveBtn = document.getElementById("hierarchySaveBtn");
    if (hierarchySaveBtn) hierarchySaveBtn.addEventListener("click", saveHierarchyOrder);
    var hierarchyDiscardBtn = document.getElementById("hierarchyDiscardBtn");
    if (hierarchyDiscardBtn) {
      hierarchyDiscardBtn.addEventListener("click", function () {
        loadAdminPanel();
      });
    }
    var signinSaveBtn = document.getElementById("signinAllowlistSaveBtn");
    if (signinSaveBtn) {
      signinSaveBtn.addEventListener("click", function () {
        saveSignInAllowlist();
      });
    }
    var localPasswordSaveBtn = document.getElementById("localPasswordSaveBtn");
    if (localPasswordSaveBtn) {
      localPasswordSaveBtn.addEventListener("click", function () {
        saveLocalPasswordSetting();
      });
    }
    var require2faSaveBtn = document.getElementById("require2faSaveBtn");
    if (require2faSaveBtn) {
      require2faSaveBtn.addEventListener("click", function () {
        saveRequire2faSetting();
      });
    }
    var meshRefreshBtn = document.getElementById("meshConnectRefreshBtn");
    if (meshRefreshBtn) {
      meshRefreshBtn.addEventListener("click", function () {
        loadMeshConnectPanel();
      });
    }
    var meshFetchBtn = document.getElementById("meshFetchKeyBtn");
    if (meshFetchBtn) {
      meshFetchBtn.addEventListener("click", function () {
        meshFetchKeyFromHayabusa();
      });
    }
    var meshConnectBtn = document.getElementById("meshConnectBtn");
    if (meshConnectBtn) {
      meshConnectBtn.addEventListener("click", function () {
        meshSaveAndConnect();
      });
    }
    var meshRevealBtn = document.getElementById("meshAuthKeyRevealBtn");
    if (meshRevealBtn) {
      meshRevealBtn.addEventListener("click", function () {
        var keyEl = document.getElementById("meshAuthKey");
        if (!keyEl) return;
        if (keyEl.type === "password") {
          keyEl.type = "text";
          meshRevealBtn.textContent = "Hide";
        } else {
          keyEl.type = "password";
          meshRevealBtn.textContent = "Show";
        }
      });
    }
    document.querySelectorAll("[data-copy-from]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var id = btn.getAttribute("data-copy-from");
        var el = id && document.getElementById(id);
        if (!el) return;
        var text = el.value != null ? String(el.value) : String(el.textContent || "");
        if (!text) {
          toast("Nothing to copy", "err");
          return;
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(
            function () {
              toast("Copied", "ok");
            },
            function () {
              toast("Copy failed", "err");
            }
          );
        } else {
          try {
            el.focus();
            el.select();
            document.execCommand("copy");
            toast("Copied", "ok");
          } catch (e) {
            toast("Copy failed", "err");
          }
        }
      });
    });
    var usersSort = document.getElementById("rbacUsersSort");
    if (usersSort) {
      usersSort.addEventListener("change", function () {
        renderAdminUsersList();
      });
    }
    document.addEventListener("click", function (e) {
      var menu = document.getElementById("adminUserCtxMenu");
      if (!menu || menu.hidden) return;
      if (menu.contains(e.target)) return;
      hideAdminUserCtxMenu();
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") hideAdminUserCtxMenu();
    });
  } else {
    document.querySelectorAll(".page-tab").forEach(function (btn) {
      btn.addEventListener("click", function () {
        showTab(btn.getAttribute("data-tab") || "overview");
      });
    });
    document.querySelectorAll("[data-goto]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        showTab(btn.getAttribute("data-goto") || "overview");
      });
    });
    var initialTab = (location.hash || "").replace(/^#/, "");
    showTab(TAB_META[initialTab] ? initialTab : "overview");
    window.addEventListener("hashchange", function () {
      var t = (location.hash || "").replace(/^#/, "");
      if (TAB_META[t]) showTab(t);
    });
  }

  var guacEmbedUrl = "";
  function setGuacStatus(text, ok) {
    setText("guacStatus", text || "");
    var pill = document.getElementById("guacPill");
    if (!pill) return;
    pill.className = "pill " + (ok === true ? "pill-ok" : ok === false ? "pill-err" : "pill-idle");
    pill.textContent = ok === true ? "Ready" : ok === false ? "Error" : "Console";
  }
  function loadGuacPanel() {
    api("/api/console/guacamole/status").then(function (d) {
      if (d && d.ok) {
        setGuacStatus("Guacamole is available on this controller.", true);
      }
    }).catch(function () {});
  }
  async function guacConnect(forceReload) {
    setGuacStatus("Loading Apache Guacamole…");
    try {
      var frame = document.getElementById("guacFrame");
      var ph = document.getElementById("guacPlaceholder");
      if (!frame) throw new Error("Guacamole frame not found");
      if (!guacEmbedUrl || forceReload) {
        var body = await api("/api/console/guacamole/bootstrap", { method: "POST" });
        if (!body || !body.success) {
          throw new Error((body && body.error) || "bootstrap failed");
        }
        guacEmbedUrl = body.embed_url || "/console/guacamole/embed";
      }
      if (forceReload || frame.getAttribute("src") !== guacEmbedUrl) {
        frame.src = guacEmbedUrl;
      }
      if (ph) ph.style.display = "none";
      setGuacStatus("Controller Guacamole ready — LAN SSH connections use vault secrets.", true);
    } catch (err) {
      setGuacStatus("Guacamole failed: " + (err && err.message ? err.message : err), false);
    }
  }
  function guacClear() {
    var frame = document.getElementById("guacFrame");
    var ph = document.getElementById("guacPlaceholder");
    if (frame) frame.removeAttribute("src");
    if (ph) ph.style.display = "flex";
    setGuacStatus("Console cleared.");
  }
  var guacLoadBtn = document.getElementById("guacLoadBtn");
  if (guacLoadBtn) guacLoadBtn.addEventListener("click", function () { guacConnect(false); });
  var guacRefreshBtn = document.getElementById("guacRefreshBtn");
  if (guacRefreshBtn) guacRefreshBtn.addEventListener("click", function () {
    guacEmbedUrl = "";
    guacConnect(true);
  });
  var guacClearBtn = document.getElementById("guacClearBtn");
  if (guacClearBtn) guacClearBtn.addEventListener("click", guacClear);
  window.loadGuacPanel = loadGuacPanel;

  // --- Backup jobs (stored on this controller) ---
  var backupState = {
    groups: [],
    selectedCidr: "",
    selectedHost: null,
    sourceHost: null,
    destHost: null,
    jobs: [],
  };

  function backupEsc(s) {
    return escapeHtml(String(s == null ? "" : s));
  }
  function backupHostLabel(h) {
    return String((h && (h.hostname || h.name || h.ip)) || "").trim() || "host";
  }
  function backupIpInCidr(ip, cidr) {
    try {
      var parts = String(cidr || "").split("/");
      if (parts.length !== 2) return false;
      var base = parts[0].split(".").map(function (x) { return parseInt(x, 10); });
      var prefix = parseInt(parts[1], 10);
      var ipParts = String(ip || "").split(".").map(function (x) { return parseInt(x, 10); });
      if (base.length !== 4 || ipParts.length !== 4 || !(prefix >= 0 && prefix <= 32)) return false;
      var baseInt = ((base[0] << 24) >>> 0) + (base[1] << 16) + (base[2] << 8) + base[3];
      var ipInt = ((ipParts[0] << 24) >>> 0) + (ipParts[1] << 16) + (ipParts[2] << 8) + ipParts[3];
      if (prefix === 0) return true;
      var mask = prefix === 32 ? 0xffffffff : ((0xffffffff << (32 - prefix)) >>> 0);
      return ((baseInt & mask) >>> 0) === ((ipInt & mask) >>> 0);
    } catch (_) { return false; }
  }
  function backupBuildGroups(payload) {
    var hosts = Array.isArray(payload && payload.hosts) ? payload.hosts.slice() : [];
    var cidrs = Array.isArray(payload && payload.cidrs) ? payload.cidrs.slice() : [];
    var groups = cidrs.map(function (cidr) {
      return {
        cidr: String(cidr),
        label: String(cidr),
        hosts: hosts.filter(function (h) { return backupIpInCidr(String(h.ip || ""), cidr); }),
      };
    });
    var assigned = {};
    groups.forEach(function (g) {
      (g.hosts || []).forEach(function (h) { if (h && h.ip) assigned[String(h.ip)] = 1; });
    });
    var other = hosts.filter(function (h) { return h && h.ip && !assigned[String(h.ip)]; });
    if (other.length || !groups.length) {
      groups.push({ cidr: "__other__", hosts: other, label: "Other / unknown" });
    }
    return groups;
  }
  function backupSetFormStatus(msg) {
    setText("backupFormStatus", msg || "");
  }
  function backupSyncFields() {
    var src = document.getElementById("backupJobSource");
    var dst = document.getElementById("backupJobDest");
    if (src) {
      src.value = backupState.sourceHost
        ? (backupHostLabel(backupState.sourceHost) + " (" + (backupState.sourceHost.ip || "") + ")")
        : "";
    }
    if (dst) {
      dst.value = backupState.destHost
        ? (backupHostLabel(backupState.destHost) + " (" + (backupState.destHost.ip || "") + ")")
        : "";
    }
  }
  function backupRenderNets() {
    var list = document.getElementById("backupNetList");
    var hostsEl = document.getElementById("backupHostList");
    if (!list || !hostsEl) return;
    var q = String((document.getElementById("backupNetSearch") || {}).value || "").trim().toLowerCase();
    var visible = backupState.groups.filter(function (g) {
      if (!q) return true;
      if (String(g.label || "").toLowerCase().indexOf(q) >= 0) return true;
      return (g.hosts || []).some(function (h) {
        return [backupHostLabel(h), h.ip, h.hostname, h.name].join(" ").toLowerCase().indexOf(q) >= 0;
      });
    });
    if (!backupState.groups.length) {
      list.innerHTML = '<li class="empty">No LAN networks yet</li>';
    } else {
      list.innerHTML = visible.map(function (g) {
        var count = (g.hosts || []).filter(function (h) {
          if (!q) return true;
          return [backupHostLabel(h), h.ip].join(" ").toLowerCase().indexOf(q) >= 0;
        }).length;
        return '<li class="job-pending-item' + (g.cidr === backupState.selectedCidr ? ' is-active' : '') +
          '" data-cidr="' + backupEsc(g.cidr) + '" style="cursor:pointer;">' +
          "<div><strong>" + backupEsc(g.label) + "</strong></div>" +
          '<div class="muted">' + count + " host" + (count === 1 ? "" : "s") + "</div></li>";
      }).join("") || '<li class="empty">No matches</li>';
      list.querySelectorAll("[data-cidr]").forEach(function (el) {
        el.addEventListener("click", function () {
          backupState.selectedCidr = el.getAttribute("data-cidr") || "";
          backupState.selectedHost = null;
          backupRenderNets();
        });
      });
    }
    var hosts = [];
    if (backupState.selectedCidr) {
      var group = backupState.groups.find(function (g) { return g.cidr === backupState.selectedCidr; });
      hosts = ((group && group.hosts) || []).filter(function (h) {
        if (!q) return true;
        return [backupHostLabel(h), h.ip].join(" ").toLowerCase().indexOf(q) >= 0;
      });
    }
    if (!backupState.selectedCidr) {
      hostsEl.innerHTML = '<li class="empty">Select a network to list hosts</li>';
    } else if (!hosts.length) {
      hostsEl.innerHTML = '<li class="empty">No hosts in this network</li>';
    } else {
      hostsEl.innerHTML = hosts.map(function (h) {
        var ip = String(h.ip || "");
        var active = backupState.selectedHost && backupState.selectedHost.ip === ip;
        return '<li class="job-pending-item' + (active ? " is-active" : "") +
          '" data-ip="' + backupEsc(ip) + '" style="cursor:pointer;">' +
          "<div><strong>" + backupEsc(backupHostLabel(h)) + "</strong></div>" +
          '<div class="muted">' + backupEsc(ip) + "</div></li>";
      }).join("");
      hostsEl.querySelectorAll("[data-ip]").forEach(function (el) {
        el.addEventListener("click", function () {
          var ip = el.getAttribute("data-ip") || "";
          backupState.selectedHost = null;
          backupState.groups.forEach(function (g) {
            (g.hosts || []).forEach(function (h) {
              if (String(h.ip || "") === ip) {
                backupState.selectedHost = {
                  ip: ip,
                  name: backupHostLabel(h),
                  hostname: h.hostname || h.name || "",
                  cidr: g.cidr === "__other__" ? "" : g.cidr,
                };
              }
            });
          });
          backupRenderNets();
        });
      });
    }
  }
  function backupFmtWhen(ts) {
    if (!ts) return "—";
    try { return new Date(Number(ts) * 1000).toLocaleString(); } catch (_) { return String(ts); }
  }
  function backupRenderJobs() {
    var list = document.getElementById("backupJobsList");
    if (!list) return;
    var jobs = backupState.jobs || [];
    if (!jobs.length) {
      list.innerHTML = '<li class="empty">No backup jobs yet</li>';
      return;
    }
    list.innerHTML = jobs.map(function (job) {
      var src = job.source_host || {};
      var dst = job.dest_host || {};
      return (
        '<li class="job-pending-item" data-id="' + backupEsc(job.id) + '">' +
          "<div><strong>" + backupEsc(job.name || job.id) + "</strong> · " +
            backupEsc(job.schedule || "manual") + " · " + backupEsc(job.last_status || "—") +
          "</div>" +
          '<div class="muted">' + backupEsc(src.name || src.ip || "?") + " → " +
            backupEsc(dst.name || dst.ip || "?") + " · last " + backupEsc(backupFmtWhen(job.last_run_at)) +
          "</div>" +
          '<details style="margin-top:0.45rem;"><summary class="muted">YAML &amp; details</summary>' +
            "<pre style=\"margin-top:0.5rem;max-height:220px;overflow:auto;white-space:pre-wrap;font-size:12px;background:#0b1220;color:#d7e3ff;padding:0.75rem;border-radius:6px;\">" +
              backupEsc(job.playbook_yaml || "") +
            "</pre>" +
            "<pre style=\"margin-top:0.5rem;max-height:160px;overflow:auto;white-space:pre-wrap;font-size:12px;background:#0b1220;color:#d7e3ff;padding:0.75rem;border-radius:6px;\">" +
              backupEsc(job.inventory_yaml || "") +
            "</pre>" +
          "</details>" +
          '<div class="row" style="margin-top:0.6rem;gap:0.5rem;">' +
            '<button type="button" class="btn btn-primary backup-run" data-id="' + backupEsc(job.id) + '">Run now</button>' +
            '<button type="button" class="btn btn-ghost backup-del" data-id="' + backupEsc(job.id) + '">Delete</button>' +
          "</div>" +
        "</li>"
      );
    }).join("");
    list.querySelectorAll(".backup-run").forEach(function (btn) {
      btn.addEventListener("click", async function () {
        btn.disabled = true;
        try {
          var res = await api("/api/backup-jobs/" + encodeURIComponent(btn.getAttribute("data-id")) + "/run", {
            method: "POST",
            body: "{}",
          });
          toast(res.pending_approval || res.status === "pending_approval"
            ? "Queued for LAN approval"
            : (res.error || "Enqueued"), res.ok === false ? "err" : "ok");
          await loadBackupJobsList();
          if (typeof loadJobsPanel === "function") loadJobsPanel();
        } catch (err) {
          toast(err.message || "Run failed", "err");
          btn.disabled = false;
        }
      });
    });
    list.querySelectorAll(".backup-del").forEach(function (btn) {
      btn.addEventListener("click", async function () {
        if (!window.confirm("Delete this backup job?")) return;
        btn.disabled = true;
        try {
          await api("/api/backup-jobs/" + encodeURIComponent(btn.getAttribute("data-id")), { method: "DELETE" });
          toast("Deleted", "ok");
          await loadBackupJobsList();
        } catch (err) {
          toast(err.message || "Delete failed", "err");
          btn.disabled = false;
        }
      });
    });
  }
  async function loadBackupNetworks() {
    setText("backupNetStatus", "Loading networks…");
    try {
      var data = await api("/api/lan/inventory?probe=1");
      backupState.groups = backupBuildGroups(data || {});
      backupRenderNets();
      setText("backupNetStatus", backupState.groups.length + " network group(s)");
    } catch (err) {
      backupState.groups = [];
      backupRenderNets();
      setText("backupNetStatus", err.message || "Networks failed");
    }
  }
  async function loadBackupJobsList() {
    try {
      var data = await api("/api/backup-jobs");
      backupState.jobs = data.jobs || [];
      backupRenderJobs();
    } catch (err) {
      var list = document.getElementById("backupJobsList");
      if (list) list.innerHTML = '<li class="empty">' + backupEsc(err.message || "Could not load jobs") + "</li>";
    }
  }
  async function loadBackupsPanel() {
    await loadBackupNetworks();
    await loadBackupJobsList();
    try { await api("/api/backup-jobs/tick", { method: "POST", body: "{}" }); } catch (_) {}
    await loadBackupJobsList();
  }
  window.loadBackupsPanel = loadBackupsPanel;

  var backupNetRefreshBtn = document.getElementById("backupNetRefreshBtn");
  if (backupNetRefreshBtn) backupNetRefreshBtn.addEventListener("click", loadBackupNetworks);
  var backupJobsRefreshBtn = document.getElementById("backupJobsRefreshBtn");
  if (backupJobsRefreshBtn) backupJobsRefreshBtn.addEventListener("click", function () {
    loadBackupJobsList();
    api("/api/backup-jobs/tick", { method: "POST", body: "{}" }).then(loadBackupJobsList).catch(function () {});
  });
  var backupNetSearch = document.getElementById("backupNetSearch");
  if (backupNetSearch) {
    backupNetSearch.addEventListener("input", backupRenderNets);
    backupNetSearch.addEventListener("search", backupRenderNets);
  }
  var backupUseSourceBtn = document.getElementById("backupUseSourceBtn");
  if (backupUseSourceBtn) backupUseSourceBtn.addEventListener("click", function () {
    if (!backupState.selectedHost) {
      backupSetFormStatus("Select a host first.");
      return;
    }
    backupState.sourceHost = Object.assign({}, backupState.selectedHost);
    backupSyncFields();
    backupSetFormStatus("Source set.");
  });
  var backupUseDestBtn = document.getElementById("backupUseDestBtn");
  if (backupUseDestBtn) backupUseDestBtn.addEventListener("click", function () {
    if (!backupState.selectedHost) {
      backupSetFormStatus("Select a host first.");
      return;
    }
    backupState.destHost = Object.assign({}, backupState.selectedHost);
    backupSyncFields();
    backupSetFormStatus("Destination set.");
  });
  var backupCreateBtn = document.getElementById("backupCreateBtn");
  if (backupCreateBtn) backupCreateBtn.addEventListener("click", async function () {
    if (!backupState.sourceHost || !backupState.destHost) {
      backupSetFormStatus("Set source and destination hosts.");
      return;
    }
    backupCreateBtn.disabled = true;
    try {
      var schedule = String((document.getElementById("backupJobSchedule") || {}).value || "daily");
      var res = await api("/api/backup-jobs", {
        method: "POST",
        body: JSON.stringify({
          name: String((document.getElementById("backupJobName") || {}).value || ""),
          source_host: backupState.sourceHost,
          dest_host: backupState.destHost,
          schedule: schedule,
          dest_path: String((document.getElementById("backupJobDestPath") || {}).value || "/var/backups/hayabusa"),
          paths: String((document.getElementById("backupJobPaths") || {}).value || "/etc"),
          enabled: schedule !== "manual",
        }),
      });
      if (!res.ok) throw new Error(res.error || "Create failed");
      toast("Backup job created", "ok");
      backupSetFormStatus("Created.");
      await loadBackupJobsList();
    } catch (err) {
      toast(err.message || "Create failed", "err");
      backupSetFormStatus(err.message || "Create failed");
    } finally {
      backupCreateBtn.disabled = false;
    }
  });

  // Initial paint + live updates
  api("/api/status").then(paintStatus).catch(function () {});
  api("/api/gitops/config").then(paintGitopsNav).catch(function () {});
  api("/api/jobs?status=pending_approval").then(function (d) {
    setText("pendingJobsOverview", String((d.jobs || []).length));
  }).catch(function () {});
  if (document.getElementById("ztpPanel")) {
    loadZtpPanel();
    setInterval(function () {
      api("/api/ztp/leases").then(function (d) {
        paintZtpLeases(d.leases || []);
        var n = String(d.count ?? (d.leases || []).length ?? 0);
        setText("ztpLeases", n);
        setText("ztpLeasesOverview", n);
      }).catch(function () {});
    }, 15000);
  }

  try {
    var proto = location.protocol === "https:" ? "wss:" : "ws:";
    var ws = new WebSocket(proto + "//" + location.host + "/ws/status");
    ws.onmessage = function (ev) {
      try {
        var msg = JSON.parse(ev.data);
        if (msg.type === "status" || msg.type === "pong" || msg.type === "ack" || msg.type === "connection") {
          paintStatus(msg);
        }
        if (msg.type === "bridge" && msg.status) {
          paintStatus({ bridge: msg.status, vpn: msg.vpn, connection: msg.connection, enroll: msg.enroll });
        }
      } catch (_) {}
    };
    setInterval(function () {
      if (ws.readyState === 1) ws.send(JSON.stringify({ type: "ping" }));
    }, 5000);
  } catch (_) {}
})();
