/**
 * Craft → Workstations → Ansible & OpenTofu workspace (isolated by user; optional org with membership checks).
 * Tabs: Creation (OpenTofu) | Configuration (Ansible) | Security (SECops) | Files.
 * Saved commands (per browser) + right-click rename in the file tree.
 */
(function () {
    "use strict";

    var _cwd = [];
    var _openFile = null;
    var _ctx = "user";
    var _orgId = null;
    var _canWrite = true;
    var _canEnqueue = true;
    var _canApprove = false;
    var _canRun = true;
    var _canRunViaController = false;
    var _mustUseController = false;
    var _globalReadOnly = false;
    var _LS_KEY = "peregrine_devops_iac_saved_commands_v1";
    var _ctxMenuPath = null;
    var _ctxMenuKind = null;
    var _docClickForCtxBound = false;
    var _activeTab = "creation";
    var _structureMode = "creation";
    var _browserPath = "";
    var _browserSelectedPath = null;
    var _browserSelectedType = null;
    var _browserEntries = [];
    var _browserRootEntries = [];
    var _browserDndInited = false;

    // --- DEVOPS_IAC_MODE_FILTER_BEGIN ---
    var DEVOPS_CREATION_ROOTS = {
        OpenTofu: 1
    };
    var DEVOPS_CONFIGURATION_ROOTS = {
        Ansible: 1
    };
    /** Child folders under Ansible/ (badges + display labels). */
    var DEVOPS_CONFIG_CHILD_KIND = {
        playbooks: "ansible",
        inventory: "ansible",
        inventories: "ansible",
        roles: "ansible",
        group_vars: "ansible",
        host_vars: "ansible",
        OpenTofu: "ansible",
        "IoT Devices": "ansible",
        "SCADA & PLC": "ansible",
        "bare-metal-ztp": "ansible",
        "Security & Fire Systems": "ansible",
        Security: "security",
        "ztp-device-defaults": "ansible",
        ztp: "ztp",
        "vendor-ztp": "ztp",
        openPLC: "plc",
        "residential-routers-and-switches": "api",
        "residential-routers-and-switches-apis": "api"
    };
    var DEVOPS_MIXED_ROOTS = {};
    var DEVOPS_NEUTRAL_NAMES = {
        "README.txt": 1,
        "README.md": 1,
        README: 1
    };
    var DEVOPS_CREATION_DIR_NAMES = {
        opentofu: 1,
        modules: 1,
        environments: 1,
        templates: 1
    };
    var DEVOPS_CONFIGURATION_DIR_NAMES = {
        playbooks: 1,
        ansible: 1,
        runbooks: 1,
        recipes: 1,
        roles: 1,
        inventories: 1,
        inventory: 1,
        group_vars: 1,
        host_vars: 1,
        ztp: 1
    };

    function _devopsNormRel(rel) {
        return String(rel || "")
            .replace(/\\/g, "/")
            .replace(/^\/+|\/+$/g, "");
    }

    function _devopsIsTofuFileName(name) {
        var n = String(name || "").toLowerCase();
        return (
            /\.tf$/i.test(n) ||
            /\.tfvars$/i.test(n) ||
            /\.tofu$/i.test(n) ||
            n === "terraform.tfstate" ||
            n.indexOf("terraform.tfstate.") === 0 ||
            n === ".terraform.lock.hcl" ||
            n === "versions.tf" ||
            n === "variables.tf" ||
            n === "outputs.tf" ||
            n === "main.tf" ||
            n === "common.tfvars"
        );
    }

    function _devopsIsAnsibleFileName(name) {
        var n = String(name || "").toLowerCase();
        return (
            /\.ya?ml$/i.test(n) ||
            n === "ansible.cfg" ||
            n === "inventory" ||
            n === "hosts" ||
            n.slice(-9) === ".ini.yml" ||
            /\.ini$/i.test(n)
        );
    }

    function _devopsRootKind(rootName) {
        var n = String(rootName || "");
        if (DEVOPS_MIXED_ROOTS[n]) {
            return "mixed";
        }
        if (DEVOPS_CREATION_ROOTS[n]) {
            return "creation";
        }
        if (DEVOPS_CONFIGURATION_ROOTS[n]) {
            return "configuration";
        }
        return "unknown";
    }

    function _devopsDirSegmentKind(seg) {
        var s = String(seg || "");
        if (DEVOPS_CREATION_DIR_NAMES[s]) {
            return "creation";
        }
        if (DEVOPS_CONFIGURATION_DIR_NAMES[s]) {
            return "configuration";
        }
        return null;
    }

    function _devopsNormalizeMode(mode) {
        mode = String(mode || "").toLowerCase();
        if (mode === "security" || mode === "secops") {
            return "security";
        }
        if (mode === "configuration" || mode === "config" || mode === "ansible") {
            return "configuration";
        }
        if (mode === "creation" || mode === "tofu" || mode === "opentofu") {
            return "creation";
        }
        return "";
    }

    function _devopsIsAnsibleToolMode(mode) {
        mode = _devopsNormalizeMode(mode);
        return mode === "configuration" || mode === "security";
    }

    function _devopsIsSecurityRel(relPath) {
        var rel = _devopsNormRel(relPath);
        return rel === "Ansible/Security" || rel.indexOf("Ansible/Security/") === 0;
    }

    function _devopsPathAllowedInMode(mode, relPath) {
        mode = _devopsNormalizeMode(mode);
        if (!mode) {
            return true;
        }
        var rel = _devopsNormRel(relPath);
        if (!rel) {
            return true;
        }
        if (mode === "security") {
            if (DEVOPS_NEUTRAL_NAMES[rel]) {
                return true;
            }
            return rel === "Ansible" || _devopsIsSecurityRel(rel);
        }
        if (mode === "configuration" && _devopsIsSecurityRel(rel)) {
            return false;
        }
        var parts = rel.split("/");
        var root = parts[0];
        var rootKind = _devopsRootKind(root);
        if (rootKind === "creation" && mode !== "creation") {
            return false;
        }
        if (rootKind === "configuration" && mode !== "configuration") {
            return false;
        }
        if (rootKind === "unknown") {
            /* custom user folders: visible in both tool tabs */
        }
        var i;
        for (i = 1; i < parts.length; i++) {
            var sk = _devopsDirSegmentKind(parts[i]);
            if (sk && sk !== mode) {
                return false;
            }
        }
        var leaf = parts[parts.length - 1];
        if (parts.length === 1 && DEVOPS_NEUTRAL_NAMES[leaf]) {
            return true;
        }
        if (_devopsIsTofuFileName(leaf) && mode !== "creation") {
            return false;
        }
        if (_devopsIsAnsibleFileName(leaf) && !_devopsIsAnsibleToolMode(mode)) {
            return false;
        }
        return true;
    }

    function _devopsEntryAllowedInMode(mode, parentRel, entry) {
        mode = _devopsNormalizeMode(mode);
        if (!mode || !entry || !entry.name) {
            return true;
        }
        var parent = _devopsNormRel(parentRel);
        var full = parent ? parent + "/" + entry.name : entry.name;

        if (mode === "security") {
            if (!parent) {
                return entry.name === "Ansible" || !!DEVOPS_NEUTRAL_NAMES[entry.name];
            }
            if (parent === "Ansible") {
                return entry.name === "Security" || !!DEVOPS_NEUTRAL_NAMES[entry.name];
            }
            return _devopsIsSecurityRel(full) || _devopsIsSecurityRel(parent);
        }

        if (mode === "configuration") {
            if (_devopsIsSecurityRel(full) || (parent === "Ansible" && entry.name === "Security")) {
                return false;
            }
        }

        var parts = full.split("/");
        var root = parts[0];
        var rootKind = _devopsRootKind(root);

        if (!parent) {
            if (DEVOPS_NEUTRAL_NAMES[entry.name]) {
                return true;
            }
            if (rootKind === "mixed") {
                return true;
            }
            if (rootKind === "creation") {
                return mode === "creation";
            }
            if (rootKind === "configuration") {
                return mode === "configuration";
            }
            if (entry.type === "file") {
                if (_devopsIsTofuFileName(entry.name)) {
                    return mode === "creation";
                }
                if (_devopsIsAnsibleFileName(entry.name)) {
                    return mode === "configuration";
                }
            }
            return true;
        }

        if (!_devopsPathAllowedInMode(mode, parent)) {
            return false;
        }

        if (parts.length === 2 && rootKind === "mixed") {
            var sk = _devopsDirSegmentKind(entry.name);
            if (sk) {
                return sk === mode;
            }
            if (entry.type === "file") {
                if (DEVOPS_NEUTRAL_NAMES[entry.name]) {
                    return true;
                }
                if (_devopsIsTofuFileName(entry.name)) {
                    return mode === "creation";
                }
                if (_devopsIsAnsibleFileName(entry.name)) {
                    return mode === "configuration";
                }
                /* domain docs / misc: show in both */
                return true;
            }
            /* unknown subdir under mixed domain: show in both */
            return true;
        }

        var leafKind = _devopsDirSegmentKind(entry.name);
        if (leafKind && leafKind !== mode) {
            return false;
        }
        if (entry.type === "file") {
            if (_devopsIsTofuFileName(entry.name) && mode !== "creation") {
                return false;
            }
            if (_devopsIsAnsibleFileName(entry.name) && !_devopsIsAnsibleToolMode(mode)) {
                return false;
            }
        }
        return _devopsPathAllowedInMode(mode, full);
    }

    function _devopsInferModeForPath(relPath) {
        var rel = _devopsNormRel(relPath);
        if (!rel) {
            return "creation";
        }
        if (_devopsIsSecurityRel(rel)) {
            return "security";
        }
        if (_devopsPathAllowedInMode("configuration", rel) && !_devopsPathAllowedInMode("creation", rel)) {
            return "configuration";
        }
        if (_devopsPathAllowedInMode("creation", rel) && !_devopsPathAllowedInMode("configuration", rel)) {
            return "creation";
        }
        var leaf = rel.split("/").pop() || "";
        if (_devopsIsAnsibleFileName(leaf)) {
            return "configuration";
        }
        if (_devopsIsTofuFileName(leaf)) {
            return "creation";
        }
        return "creation";
    }

    function _devopsFilterEntries(mode, parentRel, entries) {
        return (entries || []).filter(function (e) {
            return _devopsEntryAllowedInMode(mode, parentRel, e);
        });
    }

    function _devopsEntryBadgeKind(mode, parentRel, entry) {
        if (!entry || !entry.name) {
            return "";
        }
        mode = _devopsNormalizeMode(mode) || mode;
        var parent = _devopsNormRel(parentRel);
        if (!parent) {
            if (DEVOPS_NEUTRAL_NAMES[entry.name]) {
                return "shared";
            }
            if ((mode === "configuration" || mode === "security") && entry.name === "Ansible") {
                return mode === "security" ? "security" : "ansible";
            }
            if (DEVOPS_MIXED_ROOTS[entry.name]) {
                return mode === "configuration" || mode === "security" ? "ansible" : "tofu";
            }
            if (DEVOPS_CREATION_ROOTS[entry.name] || _devopsIsTofuFileName(entry.name)) {
                return "tofu";
            }
            if (DEVOPS_CONFIGURATION_ROOTS[entry.name] || _devopsIsAnsibleFileName(entry.name)) {
                return "ansible";
            }
            return "shared";
        }
        if (parent === "Ansible" && entry.name === "Security") {
            return "security";
        }
        if (parent === "Ansible" && DEVOPS_CONFIG_CHILD_KIND[entry.name]) {
            return DEVOPS_CONFIG_CHILD_KIND[entry.name];
        }
        if (_devopsIsSecurityRel(parent) || _devopsIsSecurityRel(parent + "/" + entry.name)) {
            return "security";
        }
        if (_devopsDirSegmentKind(entry.name) === "creation" || _devopsIsTofuFileName(entry.name)) {
            return "tofu";
        }
        if (_devopsDirSegmentKind(entry.name) === "configuration" || _devopsIsAnsibleFileName(entry.name)) {
            return "ansible";
        }
        if (DEVOPS_NEUTRAL_NAMES[entry.name]) {
            return "shared";
        }
        if (mode === "security") {
            return "security";
        }
        return mode === "configuration" ? "ansible" : "tofu";
    }

    function _devopsEntryDisplayName(mode, parentRel, entry) {
        var name = entry && entry.name ? String(entry.name) : "";
        var parent = _devopsNormRel(parentRel);
        mode = _devopsNormalizeMode(mode) || mode;
        if (!parent) {
            if (name === "OpenTofu") {
                return "OpenTofu";
            }
            if (name === "Ansible") {
                return mode === "security" ? "Ansible · Security" : "Ansible";
            }
        }
        if (parent === "Ansible" && name === "Security") {
            return "Security · SECops playbooks";
        }
        if (parent === "Ansible" && mode === "configuration") {
            var kind = DEVOPS_CONFIG_CHILD_KIND[name];
            if (kind === "ztp") {
                return name + " · vendor ZTP";
            }
            if (kind === "plc") {
                return name + " · PLC programs";
            }
            if (kind === "api") {
                return name + " · device APIs";
            }
            if (kind === "ansible") {
                if (name === "bare-metal-ztp") {
                    return name + " · recipes / playbooks";
                }
                if (name === "OpenTofu") {
                    return "OpenTofu · paired playbooks";
                }
                if (name === "playbooks") {
                    return "playbooks · shared";
                }
                if (name === "inventory" || name === "inventories") {
                    return name + " · hosts";
                }
                return name;
            }
        }
        return name;
    }

    function _devopsBadgeHtml(kind) {
        if (kind === "tofu") {
            return "<span class=\"devops-iac-badge devops-iac-badge--tofu\">OpenTofu</span>";
        }
        if (kind === "ansible") {
            return "<span class=\"devops-iac-badge devops-iac-badge--ansible\">Ansible</span>";
        }
        if (kind === "security") {
            return "<span class=\"devops-iac-badge devops-iac-badge--security\">Security</span>";
        }
        if (kind === "ztp") {
            return "<span class=\"devops-iac-badge devops-iac-badge--ztp\">ZTP</span>";
        }
        if (kind === "plc") {
            return "<span class=\"devops-iac-badge devops-iac-badge--plc\">PLC</span>";
        }
        if (kind === "api") {
            return "<span class=\"devops-iac-badge devops-iac-badge--api\">API</span>";
        }
        if (kind === "shared") {
            return "<span class=\"devops-iac-badge devops-iac-badge--shared\">Shared</span>";
        }
        return "";
    }
    // --- DEVOPS_IAC_MODE_FILTER_END ---

    function _toolMode() {
        return _devopsNormalizeMode(_structureMode) || "creation";
    }

    function _stockRunCommands() {
        return {
            creation: "tofu version",
            configuration: "ansible-playbook --version",
            security: "ansible-playbook --version"
        };
    }

    function _workdirOptionsForMode(mode) {
        mode = _devopsNormalizeMode(mode);
        if (mode === "security") {
            return [
                { value: "Ansible/Security", label: "Ansible/Security (default)" },
                { value: "Ansible/Security/playbooks", label: "Ansible/Security/playbooks" },
                { value: ".", label: "Workspace root" }
            ];
        }
        if (mode === "configuration") {
            return [
                { value: "Ansible", label: "Ansible (default)" },
                { value: "Ansible/playbooks", label: "Ansible/playbooks" },
                { value: "Ansible/OpenTofu", label: "Ansible/OpenTofu" },
                { value: "Ansible/bare-metal-ztp/playbooks", label: "Ansible/bare-metal-ztp/playbooks" },
                { value: "Ansible/Security & Fire Systems/playbooks", label: "Ansible/Security & Fire Systems/playbooks" },
                { value: "Ansible/SCADA & PLC/playbooks", label: "Ansible/SCADA & PLC/playbooks" },
                { value: ".", label: "Workspace root" }
            ];
        }
        return [
            { value: "OpenTofu", label: "OpenTofu (default)" },
            { value: "OpenTofu/environments/dev", label: "OpenTofu/environments/dev" },
            { value: "OpenTofu/environments/prod", label: "OpenTofu/environments/prod" },
            { value: "OpenTofu/modules", label: "OpenTofu/modules" },
            { value: "OpenTofu/modules/security-integrations", label: "OpenTofu/modules/security-integrations" },
            { value: ".", label: "Workspace root" }
        ];
    }

    function _applyModeChrome() {
        var mode = _toolMode();
        var onFiles = _activeTab === "files";
        var creationTb = el("devopsIacCreationToolbar");
        var configTb = el("devopsIacConfigToolbar");
        var securityTb = el("devopsIacSecurityToolbar");
        var hint = el("devopsIacModeHint");
        var filesHint = el("devopsIacFilesModeHint");
        var runLabel = el("devopsIacRunLabel");
        var pathInput = el("devopsIacCurrentPath");
        var pane = el("devopsIacConsolePane");
        var filesCreation = el("devopsIacFilesModeCreation");
        var filesConfig = el("devopsIacFilesModeConfiguration");
        var filesSecurity = el("devopsIacFilesModeSecurity");
        if (creationTb) {
            creationTb.style.display = !onFiles && mode === "creation" ? "flex" : "none";
        }
        if (configTb) {
            configTb.style.display = !onFiles && mode === "configuration" ? "flex" : "none";
        }
        if (securityTb) {
            securityTb.style.display = !onFiles && mode === "security" ? "flex" : "none";
        }
        if (hint) {
            if (mode === "security") {
                hint.textContent =
                    "Security — SECops Ansible under Ansible/Security/. Prefer running on the controller so vault secrets never leave the site.";
            } else if (mode === "configuration") {
                hint.textContent =
                    "Configuration — Ansible playbooks (IoT, SCADA, Security & Fire, …) plus related config libraries (ZTP, device APIs, OpenPLC). SECops tools live under the Security tab.";
            } else {
                hint.textContent =
                    "Creation — OpenTofu only. Primary stacks live under OpenTofu/ (including modules/security-integrations).";
            }
        }
        if (filesHint) {
            if (mode === "security") {
                filesHint.textContent = "Same folders as Security — Ansible/Security SECops playbooks.";
            } else if (mode === "configuration") {
                filesHint.textContent =
                    "Same folders as Configuration — Ansible playbooks and related config libraries.";
            } else {
                filesHint.textContent = "Same folders as Creation — OpenTofu provisioning under OpenTofu/.";
            }
        }
        if (filesCreation) {
            filesCreation.setAttribute("aria-pressed", mode === "creation" ? "true" : "false");
        }
        if (filesConfig) {
            filesConfig.setAttribute("aria-pressed", mode === "configuration" ? "true" : "false");
        }
        if (filesSecurity) {
            filesSecurity.setAttribute("aria-pressed", mode === "security" ? "true" : "false");
        }
        if (runLabel) {
            runLabel.textContent = _devopsIsAnsibleToolMode(mode) ? "Run (ansible-playbook …)" : "Run (tofu …)";
        }
        if (pathInput) {
            pathInput.placeholder = _devopsIsAnsibleToolMode(mode) ? "path/to/playbook.yml" : "path/to/main.tf";
        }
        if (pane) {
            pane.setAttribute(
                "aria-labelledby",
                mode === "security"
                    ? "devopsIacTabSecurity"
                    : mode === "configuration"
                      ? "devopsIacTabConfiguration"
                      : "devopsIacTabCreation"
            );
        }
        var wd = el("devopsIacWorkdir");
        if (wd && mode) {
            var prev = wd.value;
            var opts = _workdirOptionsForMode(mode);
            wd.innerHTML = "";
            opts.forEach(function (o) {
                var op = document.createElement("option");
                op.value = o.value;
                op.textContent = o.label;
                wd.appendChild(op);
            });
            var keep = opts.some(function (o) {
                return o.value === prev;
            });
            wd.value = keep ? prev : opts[0].value;
        }
        var cmd = el("devopsIacRunCmd");
        var stock = _stockRunCommands();
        if (cmd && mode) {
            var cur = (cmd.value || "").trim();
            if (
                !cur ||
                cur === stock.creation ||
                cur === stock.configuration ||
                cur === stock.security ||
                cur === "tofu version"
            ) {
                cmd.value = stock[mode] || stock.creation;
            }
        }
    }

    function _ensureCwdAllowedForMode() {
        var mode = _toolMode();
        var rel = _relPath();
        if (mode === "security") {
            if (!rel || !_devopsPathAllowedInMode(mode, rel)) {
                _cwd = ["Ansible", "Security"];
                return true;
            }
            return false;
        }
        if (rel && !_devopsPathAllowedInMode(mode, rel)) {
            _cwd = [];
            return true;
        }
        return false;
    }

    function _ensureBrowserPathAllowedForMode() {
        var mode = _toolMode();
        if (mode === "security") {
            if (!_browserPath || !_devopsPathAllowedInMode(mode, _browserPath)) {
                _browserPath = "Ansible/Security";
                _browserSelectedPath = null;
                _browserSelectedType = null;
                return true;
            }
            return false;
        }
        if (_browserPath && !_devopsPathAllowedInMode(mode, _browserPath)) {
            _browserPath = "";
            _browserSelectedPath = null;
            _browserSelectedType = null;
            return true;
        }
        return false;
    }

    function el(id) {
        return document.getElementById(id);
    }

    function _formatInfraBridgeNote(bridge) {
        if (!bridge || typeof bridge !== "object") {
            return "";
        }
        var lines = [];
        var sync = bridge.inventory_sync;
        if (sync && sync.ok) {
            lines.push(
                "--- infra bridge ---",
                "Auto-synced Ansible inventory → " + (sync.path || "ansible/inventory/opentofu_inventory_hosts.json"),
                "hosts: " + (sync.ansible_hosts_written != null ? sync.ansible_hosts_written : "?")
            );
        } else if (sync && sync.error) {
            lines.push("--- infra bridge ---", "Inventory sync failed: " + sync.error);
        }
        var rec = bridge.infra_record;
        if (rec && rec.ok && rec.recorded) {
            lines.push("Recorded " + rec.recorded + " host(s) on map for this change.");
        }
        return lines.length ? "\n" + lines.join("\n") : "";
    }

    function _afterInfraBridgeRun(bridge) {
        if (!bridge) {
            return;
        }
        if (typeof loadHosts === "function") {
            try {
                loadHosts();
            } catch (e) { /* ignore */ }
        }
    }

    var _lastPostedFleetOrgId = null;

    function _syncGlobalOrgScopeAndFleet() {
        try {
            if (_ctx === "org" && _orgId) {
                window.peregrinePageOrgScope = { context: "org", org_id: String(_orgId) };
            } else {
                window.peregrinePageOrgScope = { context: "", org_id: "" };
            }
            var nextOid = _ctx === "org" && _orgId ? String(_orgId) : "";
            if (!window.parent || window.parent === window) {
                return;
            }
            if (_lastPostedFleetOrgId !== null && nextOid === _lastPostedFleetOrgId) {
                return;
            }
            _lastPostedFleetOrgId = nextOid;
            window.parent.postMessage(
                {
                    type: "peregrine-fleet-sync-org-scope",
                    scope: { org_id: _ctx === "org" && _orgId ? String(_orgId) : "" }
                },
                "*"
            );
        } catch (e0) {}
    }

    function _relPath() {
        return _cwd.length ? _cwd.join("/") : "";
    }

    function _queryScope() {
        var p = "context=" + encodeURIComponent(_ctx);
        if (_ctx === "org" && _orgId) {
            p += "&org_id=" + encodeURIComponent(_orgId);
        }
        return p;
    }

    function _bodyScope() {
        var b = { context: _ctx };
        if (_ctx === "org" && _orgId) {
            b.org_id = _orgId;
        }
        return b;
    }

    function _stripUrlParams(keys) {
        try {
            var u = new URL(window.location.href);
            var changed = false;
            (keys || []).forEach(function (k) {
                if (u.searchParams.has(k)) {
                    u.searchParams.delete(k);
                    changed = true;
                }
            });
            if (changed) {
                var next = u.pathname + (u.search ? u.search : "") + (u.hash || "");
                window.history.replaceState(null, "", next);
            }
        } catch (e) {}
    }

    function _readWorkspaceUrlIntent() {
        var out = { context: "", orgId: "", openPath: "", stripAutodev: false };
        try {
            var p = new URLSearchParams(window.location.search || "");
            out.stripAutodev = p.get("devops") === "1" || p.get("iac") === "1";
            var ctx = (p.get("context") || p.get("scope") || "").trim().toLowerCase();
            out.context = ctx;
            out.orgId = (p.get("org_id") || p.get("organization_id") || "").trim();
            out.openPath = (p.get("open_file") || p.get("file") || p.get("path") || "").trim();
        } catch (e) {}
        return out;
    }

    function _escHtml(s) {
        return String(s)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    /** Same-origin fetch with small retries (transient NetworkError / connection resets). */
    function _controllerRouteUrl(url) {
        var raw = String(url || "");
        if (!raw || raw.indexOf("/api/") !== 0) return raw;
        var selector = "";
        try {
            if (typeof window.peregrineSelectedControllerBranch === "function") {
                selector = String(window.peregrineSelectedControllerBranch() || "").trim();
            }
        } catch (e) {}
        if (!selector) return raw;
        var sep = raw.indexOf("?") >= 0 ? "&" : "?";
        return raw + sep + "controller=" + encodeURIComponent(selector);
    }

    function _fetchWithRetry(url, init) {
        var base = Object.assign({ credentials: "same-origin", cache: "no-store" }, init || {});
        var routedUrl = _controllerRouteUrl(url);
        var selector = "";
        try {
            if (typeof window.peregrineSelectedControllerBranch === "function") {
                selector = String(window.peregrineSelectedControllerBranch() || "").trim();
            }
        } catch (e0) {}
        if (selector) {
            var h = Object.assign({}, base.headers || {});
            if (!h["X-Hayabusa-Controller"]) {
                h["X-Hayabusa-Controller"] = selector;
            }
            base.headers = h;
        }
        function attempt(left) {
            return fetch(routedUrl, base).catch(function (err) {
                if (left <= 0) {
                    throw err;
                }
                return new Promise(function (res) {
                    setTimeout(res, 350);
                }).then(function () {
                    return attempt(left - 1);
                });
            });
        }
        return attempt(2);
    }

    function _fetchJson(url, init) {
        return _fetchWithRetry(url, init).then(function (r) {
            return r.text().then(function (txt) {
                var j = null;
                try {
                    j = txt ? JSON.parse(txt) : null;
                } catch (e) {
                    j = null;
                }
                if (!j || typeof j !== "object") {
                    throw new Error("Invalid JSON response from server (HTTP " + r.status + ")");
                }
                return { status: r.status, okHttp: r.ok, data: j };
            });
        });
    }

    function _joinRel(parent, name) {
        parent = String(parent || "").replace(/\\/g, "/").replace(/^\/+|\/+$/g, "");
        name = String(name || "").replace(/\\/g, "/").replace(/^\/+|\/+$/g, "");
        if (!parent) {
            return name;
        }
        if (!name) {
            return parent;
        }
        return parent + "/" + name;
    }

    function _formatBytes(n) {
        n = Number(n || 0);
        if (!isFinite(n) || n < 0) {
            return "";
        }
        if (n < 1024) {
            return n + " B";
        }
        if (n < 1024 * 1024) {
            return (n / 1024).toFixed(1).replace(/\.0$/, "") + " KB";
        }
        return (n / (1024 * 1024)).toFixed(1).replace(/\.0$/, "") + " MB";
    }

    function _formatMtime(ts) {
        if (!ts) {
            return "";
        }
        try {
            return new Date(Number(ts) * 1000).toLocaleString();
        } catch (e) {
            return "";
        }
    }

    function _fileTypeLabel(entry) {
        if (!entry) {
            return "";
        }
        if (entry.type === "dir") {
            var seg = _devopsDirSegmentKind(entry.name);
            if (seg === "creation") {
                return "OpenTofu folder";
            }
            if (seg === "configuration") {
                return "Ansible folder";
            }
            return "Folder";
        }
        if (entry.type === "blocked") {
            return "Blocked";
        }
        var name = String(entry.name || "");
        if (_devopsIsTofuFileName(name)) {
            return "OpenTofu";
        }
        if (_devopsIsAnsibleFileName(name)) {
            return "Ansible";
        }
        var i = name.lastIndexOf(".");
        if (i >= 0 && i < name.length - 1) {
            return name.slice(i + 1).toUpperCase() + " File";
        }
        return "File";
    }

    function _transferMessage(msg) {
        var box = el("devopsIacFileBrowserTransferBody");
        if (box) {
            box.textContent = msg || "Idle.";
        }
    }

    function _movePathToFolder(srcPath, destFolder) {
        if (!_canWrite) {
            alert("Read-only workspace: cannot move files or folders.");
            return Promise.resolve();
        }
        srcPath = String(srcPath || "").replace(/\\/g, "/").replace(/^\/+|\/+$/g, "");
        destFolder = String(destFolder || "").replace(/\\/g, "/").replace(/^\/+|\/+$/g, "");
        if (!srcPath) {
            return Promise.resolve();
        }
        var info = _parentAndName(srcPath);
        var dst = _joinRel(destFolder, info.name);
        if (!info.name || dst === srcPath) {
            _transferMessage("Move skipped: source and target are the same.");
            return Promise.resolve();
        }
        var payload = { from: srcPath, to: dst };
        Object.assign(payload, _bodyScope());
        _setStatus("Moving...");
        _transferMessage("Moving " + srcPath + " -> " + (destFolder || "/"));
        return _fetchJson("/api/devops-iac/mv", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        })
            .then(function (pack) {
                if (!pack.data.ok) {
                    throw new Error(pack.data.error || "Move failed");
                }
                _setStatus("Moved " + srcPath);
                _transferMessage("Successful transfer: " + srcPath + " -> " + (pack.data.to || dst));
                if (_openFile && _openFile === srcPath) {
                    _openFile = pack.data.to || dst;
                    if (el("devopsIacCurrentPath")) {
                        el("devopsIacCurrentPath").value = _openFile;
                    }
                }
                if (_browserSelectedPath === srcPath) {
                    _browserSetSelected(pack.data.to || dst, _browserSelectedType || "file");
                }
                return Promise.all([refreshTree(), fileBrowserRefresh()]);
            })
            .catch(function (e) {
                var msg = e && e.message ? e.message : "Move error";
                _setStatus(msg);
                _transferMessage("Failed transfer: " + msg);
            });
    }

    function _getAllSaved() {
        try {
            return JSON.parse(localStorage.getItem(_LS_KEY) || "[]");
        } catch (e) {
            return [];
        }
    }

    function _setAllSaved(arr) {
        try {
            localStorage.setItem(_LS_KEY, JSON.stringify(arr));
        } catch (e) {
            _setStatus("Could not store saved commands: " + (e.message || e));
        }
    }

    function _savedForContext() {
        var all = _getAllSaved();
        return all.filter(function (x) {
            return x && x.context === _ctx && String(x.org_id || "") === String(_orgId || "");
        });
    }

    function _refreshSavedCommandsSelect() {
        var sel = el("devopsIacSavedCmd");
        if (!sel) {
            return;
        }
        var list = _savedForContext();
        var keep = sel.value;
        sel.innerHTML = "<option value=\"\">— choose saved, or type below —</option>";
        list.forEach(function (x) {
            if (!x || !x.id) {
                return;
            }
            var o = document.createElement("option");
            o.value = x.id;
            o.textContent = x.name && String(x.name).trim() ? String(x.name) : x.command;
            o.title = x.command;
            sel.appendChild(o);
        });
        if (keep) {
            var found = list.some(function (x) {
                return String(x.id) === String(keep);
            });
            if (found) {
                sel.value = keep;
            }
        }
    }

    function _setStatus(msg) {
        var s = el("devopsIacStatus");
        if (s) {
            s.textContent = msg || "";
        }
    }

    function _setReadonlyBanner() {
        var b = el("devopsIacReadonly");
        if (!b) {
            return;
        }
        if (_globalReadOnly) {
            b.style.display = "block";
            b.textContent =
                "Read-only: Global Visitor (or equivalent) cannot edit infrastructure or run commands anywhere.";
        } else if (_mustUseController && _canRunViaController) {
            b.style.display = "block";
            b.textContent =
                "Controller mode: Run sends the playbook (secret names only) to your controller. " +
                "An admin on the LAN must approve before secrets are filled and Ansible/OpenTofu execute.";
        } else if (_mustUseController && !_canRunViaController) {
            b.style.display = "block";
            b.textContent =
                "Controller mode: direct Hayabusa runs are blocked. Connect a controller and ensure you have run permission, or grant act_without_controller.";
        } else if (_ctx === "org" && !_canWrite && _canApprove) {
            b.style.display = "block";
            b.textContent =
                "Approve-only: you can approve queued runs but not edit this organization workspace.";
        } else if (_ctx === "org" && !_canWrite && !_canEnqueue) {
            b.style.display = "block";
            b.textContent =
                "Read-only: you can view this organization workspace but your role does not allow edits or run.";
        } else if (_ctx === "org" && _canWrite && !_canEnqueue && !_canApprove) {
            b.style.display = "block";
            b.textContent =
                "Edit-only: you can change IaC files; enqueueing runs requires enqueue_devops_runs.";
        } else if (_ctx === "org" && _canEnqueue && !_canApprove) {
            b.style.display = "block";
            b.textContent =
                "Operator: you can edit and enqueue runs, but a separate DevOps Approver must approve them.";
        } else {
            b.style.display = "none";
            b.textContent = "";
        }
    }

    function _hideContextMenu() {
        var m = el("devopsIacTreeContextMenu");
        if (m) {
            m.style.display = "none";
        }
        _ctxMenuPath = null;
        _ctxMenuKind = null;
    }

    function _onContextMenu(ev) {
        var t = ev.target;
        if (!t) {
            return;
        }
        var a = t.closest && t.closest("a");
        if (!a) {
            return;
        }
        if (!a.classList.contains("devops-iac-cd") && !a.classList.contains("devops-iac-file")) {
            return;
        }
        if (a.getAttribute("data-cd") === "..") {
            return;
        }
        var p = a.getAttribute("data-tree-path");
        if (!p) {
            return;
        }
        var kind = a.classList.contains("devops-iac-cd") ? "dir" : "file";
        try {
            p = decodeURIComponent(p);
        } catch (e) {
            return;
        }
        if (_ctx === "org" && !_canWrite) {
            ev.preventDefault();
            _setStatus("Read-only: cannot rename in this org workspace.");
            return;
        }
        ev.preventDefault();
        _ctxMenuPath = p;
        _ctxMenuKind = kind;
        var menu = el("devopsIacTreeContextMenu");
        if (!menu) {
            return;
        }
        menu.style.display = "block";
        menu.style.left = ev.clientX + "px";
        menu.style.top = ev.clientY + "px";
    }

    function _initTreeContextMenu() {
        var box = el("devopsIacFileTree");
        if (!box || box.getAttribute("data-ctx-ok")) {
            return;
        }
        box.setAttribute("data-ctx-ok", "1");
        box.addEventListener("contextmenu", _onContextMenu);
        if (!_docClickForCtxBound) {
            _docClickForCtxBound = true;
            document.addEventListener("click", _hideContextMenu);
        }
        var btn = el("devopsIacCtxRename");
        if (btn) {
            btn.addEventListener("click", function (ev) {
                ev.stopPropagation();
                if (!_ctxMenuPath) {
                    _hideContextMenu();
                    return;
                }
                devopsIacRenamePath(_ctxMenuPath, _ctxMenuKind);
                _hideContextMenu();
            });
        }
        var delBtn = el("devopsIacCtxDelete");
        if (delBtn) {
            delBtn.addEventListener("click", function (ev) {
                ev.stopPropagation();
                if (!_ctxMenuPath) {
                    _hideContextMenu();
                    return;
                }
                devopsIacDeletePath(_ctxMenuPath);
                _hideContextMenu();
            });
        }
    }

    function _onContextChange() {
        var s = el("devopsIacContext");
        var orgWrap = el("devopsIacOrgWrap");
        if (!s) {
            return;
        }
        _ctx = s.value === "org" ? "org" : "user";
        if (_ctx !== "org") {
            _orgId = null;
        }
        if (orgWrap) {
            orgWrap.style.display = _ctx === "org" ? "inline-flex" : "none";
        }
        if (_ctx === "org") {
            var osel = el("devopsIacOrgSelect");
            if (osel && osel.value) {
                _orgId = osel.value;
            } else if (osel && osel.options.length) {
                _orgId = osel.options[0].value;
                osel.value = _orgId;
            }
        }
        _resetNavForNewRoot();
        _syncGlobalOrgScopeAndFleet();
    }

    function _resetNavForNewRoot() {
        _cwd = [];
        _openFile = null;
        _browserPath = "";
        _browserSelectedPath = null;
        _browserSelectedType = null;
        _browserEntries = [];
        _browserRootEntries = [];
        if (el("devopsIacCurrentPath")) {
            el("devopsIacCurrentPath").value = "";
        }
        if (el("devopsIacEditor")) {
            el("devopsIacEditor").value = "";
        }
        if (el("devopsIacRunOutput")) {
            el("devopsIacRunOutput").textContent = "";
        }
        if (el("devopsIacFileBrowserSelectedPath")) {
            el("devopsIacFileBrowserSelectedPath").value = "";
        }
        if (el("devopsIacFileBrowserEditor")) {
            el("devopsIacFileBrowserEditor").value = "";
        }
    }

    function _refreshTofuStateSummary() {
        var span = el("devopsIacTofuState");
        if (!span) {
            return Promise.resolve();
        }
        return fetch("/api/devops-iac/opentofu-state-summary?" + _queryScope(), { credentials: "same-origin" })
            .then(function (r) {
                return r.json();
            })
            .then(function (j) {
                if (!j || !j.ok) {
                    span.textContent = "OpenTofu state: " + (j && j.error ? String(j.error) : "unavailable");
                    return;
                }
                if (!j.found) {
                    span.textContent = "OpenTofu state: none under OpenTofu";
                    return;
                }
                var rel = j.path || "terraform.tfstate";
                var n = j.resource_count != null ? String(j.resource_count) : "?";
                var line = "OpenTofu state: " + rel + " · " + n + " resources";
                if (j.catalog_snapshot && j.catalog_snapshot.catalog_updated_at) {
                    line += " · catalog " + String(j.catalog_snapshot.catalog_updated_at).replace("T", " ").replace("Z", " UTC");
                }
                span.textContent = line;
            })
            .catch(function () {
                span.textContent = "OpenTofu state: (network error)";
            });
    }

    function _setWhoami() {
        return fetch("/api/devops-iac/whoami?" + _queryScope(), { credentials: "same-origin" })
            .then(function (r) {
                return r.json();
            })
            .then(function (j) {
                if (!j || !j.ok) {
                    if (j && j.error) {
                        _setStatus(j.error);
                    }
                    return Promise.resolve();
                }
                _canWrite = j.can_write !== false;
                _canEnqueue = j.can_enqueue !== false;
                if (typeof j.can_enqueue === "undefined") {
                    _canEnqueue = _canWrite;
                }
                _canApprove = j.can_approve === true;
                _canRun = j.can_run !== false;
                if (typeof j.can_run === "undefined") {
                    _canRun = _canWrite;
                }
                _canRunViaController = j.can_run_via_controller === true;
                _mustUseController = !!(j.execution && j.execution.must_use_controller);
                if (_mustUseController && _canRunViaController) {
                    _canRun = true;
                }
                _globalReadOnly = j.global_read_only === true;
                if (j.context) {
                    _ctx = j.context;
                }
                if (j.org_id) {
                    _orgId = String(j.org_id);
                }
                var csel = el("devopsIacContext");
                if (csel) {
                    csel.value = _ctx === "org" ? "org" : "user";
                }
                var osel = el("devopsIacOrgSelect");
                if (osel && Array.isArray(j.organizations)) {
                    osel.innerHTML = "";
                    j.organizations.forEach(function (o) {
                        if (!o || o.id == null) {
                            return;
                        }
                        var opt = document.createElement("option");
                        opt.value = String(o.id);
                        opt.textContent = o.name != null ? String(o.name) : String(o.id);
                        osel.appendChild(opt);
                    });
                    if (_orgId) {
                        osel.value = _orgId;
                    } else if (osel.options.length) {
                        _orgId = osel.options[0].value;
                    }
                }
                var owrap = el("devopsIacOrgWrap");
                if (owrap) {
                    owrap.style.display = _ctx === "org" ? "inline-flex" : "none";
                }
                var w = el("devopsIacWhoami");
                if (w && j) {
                    var label =
                        j.context === "org"
                            ? "Org: " + (j.org_id || "—") + "  ·  " + (j.tofu_project || "OpenTofu")
                            : "User: " + (j.user_key || "—") + "  ·  " + (j.tofu_project || "OpenTofu");
                    w.textContent = label;
                    w.title = j.workspace || "";
                }
                _setReadonlyBanner();
                _refreshSavedCommandsSelect();
                _syncGlobalOrgScopeAndFleet();
                return Promise.all([_refreshTofuStateSummary(), _refreshSshKeyStatus()]);
            })
            .catch(function () {
                var w0 = el("devopsIacWhoami");
                if (w0) {
                    w0.textContent = "";
                }
            });
    }

    function _refreshSshKeyStatus() {
        var span = el("devopsIacSshStatus");
        if (!span) {
            return Promise.resolve();
        }
        span.textContent = "SSH keys: …";
        return fetch("/api/user-ssh-keys", { credentials: "same-origin" })
            .then(function (r) {
                return r.json();
            })
            .then(function (j) {
                if (!j || !j.ok) {
                    span.textContent = "SSH keys: (unavailable)";
                    return;
                }
                var p = j.personal && j.personal.configured ? "personal ✓" : "personal —";
                if (_ctx === "org" && _orgId) {
                    var row = (j.orgs || []).filter(function (x) {
                        return x && String(x.id) === String(_orgId);
                    })[0];
                    var o = row && row.configured ? "member key ✓" : "member key —";
                    span.textContent = "SSH keys: " + p + " · this org: " + o;
                } else {
                    span.textContent = "SSH keys: " + p + " · ansible-playbook uses personal key here";
                }
            })
            .catch(function () {
                span.textContent = "SSH keys: (error)";
            });
    }

    function refreshTree() {
        var rel = _relPath();
        var u = "/api/devops-iac/ls?" + _queryScope() + (rel ? "&path=" + encodeURIComponent(rel) : "");
        var box = el("devopsIacFileTree");
        _setStatus("Loading…");
        return _fetchWithRetry(u, {})
            .then(function (r) {
                return r.text().then(function (txt) {
                    var j = null;
                    try {
                        j = txt ? JSON.parse(txt) : null;
                    } catch (e1) {
                        j = null;
                    }
                    return { okHttp: r.ok, status: r.status, j: j, raw: txt };
                });
            })
            .then(function (pack) {
                if (!pack.j || typeof pack.j !== "object") {
                    var snip = (pack.raw && String(pack.raw).slice(0, 200)) || "";
                    _setStatus("List failed: invalid response (HTTP " + pack.status + ")");
                    if (box) {
                        box.innerHTML =
                            "<p style=\"color:#f88;font-size:12px;margin:0;line-height:1.45;\">Could not parse <code>/api/devops-iac/ls</code> response. HTTP " +
                            pack.status +
                            ". Check the Network tab.</p>" +
                            (snip ? "<pre style=\"font-size:10px;color:#94a3b8;white-space:pre-wrap;word-break:break-all;\">" + _escHtml(snip) + "</pre>" : "");
                    }
                    return;
                }
                var j = pack.j;
                if (!j.ok) {
                    _setStatus(j.error || "List failed");
                    if (box) {
                        box.innerHTML =
                            "<p style=\"color:#f88;font-size:12px;margin:0;line-height:1.45;\">" +
                            _escHtml(j.error || "List failed") +
                            "</p><p style=\"color:#94a3b8;font-size:11px;margin:8px 0 0;\">If you use an <strong>organization</strong> workspace, confirm you are a member and pick the org in the toolbar.</p>";
                    }
                    return;
                }
                if (j.can_write === false) {
                    _canWrite = false;
                } else {
                    _canWrite = true;
                }
                _setReadonlyBanner();
                _setStatus("");
                var mode = _toolMode();
                renderTree(_devopsFilterEntries(mode, rel, j.entries || []), rel);
                _initTreeContextMenu();
            })
            .catch(function (e) {
                var msg = e && e.message ? e.message : "Network error";
                _setStatus(msg);
                if (box) {
                    box.innerHTML =
                        "<p style=\"color:#f88;font-size:12px;margin:0;\">" +
                        _escHtml(msg) +
                        "</p><p style=\"color:#94a3b8;font-size:11px;margin:8px 0 0;\">Retried automatically. Check connectivity to Peregrine, then use <strong>Refresh tree</strong> in the workspace header.</p>";
                }
            });
    }

    function renderTree(entries, rel) {
        var box = el("devopsIacFileTree");
        if (!box) {
            return;
        }
        var mode = _toolMode();
        var parts = [
            "<div class=\"devops-iac-tree__path\" style=\"font-size:10px;color:#6a7a80;margin-bottom:6px;word-break:break-all;\">",
            mode === "security" ? "Security · " : mode === "configuration" ? "Configuration · " : "Creation · ",
            (rel || "/") || "root",
            "</div>",
            "<ul style=\"list-style:none;margin:0;padding:0;\">"
        ];
        if (rel) {
            parts.push(
                "<li><a href=\"#\" class=\"devops-iac-cd\" data-cd=\"..\" style=\"color:#5d93a2;font-size:12px;\">..</a></li>"
            );
        }
        (entries || []).forEach(function (e) {
            var fullP = (rel ? rel + "/" : "") + e.name;
            var encP = encodeURIComponent(fullP);
            var label = _devopsEntryDisplayName(mode, rel, e);
            var badge = _devopsBadgeHtml(_devopsEntryBadgeKind(mode, rel, e));
            if (e.type === "dir") {
                parts.push(
                    "<li><a href=\"#\" class=\"devops-iac-cd\" data-cd=\"",
                    e.name,
                    "\" data-tree-path=\"",
                    encP,
                    "\" style=\"color:#5d93a2;font-size:12px;\">",
                    _escHtml(label),
                    " /",
                    badge,
                    "</a></li>"
                );
            } else {
                var rp = (rel ? rel + "/" : "") + e.name;
                parts.push(
                    "<li><a href=\"#\" class=\"devops-iac-file\" data-file=\"",
                    rp,
                    "\" data-tree-path=\"",
                    encP,
                    "\" style=\"color:#aaa;font-size:12px;\">",
                    _escHtml(label),
                    badge,
                    "</a></li>"
                );
            }
        });
        var nEnt = (entries || []).length;
        if (!nEnt && !rel) {
            var emptyHint =
                mode === "security"
                    ? "No Security folders here yet. Look under <code>Ansible/Security/</code> for SECops playbooks."
                    : mode === "configuration"
                      ? "No Ansible folders here yet. Look under <code>Ansible/</code> for playbooks, inventories, and domain labs."
                      : "No OpenTofu folders here yet. Look for <code>OpenTofu/</code> or a domain’s <code>opentofu/</code>.";
            parts.push(
                "<li style=\"color:#8ea1b1;font-size:11px;padding:6px 0;line-height:1.45;\">",
                emptyHint,
                " Click <strong>↻ Tree</strong> if the workspace is still seeding.",
                "</li>"
            );
        } else if (!nEnt) {
            parts.push(
                "<li style=\"color:#8ea1b1;font-size:11px;padding:4px 0;\">",
                mode === "security"
                    ? "(no Security items in this folder)"
                    : mode === "configuration"
                      ? "(no Ansible items in this folder)"
                      : "(no OpenTofu items in this folder)",
                "</li>"
            );
        }
        parts.push("</ul>");
        box.innerHTML = parts.join("");

        box.querySelectorAll(".devops-iac-cd").forEach(function (a) {
            a.onclick = function (ev) {
                ev.preventDefault();
                var t = a.getAttribute("data-cd");
                if (t === "..") {
                    _cwd.pop();
                } else {
                    _cwd.push(t);
                }
                refreshTree();
            };
        });
        box.querySelectorAll(".devops-iac-file").forEach(function (a) {
            a.onclick = function (ev) {
                ev.preventDefault();
                var f = a.getAttribute("data-file");
                openFile(f);
            };
        });
    }

    function _browserListUrl(rel) {
        return "/api/devops-iac/ls?" + _queryScope() + (rel ? "&path=" + encodeURIComponent(rel) : "");
    }

    function _browserSetSelected(path, typ) {
        _browserSelectedPath = path || null;
        _browserSelectedType = typ || null;
        var input = el("devopsIacFileBrowserSelectedPath");
        if (input) {
            input.value = _browserSelectedPath || "";
        }
        var list = el("devopsIacFileBrowserList");
        if (list) {
            list.querySelectorAll(".devops-iac-file-row").forEach(function (row) {
                var rowPath = row.getAttribute("data-path") || "";
                try {
                    rowPath = decodeURIComponent(rowPath);
                } catch (e) {}
                row.classList.toggle("is-selected", rowPath === String(_browserSelectedPath || ""));
            });
        }
    }

    function _browserRenderRootTree() {
        var box = el("devopsIacFileBrowserTree");
        if (!box) {
            return;
        }
        var mode = _toolMode();
        var roots = _devopsFilterEntries(mode, "", _browserRootEntries || []);
        var parts = [
            "<button type=\"button\" class=\"devops-iac-file-tree-button\" data-path=\"\">[-] / ",
            mode === "security" ? "Security root" : mode === "configuration" ? "Configuration root" : "Creation root",
            "</button>"
        ];
        roots.forEach(function (e) {
            if (!e || e.type !== "dir") {
                return;
            }
            var p = e.name;
            var label = _devopsEntryDisplayName(mode, "", e);
            parts.push(
                "<button type=\"button\" class=\"devops-iac-file-tree-button\" data-path=\"",
                encodeURIComponent(p),
                "\">",
                "[+] ",
                _escHtml(label),
                "/",
                _devopsBadgeHtml(_devopsEntryBadgeKind(mode, "", e)),
                "</button>"
            );
        });
        if (!roots.length) {
            parts.push(
                "<div style=\"padding:8px 4px;color:#64748b;font-size:11px;line-height:1.4;\">",
                mode === "configuration"
                    ? "No Ansible folders in this structure."
                    : "No OpenTofu folders in this structure.",
                "</div>"
            );
        }
        box.innerHTML = parts.join("");
        box.querySelectorAll("button[data-path]").forEach(function (b) {
            b.onclick = function () {
                var p = b.getAttribute("data-path") || "";
                try {
                    p = decodeURIComponent(p);
                } catch (e) {
                    p = "";
                }
                fileBrowserLoad(p);
            };
            b.ondragover = function (ev) {
                if (_canHandleDrop(ev)) {
                    ev.preventDefault();
                    b.classList.add("is-drag-over");
                }
            };
            b.ondragleave = function () {
                b.classList.remove("is-drag-over");
            };
            b.ondrop = function (ev) {
                b.classList.remove("is-drag-over");
                _handleDrop(ev, p);
            };
        });
    }

    function _browserRenderList() {
        var pathEl = el("devopsIacFileBrowserPath");
        var list = el("devopsIacFileBrowserList");
        var mode = _toolMode();
        if (pathEl) {
            var shownPath = "/" + (_browserPath || "");
            if ("value" in pathEl) {
                pathEl.value = shownPath;
            } else {
                pathEl.textContent = shownPath;
            }
        }
        if (!list) {
            return;
        }
        var entries = _devopsFilterEntries(mode, _browserPath, _browserEntries || []).slice().sort(function (a, b) {
            if (a.type === "dir" && b.type !== "dir") return -1;
            if (a.type !== "dir" && b.type === "dir") return 1;
            return String(a.name || "").localeCompare(String(b.name || ""));
        });
        var parts = [];
        if (_browserPath) {
            parts.push(
                "<div class=\"devops-iac-file-row\" data-kind=\"dir\" data-path=\"..\">",
                "<strong>..</strong>",
                "<span class=\"devops-iac-file-row__meta\"></span>",
                "<span class=\"devops-iac-file-row__meta\">Up</span>",
                "<span class=\"devops-iac-file-row__meta\"></span>",
                "</div>"
            );
        }
        if (!entries.length) {
            parts.push(
                "<div style=\"padding:18px;color:#8ea1b1;font-size:12px;line-height:1.45;\">",
                _browserPath
                    ? mode === "configuration"
                        ? "No Ansible items in this folder for the Configuration structure."
                        : "No OpenTofu items in this folder for the Creation structure."
                    : mode === "configuration"
                      ? "No Ansible folders at the Configuration root."
                      : "No OpenTofu folders at the Creation root.",
                "</div>"
            );
        }
        entries.forEach(function (e) {
            if (!e || !e.name) {
                return;
            }
            var typ = e.type || "file";
            var full = _joinRel(_browserPath, e.name);
            var icon = typ === "dir" ? "folder" : typ === "blocked" ? "blocked" : "file";
            var size = typ === "dir" ? "" : _formatBytes(e.size);
            var label = _devopsEntryDisplayName(mode, _browserPath, e);
            var badge = _devopsBadgeHtml(_devopsEntryBadgeKind(mode, _browserPath, e));
            parts.push(
                "<div class=\"devops-iac-file-row\" data-kind=\"",
                _escHtml(typ),
                "\" data-path=\"",
                encodeURIComponent(full),
                "\" draggable=\"true\">",
                "<strong>",
                icon === "folder" ? "[+] " : icon === "blocked" ? "[blocked] " : "",
                _escHtml(label),
                typ === "dir" ? "/" : "",
                badge,
                "</strong>",
                "<span class=\"devops-iac-file-row__meta\">",
                _escHtml(size),
                "</span>",
                "<span class=\"devops-iac-file-row__meta\">",
                _escHtml(_fileTypeLabel(e)),
                "</span>",
                "<span class=\"devops-iac-file-row__meta\">",
                _escHtml(_formatMtime(e.mtime)),
                "</span>",
                "</div>"
            );
        });
        list.innerHTML = parts.join("");
        list.querySelectorAll(".devops-iac-file-row").forEach(function (row) {
            row.ondragstart = function (ev) {
                var rawPath = row.getAttribute("data-path") || "";
                if (rawPath === "..") {
                    ev.preventDefault();
                    return;
                }
                var path = rawPath;
                try {
                    path = decodeURIComponent(rawPath);
                } catch (e) {}
                ev.dataTransfer.effectAllowed = "move";
                ev.dataTransfer.setData("text/plain", path);
                ev.dataTransfer.setData("application/x-peregrine-iac-path", path);
                ev.dataTransfer.setData("application/x-peregrine-iac-kind", row.getAttribute("data-kind") || "file");
            };
            row.ondragover = function (ev) {
                var kind = row.getAttribute("data-kind") || "file";
                if (kind === "dir" && _canHandleDrop(ev)) {
                    ev.preventDefault();
                    row.classList.add("is-drag-over");
                }
            };
            row.ondragleave = function () {
                row.classList.remove("is-drag-over");
            };
            row.ondrop = function (ev) {
                row.classList.remove("is-drag-over");
                var kind = row.getAttribute("data-kind") || "file";
                if (kind !== "dir") {
                    return;
                }
                var rawPath = row.getAttribute("data-path") || "";
                var path = rawPath;
                try {
                    path = decodeURIComponent(rawPath);
                } catch (e) {}
                _handleDrop(ev, path === ".." ? "" : path);
            };
            row.onclick = function () {
                var rawPath = row.getAttribute("data-path") || "";
                var kind = row.getAttribute("data-kind") || "file";
                var path = rawPath;
                try {
                    path = decodeURIComponent(rawPath);
                } catch (e) {}
                if (path === "..") {
                    fileBrowserUp();
                    return;
                }
                if (kind === "dir") {
                    fileBrowserLoad(path);
                    return;
                }
                if (kind === "blocked" || kind === "unknown") {
                    _setStatus("This path is blocked by workspace containment checks.");
                    return;
                }
                _browserSetSelected(path, kind);
                fileBrowserOpen(path);
            };
        });
        _browserSetSelected(_browserSelectedPath, _browserSelectedType);
    }

    function fileBrowserLoad(path) {
        var next = String(path || "").replace(/\\/g, "/").replace(/^\/+|\/+$/g, "");
        if (next && !_devopsPathAllowedInMode(_toolMode(), next)) {
            _setStatus("That folder is outside the current Creation/Configuration structure.");
            next = "";
        }
        _browserPath = next;
        _setStatus("Loading files…");
        return _fetchJson(_browserListUrl(_browserPath), {})
            .then(function (pack) {
                var j = pack.data;
                if (!j.ok) {
                    throw new Error(j.error || "List failed");
                }
                _canWrite = j.can_write !== false;
                _browserEntries = j.entries || [];
                _setReadonlyBanner();
                _browserRenderList();
                _setStatus("");
            })
            .catch(function (e) {
                var msg = e && e.message ? e.message : "File browser error";
                _setStatus(msg);
                var list = el("devopsIacFileBrowserList");
                if (list) {
                    list.innerHTML = "<div style=\"padding:14px;color:#fca5a5;font-size:12px;\">" + _escHtml(msg) + "</div>";
                }
            });
    }

    function fileBrowserRefresh() {
        var rootReq = _fetchJson(_browserListUrl(""), {})
            .then(function (pack) {
                if (pack.data && pack.data.ok) {
                    _browserRootEntries = pack.data.entries || [];
                    _browserRenderRootTree();
                }
            })
            .catch(function () {});
        _initFileBrowserDnd();
        return Promise.all([rootReq, fileBrowserLoad(_browserPath)]).then(function () {});
    }

    function _canHandleDrop(ev) {
        if (!ev || !ev.dataTransfer) {
            return false;
        }
        var types = Array.prototype.slice.call(ev.dataTransfer.types || []);
        return types.indexOf("application/x-peregrine-iac-path") >= 0 || types.indexOf("Files") >= 0;
    }

    function _handleDrop(ev, destFolder) {
        if (!ev || !ev.dataTransfer) {
            return;
        }
        ev.preventDefault();
        ev.stopPropagation();
        var browser = document.querySelector(".devops-iac-file-browser");
        if (browser) {
            browser.classList.remove("is-drop-target");
        }
        var internalPath = ev.dataTransfer.getData("application/x-peregrine-iac-path");
        if (internalPath) {
            _movePathToFolder(internalPath, destFolder || "");
            return;
        }
        if (ev.dataTransfer.files && ev.dataTransfer.files.length) {
            _uploadDroppedItems(ev.dataTransfer, destFolder || _browserPath || "");
        }
    }

    function _readAllDirectoryEntries(reader) {
        var out = [];
        function nextBatch(resolve, reject) {
            reader.readEntries(
                function (batch) {
                    if (!batch || !batch.length) {
                        resolve(out);
                        return;
                    }
                    out = out.concat(Array.prototype.slice.call(batch));
                    nextBatch(resolve, reject);
                },
                reject
            );
        }
        return new Promise(nextBatch);
    }

    function _walkDroppedEntry(entry, prefix) {
        prefix = prefix || "";
        if (!entry) {
            return Promise.resolve([]);
        }
        if (entry.isFile) {
            return new Promise(function (resolve, reject) {
                entry.file(
                    function (file) {
                        resolve([{ file: file, path: prefix + file.name }]);
                    },
                    reject
                );
            });
        }
        if (entry.isDirectory) {
            return _readAllDirectoryEntries(entry.createReader()).then(function (children) {
                return Promise.all(
                    children.map(function (child) {
                        return _walkDroppedEntry(child, prefix + entry.name + "/");
                    })
                ).then(function (lists) {
                    return Array.prototype.concat.apply([], lists);
                });
            });
        }
        return Promise.resolve([]);
    }

    function _collectDroppedFiles(dt) {
        var items = dt && dt.items ? Array.prototype.slice.call(dt.items) : [];
        var walkers = [];
        if (items.length && items[0] && typeof items[0].webkitGetAsEntry === "function") {
            items.forEach(function (item) {
                var entry = item.webkitGetAsEntry && item.webkitGetAsEntry();
                if (entry) {
                    walkers.push(_walkDroppedEntry(entry, ""));
                }
            });
        }
        if (walkers.length) {
            return Promise.all(walkers).then(function (lists) {
                return Array.prototype.concat.apply([], lists);
            });
        }
        var files = dt && dt.files ? Array.prototype.slice.call(dt.files) : [];
        return Promise.resolve(
            files.map(function (file) {
                return { file: file, path: file.webkitRelativePath || file.name };
            })
        );
    }

    function _uploadDroppedItems(dt, destFolder) {
        if (!_canWrite) {
            alert("Read-only workspace: cannot upload.");
            return;
        }
        _setStatus("Preparing upload...");
        _transferMessage("Preparing local files/folders for upload...");
        return _collectDroppedFiles(dt)
            .then(function (items) {
                items = (items || []).filter(function (x) {
                    return x && x.file && x.path;
                });
                if (!items.length) {
                    throw new Error("No files found in drop.");
                }
                var fd = new FormData();
                fd.append("target_path", destFolder || "");
                items.forEach(function (x) {
                    fd.append("files", x.file, x.file.name);
                    fd.append("paths", x.path);
                });
                _setStatus("Uploading " + items.length + " file(s)...");
                _transferMessage("Queued files: " + items.length + " -> /" + (destFolder || ""));
                return _fetchJson("/api/devops-iac/upload?" + _queryScope(), {
                    method: "POST",
                    body: fd
                });
            })
            .then(function (pack) {
                if (!pack.data.ok) {
                    throw new Error(pack.data.error || "Upload failed");
                }
                _setStatus("Uploaded " + pack.data.count + " file(s).");
                _transferMessage(
                    "Successful transfers: " +
                        pack.data.count +
                        " file(s), " +
                        _formatBytes(pack.data.total_bytes || 0) +
                        " total."
                );
                return Promise.all([refreshTree(), fileBrowserRefresh()]);
            })
            .catch(function (e) {
                var msg = e && e.message ? e.message : "Upload error";
                _setStatus(msg);
                _transferMessage("Failed transfers: " + msg);
            });
    }

    function _initFileBrowserDnd() {
        if (_browserDndInited) {
            return;
        }
        var browser = document.querySelector(".devops-iac-file-browser");
        if (!browser) {
            return;
        }
        _browserDndInited = true;
        browser.addEventListener("dragover", function (ev) {
            if (_canHandleDrop(ev)) {
                ev.preventDefault();
                browser.classList.add("is-drop-target");
                ev.dataTransfer.dropEffect = ev.dataTransfer.types && Array.prototype.slice.call(ev.dataTransfer.types).indexOf("Files") >= 0 ? "copy" : "move";
            }
        });
        browser.addEventListener("dragleave", function (ev) {
            if (!browser.contains(ev.relatedTarget)) {
                browser.classList.remove("is-drop-target");
            }
        });
        browser.addEventListener("drop", function (ev) {
            _handleDrop(ev, _browserPath || "");
        });
    }

    function fileBrowserOpen(rel) {
        _setStatus("Loading file…");
        return _fetchJson("/api/devops-iac/file?path=" + encodeURIComponent(rel) + "&" + _queryScope(), {})
            .then(function (pack) {
                var j = pack.data;
                if (!j.ok) {
                    throw new Error(j.error || "Load failed");
                }
                _canWrite = j.can_write !== false;
                _setReadonlyBanner();
                var ed = el("devopsIacFileBrowserEditor");
                if (ed) {
                    ed.value = j.content != null ? j.content : "";
                }
                _browserSetSelected(j.path || rel, "file");
                _setStatus("");
            })
            .catch(function (e) {
                var ed = el("devopsIacFileBrowserEditor");
                if (ed) {
                    ed.value = e && e.message ? e.message : "Load error";
                }
                _setStatus(e && e.message ? e.message : "Load error");
            });
    }

    function fileBrowserSave() {
        if (!_canWrite) {
            alert("Read-only workspace: cannot save.");
            return;
        }
        var pathInput = el("devopsIacFileBrowserSelectedPath");
        var ed = el("devopsIacFileBrowserEditor");
        var rel = (pathInput && pathInput.value ? pathInput.value : _browserSelectedPath || "").trim();
        if (!rel || !ed) {
            alert("Select or name a file first.");
            return;
        }
        var payload = { path: rel, content: ed.value };
        Object.assign(payload, _bodyScope());
        _setStatus("Saving file…");
        return _fetchJson("/api/devops-iac/file", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        })
            .then(function (pack) {
                if (!pack.data.ok) {
                    throw new Error(pack.data.error || "Save failed");
                }
                _browserSetSelected(pack.data.path || rel, "file");
                _setStatus("Saved " + (pack.data.path || rel));
                return Promise.all([refreshTree(), fileBrowserRefresh()]);
            })
            .catch(function (e) {
                _setStatus(e && e.message ? e.message : "Save error");
            });
    }

    function fileBrowserNewFolder() {
        if (!_canWrite) {
            alert("Read-only workspace: cannot create folders.");
            return;
        }
        var rel = window.prompt("New folder path", _joinRel(_browserPath, "new-folder"));
        if (rel == null) {
            return;
        }
        rel = (rel || "").trim();
        if (!rel) {
            return;
        }
        var payload = { path: rel };
        Object.assign(payload, _bodyScope());
        _setStatus("Creating folder…");
        return _fetchJson("/api/devops-iac/mkdir", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        })
            .then(function (pack) {
                if (!pack.data.ok) {
                    throw new Error(pack.data.error || "Create folder failed");
                }
                _setStatus("Created folder " + (pack.data.path || rel));
                return Promise.all([refreshTree(), fileBrowserRefresh()]);
            })
            .catch(function (e) {
                _setStatus(e && e.message ? e.message : "Create folder error");
            });
    }

    function fileBrowserNewFile() {
        if (!_canWrite) {
            alert("Read-only workspace: cannot create files.");
            return;
        }
        var rel = window.prompt("New file path", _joinRel(_browserPath, "new-file.yml"));
        if (rel == null) {
            return;
        }
        rel = (rel || "").trim();
        if (!rel) {
            return;
        }
        _browserSetSelected(rel, "file");
        var ed = el("devopsIacFileBrowserEditor");
        if (ed) {
            ed.value = rel.indexOf("OpenTofu") === 0 ? 'terraform {\n  required_version = ">= 1.5.0"\n}\n\n' : "";
        }
        _setStatus("New file (unsaved) — click Save file to write");
    }

    function fileBrowserRenameSelected() {
        if (!_canWrite) {
            alert("Read-only workspace: cannot rename.");
            return;
        }
        if (!_browserSelectedPath) {
            alert("Select a file first.");
            return;
        }
        return devopsIacRenamePath(_browserSelectedPath);
    }

    function fileBrowserDeleteSelected() {
        if (!_canWrite) {
            alert("Read-only workspace: cannot delete.");
            return;
        }
        if (!_browserSelectedPath) {
            alert("Select a file first.");
            return;
        }
        if (!window.confirm("Delete " + _browserSelectedPath + "? This cannot be undone.")) {
            return;
        }
        return devopsIacDeletePath(_browserSelectedPath, { skipConfirm: true });
    }

    function fileBrowserUp() {
        if (!_browserPath) {
            return fileBrowserLoad("");
        }
        var info = _parentAndName(_browserPath);
        return fileBrowserLoad(info.parent || "");
    }

    function fileBrowserOpenInConsole() {
        var rel = (el("devopsIacFileBrowserSelectedPath") && el("devopsIacFileBrowserSelectedPath").value) || _browserSelectedPath;
        if (!rel) {
            alert("Select a file first.");
            return;
        }
        var mode = _devopsInferModeForPath(rel);
        devopsIacShowWorkspaceTab(mode);
        return openFile(rel);
    }

    function devopsIacSetStructureMode(mode) {
        var next = _devopsNormalizeMode(mode) || "creation";
        _structureMode = next;
        _applyModeChrome();
        _ensureCwdAllowedForMode();
        _ensureBrowserPathAllowedForMode();
        if (_activeTab === "files") {
            return fileBrowserRefresh();
        }
        if (_activeTab === "creation" || _activeTab === "configuration" || _activeTab === "security") {
            _activeTab = next;
            var creationTab = el("devopsIacTabCreation");
            var configurationTab = el("devopsIacTabConfiguration");
            var securityTab = el("devopsIacTabSecurity");
            if (creationTab) creationTab.setAttribute("aria-selected", next === "creation" ? "true" : "false");
            if (configurationTab) configurationTab.setAttribute("aria-selected", next === "configuration" ? "true" : "false");
            if (securityTab) securityTab.setAttribute("aria-selected", next === "security" ? "true" : "false");
            return refreshTree();
        }
        return refreshTree();
    }

    function devopsIacShowWorkspaceTab(tab) {
        var raw = String(tab || "").toLowerCase();
        if (raw === "console") {
            raw = "creation";
        }
        if (raw === "files" || raw === "graphical") {
            _activeTab = "files";
        } else if (raw === "security" || raw === "secops") {
            _activeTab = "security";
            _structureMode = "security";
        } else if (raw === "configuration" || raw === "config" || raw === "ansible") {
            _activeTab = "configuration";
            _structureMode = "configuration";
        } else {
            _activeTab = "creation";
            _structureMode = "creation";
        }
        var consolePane = el("devopsIacConsolePane");
        var filesPane = el("devopsIacFilesPane");
        var creationTab = el("devopsIacTabCreation");
        var configurationTab = el("devopsIacTabConfiguration");
        var securityTab = el("devopsIacTabSecurity");
        var filesTab = el("devopsIacTabFiles");
        var legacyConsoleTab = el("devopsIacTabConsole");
        if (consolePane) consolePane.classList.toggle("is-active", _activeTab !== "files");
        if (filesPane) filesPane.classList.toggle("is-active", _activeTab === "files");
        if (creationTab) creationTab.setAttribute("aria-selected", _activeTab === "creation" ? "true" : "false");
        if (configurationTab) configurationTab.setAttribute("aria-selected", _activeTab === "configuration" ? "true" : "false");
        if (securityTab) securityTab.setAttribute("aria-selected", _activeTab === "security" ? "true" : "false");
        if (filesTab) filesTab.setAttribute("aria-selected", _activeTab === "files" ? "true" : "false");
        if (legacyConsoleTab) legacyConsoleTab.setAttribute("aria-selected", _activeTab === "creation" ? "true" : "false");
        _applyModeChrome();
        if (_activeTab === "files") {
            _ensureBrowserPathAllowedForMode();
            return fileBrowserRefresh();
        }
        _ensureCwdAllowedForMode();
        return refreshTree();
    }

    function openFile(rel) {
        _openFile = rel;
        var pathEl = el("devopsIacCurrentPath");
        if (pathEl) {
            pathEl.value = rel;
        }
        _setStatus("Loading file…");
        return fetch(
            "/api/devops-iac/file?path=" + encodeURIComponent(rel) + "&" + _queryScope(),
            { credentials: "same-origin" }
        )
            .then(function (r) {
                return r.json();
            })
            .then(function (j) {
                if (!j.ok) {
                    _setStatus(j.error || "Load failed");
                    return;
                }
                if (j.can_write === false) {
                    _canWrite = false;
                } else {
                    _canWrite = true;
                }
                _setReadonlyBanner();
                _setStatus("");
                var ed = el("devopsIacEditor");
                if (ed) {
                    ed.value = j.content != null ? j.content : "";
                }
            })
            .catch(function (e) {
                _setStatus(e && e.message ? e.message : "Load error");
            });
    }

    function save() {
        if (_ctx === "org" && !_canWrite) {
            alert("Read-only: your role cannot edit this organization workspace.");
            return;
        }
        var rel = (el("devopsIacCurrentPath") && el("devopsIacCurrentPath").value) || _openFile;
        if (!rel) {
            alert("Open or set a file path first.");
            return;
        }
        var ed = el("devopsIacEditor");
        if (!ed) {
            return;
        }
        _setStatus("Saving…");
        var payload = { path: rel, content: ed.value };
        Object.assign(payload, _bodyScope());
        return fetch("/api/devops-iac/file", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
            body: JSON.stringify(payload)
        })
            .then(function (r) {
                return r.json();
            })
            .then(function (j) {
                if (!j.ok) {
                    _setStatus(j.error || "Save failed");
                    return;
                }
                _setStatus("Saved " + (j.path || rel));
                _openFile = j.path || rel;
                refreshTree();
            })
            .catch(function (e) {
                _setStatus(e && e.message ? e.message : "Save error");
            });
    }

    function newFile() {
        if (_ctx === "org" && !_canWrite) {
            alert("Read-only: your role cannot add files in this organization workspace.");
            return;
        }
        var rel = window.prompt(
            _devopsIsAnsibleToolMode(_toolMode())
                ? (_toolMode() === "security"
                    ? "New file path (under this workspace), e.g. Ansible/Security/playbooks/custom.yml"
                    : "New file path (under this workspace), e.g. Ansible/playbooks/site.yml")
                : "New file path (under this workspace), e.g. OpenTofu/main.tf",
            _toolMode() === "security"
                ? "Ansible/Security/playbooks/custom.yml"
                : _toolMode() === "configuration"
                  ? "Ansible/playbooks/site.yml"
                  : "OpenTofu/main.tf"
        );
        if (rel == null) {
            return;
        }
        rel = (rel || "").trim();
        if (!rel) {
            return;
        }
        if (el("devopsIacEditor")) {
            el("devopsIacEditor").value = "";
        }
        _openFile = rel;
        if (el("devopsIacCurrentPath")) {
            el("devopsIacCurrentPath").value = rel;
        }
        if (rel.indexOf("Ansible") === 0 || rel.indexOf("ansible") === 0 || rel.indexOf("bare-metal-ztp") === 0) {
            if (el("devopsIacEditor") && !el("devopsIacEditor").value) {
                el("devopsIacEditor").value =
                    "---\n- hosts: localhost\n  connection: local\n  gather_facts: false\n  tasks: []\n";
            }
        } else if (rel.indexOf("OpenTofu") === 0 || rel.indexOf("opentofu") === 0) {
            if (el("devopsIacEditor") && !el("devopsIacEditor").value) {
                el("devopsIacEditor").value = 'terraform {\n  required_version = ">= 1.5.0"\n}\n\n';
            }
        }
        _setStatus("New file (unsaved) — click Save to write");
    }

    function _extractSecretNames(text) {
        var names = [];
        var seen = {};
        var s = String(text || "");
        var re = /\{\{\s*hayabusa_secret:([A-Za-z0-9._:-]+)\s*\}\}|<<\s*SECRET:([A-Za-z0-9._:-]+)\s*>>/g;
        var m;
        while ((m = re.exec(s))) {
            var k = m[1] || m[2] || "";
            if (k && !seen[k]) {
                seen[k] = 1;
                names.push(k);
            }
        }
        return names;
    }

    function _formatControllerExecuteResult(ex, out) {
        if (!out) {
            return ex;
        }
        var bits = [];
        bits.push("status=" + ((ex && ex.status) || (ex && ex.ok ? "completed" : "failed")));
        if (ex && ex.cmd) bits.push("cmd: " + ex.cmd);
        if (ex && ex.stdout) bits.push(ex.stdout);
        if (ex && ex.stderr) bits.push(ex.stderr);
        if (ex && ex.error) bits.push(String(ex.error));
        if (ex && ex.code === "csrf_failed") {
            bits.push("CSRF rejected — refresh the page and retry (session cookie must match X-CSRF-Token).");
        }
        bits.push("\nexecuted_on=controller · lan_approved=yes · hayabusa_saw_secret_values=false");
        out.textContent = bits.join("\n");
        return ex;
    }

    function _awaitControllerJobExecute(jobId, out) {
        // Single POST with wait=true: poll until controller LAN-approves, hydrates, and executes.
        // Secret values never return to Hayabusa.
        if (out) {
            out.textContent =
                "Waiting for LAN Approve & pass on the controller (hydrate + execute there)…\njob_id=" +
                jobId +
                "\n(Open the controller → Job approvals.)";
        }
        return _fetchJson("/api/my-controller/jobs/" + encodeURIComponent(jobId) + "/execute", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ wait: true, timeout_sec: 900 }),
        }).then(function (exWrap) {
            var ex = (exWrap && exWrap.data) || exWrap || {};
            if (exWrap && !exWrap.okHttp && ex && ex.error) {
                if (out) {
                    out.textContent =
                        String(ex.error) +
                        (ex.code ? " (" + ex.code + ")" : "") +
                        (ex.hint ? "\n" + ex.hint : "") +
                        "\njob_id=" +
                        jobId;
                }
                return ex;
            }
            return _formatControllerExecuteResult(ex, out);
        });
    }

    function _pollControllerJob(jobId, out) {
        // Prefer wait-based execute; fall back to status poll only if execute wait is unavailable.
        return _awaitControllerJobExecute(jobId, out).catch(function () {
            var tries = 0;
            function tick() {
                tries += 1;
                return _fetchJson("/api/my-controller/jobs/" + encodeURIComponent(jobId), {
                    method: "GET",
                })
                    .then(function (wrap) {
                        var j = (wrap && wrap.data) || wrap || {};
                        var status = (j && j.status) || "";
                        if (out) {
                            out.textContent =
                                "Controller job " +
                                jobId.slice(0, 8) +
                                "… status=" +
                                status +
                                "\n(Approve & pass on the controller LAN UI under Job approvals. Controller hydrates and executes; secrets stay there.)";
                        }
                        if (status === "hydrated") {
                            if (out) {
                                out.textContent =
                                    "Legacy controller reported hydrated — upgrade controller so it executes locally (secrets must not leave it)…\njob_id=" +
                                    jobId;
                            }
                            return _fetchJson(
                                "/api/my-controller/jobs/" + encodeURIComponent(jobId) + "/execute",
                                {
                                    method: "POST",
                                    headers: { "Content-Type": "application/json" },
                                    body: JSON.stringify({ wait: false }),
                                }
                            ).then(function (exWrap) {
                                return _formatControllerExecuteResult(
                                    (exWrap && exWrap.data) || exWrap || {},
                                    out
                                );
                            });
                        }
                        if (
                            status === "pending_approval" ||
                            status === "hydrating" ||
                            status === "running"
                        ) {
                            if (tries > 90) {
                                if (out) {
                                    out.textContent += "\nStill waiting for LAN approval / hydrate.";
                                }
                                return j;
                            }
                            return new Promise(function (res) {
                                setTimeout(res, 3000);
                            }).then(tick);
                        }
                        var result = (j && j.result) || j || {};
                        if (out) {
                            var bits = [];
                            bits.push("status=" + status);
                            if (result.cmd) bits.push("cmd: " + result.cmd);
                            if (result.stdout) bits.push(result.stdout);
                            if (result.stderr) bits.push(result.stderr);
                            if (result.error || j.error) bits.push(String(result.error || j.error));
                            bits.push(
                                "\nexecuted_on=controller · hayabusa_saw_secret_values=false · lan_approved=" +
                                    (status === "completed" || status === "failed" ? "yes" : status)
                            );
                            out.textContent = bits.join("\n");
                        }
                        return j;
                    })
                    .catch(function (e) {
                        if (out) {
                            out.textContent = (e && e.message) || "poll error";
                        }
                    });
            }
            return tick();
        });
    }

    function runCommand() {
        if (_mustUseController && !_canRunViaController && !_canRun) {
            if (el("devopsIacRunOutput")) {
                el("devopsIacRunOutput").textContent =
                    "Run disabled: controller is bound. Need run permission for /api/my-controller, or act_without_controller for direct Hayabusa runs.";
            }
            return;
        }
        if (!_mustUseController && _ctx === "org" && !_canRun) {
            if (el("devopsIacRunOutput")) {
                el("devopsIacRunOutput").textContent =
                    "Run disabled: need run_devops_iac, and if a controller is bound you also need act_without_controller (or use /api/my-controller).";
            }
            return;
        }
        var cmd = (el("devopsIacRunCmd") && el("devopsIacRunCmd").value) || "";
        var workdir = (el("devopsIacWorkdir") && el("devopsIacWorkdir").value) || ".";
        var out = el("devopsIacRunOutput");
        if (out) {
            out.textContent = _mustUseController
                ? "Submitting to controller (awaiting LAN approval)…"
                : "Running…";
        }

        if (_mustUseController && _canRunViaController) {
            var editor = el("devopsIacEditor");
            var content = editor ? editor.value || "" : "";
            var playbookPath = _openFile || "";
            var body = {
                command: cmd,
                workdir: workdir === "." ? "" : workdir,
                timeout_sec: 300,
                execute_on: "controller",
                secret_keys: _extractSecretNames(content + "\n" + cmd),
            };
            if (playbookPath && content) {
                body.playbook_path = playbookPath;
                body.playbook_content = content;
            }
            return _fetchJson("/api/my-controller/jobs/run", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
            })
                .then(function (wrap) {
                    var j = (wrap && wrap.data) || wrap || {};
                    if (!j) {
                        if (out) out.textContent = "No response";
                        return;
                    }
                    if (!wrap.okHttp && !j.pending_approval && j.status !== "pending_approval") {
                        if (out) {
                            out.textContent = j.error || JSON.stringify(j, null, 2);
                        }
                        return j;
                    }
                    if (j.pending_approval || j.status === "pending_approval") {
                        var jid = j.job_id || j.id || "";
                        if (out) {
                            out.textContent =
                                "Queued on controller for LAN approval.\njob_id=" +
                                jid +
                                "\nOpen the controller → Job approvals, then Approve & pass.\n" +
                                "Controller hydrates secrets and runs Ansible/OpenTofu locally. Secret values never leave the controller.";
                        }
                        if (jid) {
                            return _pollControllerJob(jid, out);
                        }
                        return j;
                    }
                    if (out) {
                        out.textContent = JSON.stringify(j, null, 2);
                    }
                    return j;
                })
                .catch(function (e) {
                    if (out) {
                        out.textContent = (e && e.message) || "controller job error";
                    }
                });
        }

        var bodyDirect = { command: cmd, workdir: workdir, timeout: 300 };
        Object.assign(bodyDirect, _bodyScope());
        var chk = el("devopsIacUseSshKey");
        if (chk) {
            bodyDirect.use_ssh_key = chk.checked ? "1" : "0";
        }
        return fetch("/api/devops-iac/run", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
            body: JSON.stringify(bodyDirect)
        })
            .then(function (r) {
                return r.json().then(function (j) {
                    return { status: r.status, data: j };
                });
            })
            .then(function (o) {
                if (!o.data) {
                    if (out) {
                        out.textContent = "No response";
                    }
                    return;
                }
                if (out) {
                    var d = o.data;
                    var lines = [];
                    if (d.error) lines.push(String(d.error));
                    if (d.stdout) lines.push(d.stdout);
                    if (d.stderr) lines.push(d.stderr);
                    if (!lines.length) lines.push(JSON.stringify(d, null, 2));
                    lines.push(_formatInfraBridgeNote(d.infra_bridge));
                    out.textContent = lines.join("\n");
                }
                _afterInfraBridgeRun(o.data && o.data.infra_bridge);
            })
            .catch(function (e) {
                if (out) {
                    out.textContent = e && e.message ? e.message : "Run error";
                }
            });
    }

    function devopsIacOnSavedCommandPick(selectEl) {
        var v = (selectEl && selectEl.value) || "";
        if (!v) {
            return;
        }
        var list = _savedForContext();
        var ent = null;
        list.forEach(function (x) {
            if (x && String(x.id) === String(v)) {
                ent = x;
            }
        });
        if (ent && ent.command != null) {
            var i = el("devopsIacRunCmd");
            if (i) {
                i.value = ent.command;
            }
        }
    }

    function devopsIacSaveCommandEntry() {
        var i = el("devopsIacRunCmd");
        var raw = (i && i.value) ? i.value.trim() : "";
        if (!raw) {
            alert("Type a command first, then click Save to store it.");
            return;
        }
        var name = window.prompt("Label for this command (e.g. “tofu plan dev”)", raw.slice(0, 40));
        if (name == null) {
            return;
        }
        name = (name || "").trim() || raw.slice(0, 64);
        var all = _getAllSaved();
        var id = "s" + Date.now() + "r" + Math.floor(Math.random() * 1e6);
        all.push({
            id: id,
            name: name,
            command: raw,
            context: _ctx,
            org_id: _orgId || null
        });
        _setAllSaved(all);
        _refreshSavedCommandsSelect();
        var sel = el("devopsIacSavedCmd");
        if (sel) {
            sel.value = id;
        }
        _setStatus("Saved command: " + name);
    }

    function devopsIacDeleteSavedCommand() {
        var sel = el("devopsIacSavedCmd");
        var v = (sel && sel.value) || "";
        if (!v) {
            alert("Select a saved command in the list first.");
            return;
        }
        var all = _getAllSaved();
        var next = all.filter(function (x) {
            return !x || String(x.id) !== String(v);
        });
        if (next.length === all.length) {
            return;
        }
        _setAllSaved(next);
        if (sel) {
            sel.value = "";
        }
        _setStatus("Removed saved command.");
    }

    function _parentAndName(fullPath) {
        var s = (fullPath || "").replace(/\\/g, "/").replace(/\/+$/g, "");
        if (!s) {
            return { parent: "", name: "" };
        }
        var i = s.lastIndexOf("/");
        if (i < 0) {
            return { parent: "", name: s };
        }
        return { parent: s.slice(0, i), name: s.slice(i + 1) };
    }

    function _validNewName(n) {
        n = (n || "").trim();
        if (!n || n === "." || n === "..") {
            return false;
        }
        if (n.indexOf("/") >= 0 || n.indexOf("\\") >= 0) {
            return false;
        }
        return true;
    }

    function devopsIacDeletePath(rel, opts) {
        if (!_canWrite) {
            alert("Read-only workspace: cannot delete.");
            return;
        }
        rel = String(rel || "").trim();
        if (!rel) {
            alert("Select a file or folder first.");
            return;
        }
        opts = opts || {};
        if (!opts.skipConfirm && !window.confirm("Delete " + rel + "? This cannot be undone.\nPackaged default playbooks cannot be deleted.")) {
            return;
        }
        var payload = { path: rel };
        Object.assign(payload, _bodyScope());
        _setStatus("Deleting…");
        return _fetchJson("/api/devops-iac/rm", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        })
            .then(function (pack) {
                var j = pack && pack.data ? pack.data : pack;
                if (!j || !j.ok) {
                    throw new Error((j && j.error) || "Delete failed");
                }
                if (_openFile && (_openFile === rel || _openFile.indexOf(rel + "/") === 0)) {
                    _openFile = null;
                    if (el("devopsIacCurrentPath")) {
                        el("devopsIacCurrentPath").value = "";
                    }
                    if (el("devopsIacEditor")) {
                        el("devopsIacEditor").value = "";
                    }
                }
                if (_browserSelectedPath && (_browserSelectedPath === rel || _browserSelectedPath.indexOf(rel + "/") === 0)) {
                    _browserSetSelected(null, null);
                    var ed = el("devopsIacFileBrowserEditor");
                    if (ed) {
                        ed.value = "";
                    }
                }
                _setStatus("Deleted " + (j.path || rel));
                return Promise.all([refreshTree(), fileBrowserRefresh()]);
            })
            .catch(function (e) {
                _setStatus(e && e.message ? e.message : "Delete error");
            });
    }

    function devopsIacRenamePath(oldPath) {
        if (_ctx === "org" && !_canWrite) {
            alert("Read-only in this org workspace.");
            return;
        }
        var info = _parentAndName(oldPath);
        var nn = window.prompt("New name (same folder only)", info.name);
        if (nn == null) {
            return;
        }
        if (!_validNewName(nn)) {
            alert("Invalid name. Use a single name without / or path segments.");
            return;
        }
        if (nn === info.name) {
            return;
        }
        var newPath = info.parent ? info.parent + "/" + nn : nn;
        if (oldPath === newPath) {
            return;
        }
        _setStatus("Renaming…");
        var payload = { from: oldPath, to: newPath };
        Object.assign(payload, _bodyScope());
        return fetch("/api/devops-iac/mv", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
            body: JSON.stringify(payload)
        })
            .then(function (r) {
                return r.json();
            })
            .then(function (j) {
                if (!j.ok) {
                    _setStatus(j.error || "Rename failed");
                    return;
                }
                _setStatus("Renamed to " + (j.to || newPath));
                if (_openFile && (_openFile === oldPath || _openFile.indexOf(oldPath + "/") === 0)) {
                    if (_openFile === oldPath) {
                        _openFile = j.to;
                        if (el("devopsIacCurrentPath")) {
                            el("devopsIacCurrentPath").value = j.to;
                        }
                    } else {
                        _openFile = j.to + _openFile.slice(oldPath.length);
                        if (el("devopsIacCurrentPath")) {
                            el("devopsIacCurrentPath").value = _openFile;
                        }
                    }
                }
                _cwd = [];
                if (_browserSelectedPath && _browserSelectedPath === oldPath) {
                    _browserSelectedPath = j.to || newPath;
                    _browserSelectedType = _ctxMenuKind || _browserSelectedType || "file";
                }
                refreshTree();
                fileBrowserRefresh();
            })
            .catch(function (e) {
                _setStatus(e && e.message ? e.message : "Rename error");
            });
    }

    function resetView() {
        _cwd = [];
        _openFile = null;
        _ctx = "user";
        _orgId = null;
        _canWrite = true;
        _canEnqueue = true;
        _canApprove = false;
        _canRun = true;
        _activeTab = "creation";
        _structureMode = "creation";
        _browserPath = "";
        _browserSelectedPath = null;
        _browserSelectedType = null;
        _browserEntries = [];
        _browserRootEntries = [];
        if (el("devopsIacContext")) {
            el("devopsIacContext").value = "user";
        }
        if (el("devopsIacOrgWrap")) {
            el("devopsIacOrgWrap").style.display = "none";
        }
        if (el("devopsIacCurrentPath")) {
            el("devopsIacCurrentPath").value = "";
        }
        if (el("devopsIacEditor")) {
            el("devopsIacEditor").value = "";
        }
        if (el("devopsIacRunOutput")) {
            el("devopsIacRunOutput").textContent = "";
        }
        if (el("devopsIacFileBrowserSelectedPath")) {
            el("devopsIacFileBrowserSelectedPath").value = "";
        }
        if (el("devopsIacFileBrowserEditor")) {
            el("devopsIacFileBrowserEditor").value = "";
        }
        if (el("devopsIacRunCmd")) {
            el("devopsIacRunCmd").value = _stockRunCommands().creation;
        }
        if (el("devopsIacSavedCmd")) {
            el("devopsIacSavedCmd").value = "";
        }
        var ts = el("devopsIacTofuState");
        if (ts) {
            ts.textContent = "OpenTofu state: —";
        }
        _applyModeChrome();
    }

    window.devopsIacRefreshTofuState = function () {
        _setStatus("Loading OpenTofu state…");
        return _refreshTofuStateSummary().then(function () {
            _setStatus("");
        });
    };

    window.devopsIacLoadTofuInventory = function () {
        var out = el("devopsIacRunOutput");
        if (!out) {
            return;
        }
        _setStatus("Loading inventory from state…");
        var u = "/api/devops-iac/opentofu-state-inventory?limit=500&format=ansible&" + _queryScope();
        fetch(u, { credentials: "same-origin" })
            .then(function (r) {
                return r.json();
            })
            .then(function (j) {
                _setStatus("");
                if (!j || !j.ok) {
                    out.textContent = j && j.error ? String(j.error) : "Inventory request failed";
                    return;
                }
                if (!j.found) {
                    out.textContent = j.message || "No terraform.tfstate found under OpenTofu.";
                    return;
                }
                var slim = {
                    ok: j.ok,
                    found: j.found,
                    path: j.path,
                    row_count: j.row_count,
                    ansible_inventory_hosts: j.ansible_inventory_hosts,
                    ansible_inventory: j.ansible_inventory
                };
                var s = JSON.stringify(slim, null, 2);
                var max = 120000;
                if (s.length > max) {
                    s =
                        s.slice(0, max) +
                        "\n\n… truncated for display (" +
                        s.length +
                        " chars). Use Sync inventory or the API with a smaller limit.";
                }
                out.textContent = s;
            })
            .catch(function (e) {
                _setStatus("");
                out.textContent = e && e.message ? e.message : "Network error";
            });
    };

    window.devopsIacSyncFromController = function () {
        _setStatus("Pulling workspace from controller…");
        return _fetchJson("/api/my-controller/iac/sync", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: "{}"
        })
            .then(function (j) {
                if (!j || !j.ok) {
                    throw new Error((j && j.error) || "Pull from controller failed");
                }
                _setStatus(
                    "Pulled " +
                        (j.written != null ? j.written : j.exported_count || 0) +
                        " file(s) from controller."
                );
                if (window.devopsIacRefreshTree) {
                    return window.devopsIacRefreshTree();
                }
            })
            .catch(function (e) {
                _setStatus((e && e.message) || "Pull from controller failed");
            });
    };

    window.devopsIacSyncToController = function () {
        _setStatus("Pushing workspace to controller…");
        return _fetchJson("/api/my-controller/iac/push", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: "{}"
        })
            .then(function (j) {
                if (!j || !j.ok) {
                    throw new Error((j && j.error) || "Push to controller failed");
                }
                _setStatus(
                    "Pushed " +
                        (j.written != null ? j.written : j.exported_count || 0) +
                        " file(s) to controller."
                );
            })
            .catch(function (e) {
                _setStatus((e && e.message) || "Push to controller failed");
            });
    };

    window.devopsIacSyncTofuInventory = function () {
        if (!_canWrite) {
            alert("Read-only workspace: cannot write inventory.");
            return;
        }
        if (!window.confirm("Write Ansible JSON inventory to Ansible/inventory/opentofu_inventory_hosts.json ?")) {
            return;
        }
        var out = el("devopsIacRunOutput");
        _setStatus("Syncing inventory…");
        fetch("/api/devops-iac/opentofu-sync-inventory", {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(_bodyScope())
        })
            .then(function (r) {
                return r.json().then(function (j) {
                    return { status: r.status, j: j };
                });
            })
            .then(function (x) {
                _setStatus("");
                if (!x.j || !x.j.ok) {
                    var msg = (x.j && x.j.error) || "Sync failed";
                    if (out) {
                        out.textContent = msg;
                    }
                    _setStatus(msg);
                    return;
                }
                var line =
                    "Synced inventory → " +
                    (x.j.path || "Ansible/inventory/opentofu_inventory_hosts.json") +
                    "\nstate: " +
                    (x.j.state_path || "—") +
                    "\nrows: " +
                    (x.j.row_count != null ? x.j.row_count : "?") +
                    " · ansible hosts: " +
                    (x.j.ansible_hosts_written != null ? x.j.ansible_hosts_written : "?");
                if (out) {
                    out.textContent = line;
                }
                _setStatus("Inventory synced.");
                return _refreshTofuStateSummary();
            })
            .catch(function (e) {
                _setStatus("");
                if (out) {
                    out.textContent = e && e.message ? e.message : "Network error";
                }
            });
    };

    window.devopsIacRefreshTree = function () {
        return refreshTree().then(function () {
            if (_activeTab === "files") {
                return fileBrowserRefresh();
            }
        });
    };

    window.initDevopsIacWorkspace = function initDevopsIacWorkspace() {
        var intent = _readWorkspaceUrlIntent();
        resetView();
        devopsIacShowWorkspaceTab("creation");
        if (intent.context === "org" || intent.context === "organization") {
            _ctx = "org";
            _orgId = intent.orgId || null;
        }
        if (el("devopsIacContext")) {
            el("devopsIacContext").value = _ctx === "org" ? "org" : "user";
        }
        if (el("devopsIacOrgWrap")) {
            el("devopsIacOrgWrap").style.display = _ctx === "org" ? "inline-flex" : "none";
        }
        return _setWhoami()
            .then(function () {
                if (_ctx === "org" && intent.orgId && el("devopsIacOrgSelect")) {
                    var osel = el("devopsIacOrgSelect");
                    var i;
                    var found = false;
                    for (i = 0; i < osel.options.length; i++) {
                        if (osel.options[i].value === intent.orgId) {
                            osel.value = intent.orgId;
                            _orgId = intent.orgId;
                            found = true;
                            break;
                        }
                    }
                    if (!found && intent.orgId) {
                        _setStatus("URL org_id is not in your organization list; pick an org from the dropdown.");
                    }
                }
                return refreshTree();
            })
            .then(function () {
                if (intent.openPath) {
                    var inferred = _devopsInferModeForPath(intent.openPath);
                    if (inferred !== _toolMode()) {
                        devopsIacShowWorkspaceTab(inferred);
                    }
                    openFile(intent.openPath);
                }
                if (intent.stripAutodev) {
                    _stripUrlParams(["devops", "iac"]);
                }
                _syncGlobalOrgScopeAndFleet();
            });
    };

    function devopsIacOpenSshKeyModal(scope) {
        var m = el("devopsIacSshModal");
        var ta = el("devopsIacSshPem");
        var sc = el("devopsIacSshScopeLabel");
        if (!m || !ta) {
            return;
        }
        ta.value = "";
        m.style.display = "flex";
        m.dataset.scope = scope === "org" ? "org" : "personal";
        if (sc) {
            sc.textContent =
                scope === "org"
                    ? "Saving organization member key for org " + String(_orgId || "") + " (encrypted on disk)."
                    : "Saving personal SSH key for your user workspace (encrypted on disk).";
        }
    }

    function devopsIacCloseSshKeyModal() {
        var m = el("devopsIacSshModal");
        if (m) {
            m.style.display = "none";
        }
    }

    function devopsIacSshSavePem() {
        var m = el("devopsIacSshModal");
        var ta = el("devopsIacSshPem");
        if (!m || !ta) {
            return;
        }
        var scope = m.dataset.scope || "personal";
        var pem = (ta.value || "").trim();
        if (!pem) {
            alert("Paste a PEM private key first.");
            return;
        }
        if (scope === "org" && (!_orgId || _ctx !== "org")) {
            alert("Switch workspace to an organization first, then set the org member key.");
            return;
        }
        var url = scope === "org" ? "/api/user-ssh-keys/org" : "/api/user-ssh-keys/personal";
        var body =
            scope === "org"
                ? JSON.stringify({ org_id: _orgId, private_key: pem })
                : JSON.stringify({ private_key: pem });
        fetch(url, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
            body: body
        })
            .then(function (r) {
                return r.json().then(function (j) {
                    return { ok: r.ok, j: j };
                });
            })
            .then(function (x) {
                if (!x.j || !x.j.ok) {
                    alert((x.j && x.j.error) || "Save failed");
                    return;
                }
                devopsIacCloseSshKeyModal();
                return _refreshSshKeyStatus();
            })
            .catch(function (e) {
                alert(e && e.message ? e.message : "Save error");
            });
    }

    function devopsIacSshDeleteCurrentScope() {
        var scope = _ctx === "org" && _orgId ? "org" : "personal";
        if (
            !window.confirm(
                "Remove the saved " + (scope === "org" ? "organization member" : "personal") + " SSH private key from Peregrine?"
            )
        ) {
            return;
        }
        if (scope === "personal") {
            fetch("/api/user-ssh-keys/personal", { method: "DELETE", credentials: "same-origin" })
                .then(function (r) {
                    return r.json();
                })
                .then(function (j) {
                    if (!j || !j.ok) {
                        alert((j && j.error) || "Delete failed");
                        return;
                    }
                    return _refreshSshKeyStatus();
                });
        } else {
            fetch("/api/user-ssh-keys/org", {
                method: "DELETE",
                headers: { "Content-Type": "application/json" },
                credentials: "same-origin",
                body: JSON.stringify({ org_id: _orgId })
            })
                .then(function (r) {
                    return r.json();
                })
                .then(function (j) {
                    if (!j || !j.ok) {
                        alert((j && j.error) || "Delete failed");
                        return;
                    }
                    return _refreshSshKeyStatus();
                });
        }
    }

    window.devopsIacOpenSshKeyModalForContext = function () {
        devopsIacOpenSshKeyModal(_ctx === "org" && _orgId ? "org" : "personal");
    };
    window.devopsIacCloseSshKeyModal = devopsIacCloseSshKeyModal;
    window.devopsIacSshSavePem = devopsIacSshSavePem;
    window.devopsIacSshDeleteCurrentScope = devopsIacSshDeleteCurrentScope;

    window.devopsIacSave = save;
    window.devopsIacNewFile = newFile;
    window.devopsIacRun = runCommand;
    window.devopsIacOnContextChange = _onContextChange;
    window.devopsIacOnSavedCommandPick = devopsIacOnSavedCommandPick;
    window.devopsIacSaveCommandEntry = devopsIacSaveCommandEntry;
    window.devopsIacDeleteSavedCommand = devopsIacDeleteSavedCommand;
    window.devopsIacRenamePath = devopsIacRenamePath;
    window.devopsIacDeletePath = devopsIacDeletePath;
    window.devopsIacShowWorkspaceTab = devopsIacShowWorkspaceTab;
    window.devopsIacSetStructureMode = devopsIacSetStructureMode;
    window.devopsIacFileBrowserRefresh = fileBrowserRefresh;
    window.devopsIacFileBrowserUp = fileBrowserUp;
    window.devopsIacFileBrowserNewFolder = fileBrowserNewFolder;
    window.devopsIacFileBrowserNewFile = fileBrowserNewFile;
    window.devopsIacFileBrowserRenameSelected = fileBrowserRenameSelected;
    window.devopsIacFileBrowserDeleteSelected = fileBrowserDeleteSelected;
    window.devopsIacFileBrowserOpenInConsole = fileBrowserOpenInConsole;
    window.devopsIacFileBrowserSave = fileBrowserSave;
    window.devopsIacModeFilter = {
        entryAllowed: _devopsEntryAllowedInMode,
        pathAllowed: _devopsPathAllowedInMode,
        inferMode: _devopsInferModeForPath,
        filterEntries: _devopsFilterEntries,
        displayName: _devopsEntryDisplayName,
        badgeKind: _devopsEntryBadgeKind,
        workdirOptions: _workdirOptionsForMode,
        stockCommands: _stockRunCommands
    };

    window.devopsIacApplyContext = function () {
        _onContextChange();
        if (_ctx === "org") {
            var osel = el("devopsIacOrgSelect");
            if (!osel || !osel.options.length) {
                alert("No organizations are available for this account. Use Personal workspace or grant organization access in your profile.");
                if (el("devopsIacContext")) {
                    el("devopsIacContext").value = "user";
                }
                _ctx = "user";
                _orgId = null;
                if (el("devopsIacOrgWrap")) {
                    el("devopsIacOrgWrap").style.display = "none";
                }
                return _setWhoami().then(function () {
                    _refreshSavedCommandsSelect();
                    return refreshTree().then(function () {
                        if (_activeTab === "files") {
                            return fileBrowserRefresh();
                        }
                    });
                });
            }
        }
        _resetNavForNewRoot();
        return _setWhoami().then(function () {
            return refreshTree().then(function () {
                if (_activeTab === "files") {
                    return fileBrowserRefresh();
                }
            });
        });
    };

    window.devopsIacOnOrgChange = function () {
        var osel = el("devopsIacOrgSelect");
        if (osel) {
            _orgId = osel.value;
        }
        _resetNavForNewRoot();
        _syncGlobalOrgScopeAndFleet();
        return _setWhoami().then(function () {
            return refreshTree().then(function () {
                if (_activeTab === "files") {
                    return fileBrowserRefresh();
                }
            });
        });
    };

    function _showSchedModal(open) {
        var m = el("devopsIacScheduleModal");
        if (m) {
            m.style.display = open ? "flex" : "none";
        }
    }

    window.devopsIacOpenScheduleDialog = function () {
        if (_ctx === "org" && !_canWrite) {
            alert("Read-only: scheduling is not allowed for this organization workspace.");
            return;
        }
        var cmdI = el("devopsIacRunCmd");
        if (el("devopsIacSchedCommandPreview")) {
            el("devopsIacSchedCommandPreview").value = (cmdI && cmdI.value) || "";
        }
        if (el("devopsIacSchedWorkdir")) {
            el("devopsIacSchedWorkdir").value = (el("devopsIacWorkdir") && el("devopsIacWorkdir").value) || ".";
        }
        if (el("devopsIacSchedAck")) {
            el("devopsIacSchedAck").checked = false;
        }
        _showSchedModal(true);
    };

    window.devopsIacCloseScheduleDialog = function () {
        _showSchedModal(false);
    };

    window.devopsIacRefreshQueue = function () {
        if (_ctx !== "org" || !_orgId) {
            _setStatus("DevOps queue requires organization workspace.");
            return;
        }
        var qs = "org_id=" + encodeURIComponent(_orgId) + "&context=organization";
        fetch("/api/devops-iac/run/queue?" + qs, { credentials: "same-origin" })
            .then(function (r) { return r.json(); })
            .then(function (j) {
                var box = el("devopsIacQueueOut");
                if (!box) return;
                var items = (j && j.items) || [];
                if (!items.length) {
                    box.textContent = "Queue empty.";
                    return;
                }
                box.innerHTML = items.map(function (it) {
                    var line = (it.status || "?") + " · " + (it.command || "") + " · " + (it.username || "");
                    var exec = (it.result && it.result.execution) ? it.result.execution : null;
                    var execHtml = "";
                    if (exec) {
                        var tail = (exec.stdout || exec.stderr || exec.error || "").slice(0, 400);
                        if (exec.infra_bridge) {
                            tail += _formatInfraBridgeNote(exec.infra_bridge);
                        }
                        execHtml = "<pre style='margin:4px 0 0;padding:4px;background:#0b0f14;color:#94a3b8;font-size:10px;max-height:80px;overflow:auto;'>" +
                            tail.replace(/</g, "&lt;") + "</pre>";
                    }
                    if (it.status === "pending") {
                        var approveBtn = _canApprove
                            ? " <button type='button' class='devops-iac-queue-approve' data-id='" + it.id + "'>Approve</button>"
                            : " <span style='color:#94a3b8;font-size:11px;'>(awaiting approver)</span>";
                        return "<div style='margin:6px 0;'>" + line + approveBtn + execHtml + "</div>";
                    }
                    return "<div style='margin:6px 0;'>" + line + execHtml + "</div>";
                }).join("");
                box.querySelectorAll(".devops-iac-queue-approve").forEach(function (btn) {
                    btn.addEventListener("click", function () {
                        if (!_canApprove) {
                            alert("Your role cannot approve DevOps runs.");
                            return;
                        }
                        var id = btn.getAttribute("data-id");
                        fetch("/api/devops-iac/run/queue/" + encodeURIComponent(id) + "/approve?org_id=" + encodeURIComponent(_orgId) + "&context=organization", {
                            method: "POST",
                            credentials: "same-origin",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({ org_id: _orgId, execute: true })
                        }).then(function (r) { return r.json(); }).then(function (j) {
                            if (j && !j.ok) { alert((j.error) || "Approve failed"); }
                            var exec = j && j.item && j.item.result && j.item.result.execution;
                            _afterInfraBridgeRun(exec && exec.infra_bridge);
                            window.devopsIacRefreshQueue();
                        });
                    });
                });
            });
    };

    window.devopsIacEnqueueCommand = function () {
        if (_ctx !== "org" || !_orgId) {
            alert("Switch to an organization DevOps workspace to use the approval queue.");
            return;
        }
        if (!_canEnqueue) {
            alert("Your role cannot enqueue DevOps runs (requires enqueue_devops_runs).");
            return;
        }
        var cmd = (el("devopsIacRunCmd") && el("devopsIacRunCmd").value) || "";
        if (!cmd.trim()) {
            alert("Enter a command in the Run line first.");
            return;
        }
        fetch("/api/devops-iac/run/queue?context=organization&org_id=" + encodeURIComponent(_orgId), {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                org_id: _orgId,
                workspace: _relPath() || ".",
                command: cmd.trim()
            })
        }).then(function (r) { return r.json(); }).then(function (j) {
            if (j && j.ok) {
                _setStatus("Queued for approval: " + (j.item && j.item.id));
                window.devopsIacRefreshQueue();
            } else {
                alert((j && (j.error || j.required_permission)) || "Queue failed");
            }
        });
    };

    window.devopsIacSubmitSchedule = function () {
        if (!el("devopsIacSchedAck") || !el("devopsIacSchedAck").checked) {
            alert("Please confirm you understand the job will run on a schedule until cancelled.");
            return;
        }
        var name = (el("devopsIacSchedName") && el("devopsIacSchedName").value) || "Scheduled job";
        var command = (el("devopsIacSchedCommandPreview") && el("devopsIacSchedCommandPreview").value) || "";
        var workdir = (el("devopsIacSchedWorkdir") && el("devopsIacSchedWorkdir").value) || ".";
        var im = parseInt((el("devopsIacSchedInterval") && el("devopsIacSchedInterval").value) || "60", 10) || 60;
        if (!String(command).trim()) {
            alert("Command is required (copy from the Run line).");
            return;
        }
        var body = {
            name: String(name).trim() || "Scheduled job",
            command: String(command).trim(),
            workdir: String(workdir).trim() || ".",
            context: _ctx,
            org_id: _ctx === "org" ? _orgId : null,
            interval_minutes: im
        };
        return fetch("/api/automation-jobs", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
            body: JSON.stringify(body)
        })
            .then(function (r) {
                return r.json().then(function (j) {
                    return { status: r.status, data: j };
                });
            })
            .then(function (o) {
                if (!o.data || !o.data.ok) {
                    alert((o.data && o.data.error) || "Could not create job (login and permissions required).");
                    return;
                }
                _setStatus("Scheduled job: " + (o.data.job && o.data.job.name) + " (Integrations → Automation jobs)");
                _showSchedModal(false);
                alert("Job saved. Manage it under Integrations → Automation jobs (or the Manage Integrations bar).");
            })
            .catch(function (e) {
                alert(e && e.message ? e.message : "Schedule request failed");
            });
    };
})();
