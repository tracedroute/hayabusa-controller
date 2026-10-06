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
    opts = opts || {};
    var headers = Object.assign({}, opts.headers || {});
    if (opts.body && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }
    var res = await fetch(
      path,
      Object.assign({ credentials: "same-origin", headers: headers }, opts)
    );
    var data = await res.json().catch(function () { return {}; });
    if (!res.ok) {
      throw new Error(data.message || data.error || res.statusText || "Request failed");
    }
    return data;
  }

  function escapeHtml(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c];
    });
  }

  function fmtBytes(n) {
    n = Number(n || 0);
    if (!isFinite(n) || n < 0) return "—";
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
    if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + " MB";
    return (n / (1024 * 1024 * 1024)).toFixed(2) + " GB";
  }

  function fmtWhen(iso, epoch) {
    if (iso) {
      try {
        return new Date(iso).toLocaleString();
      } catch (_) {}
    }
    if (epoch) {
      try {
        return new Date(Number(epoch) * 1000).toLocaleString();
      } catch (_) {}
    }
    return "—";
  }

  var canManage = document.body.getAttribute("data-can-manage") === "1";
  var selectedIso = "";
  var lastDisk = null;
  var bankFilter = "all";
  var bankCache = [];
  var deployTarget = "bare_metal";
  var stripCatalog = [];
  var stripPresets = [];
  var stripCategoryOrder = [];
  var stripDefaultIds = [];
  var stripRecommendedIds = [];
  var stripInventoryMeta = {};
  var STRIP_PREFS_KEY = "image-nest-strip-prefs-v3";

  function selectedStripPackages() {
    var host = document.getElementById("nestStripOptions");
    if (!host) return [];
    return Array.prototype.slice
      .call(host.querySelectorAll('input[type="checkbox"][data-strip-id]:checked'))
      .map(function (el) {
        return el.getAttribute("data-strip-id");
      })
      .filter(Boolean);
  }

  // Back-compat alias used by older helpers
  function selectedStripOptionIds() {
    return selectedStripPackages();
  }

  function defaultStripIds() {
    if (stripRecommendedIds.length) return stripRecommendedIds.slice();
    if (stripDefaultIds.length) return stripDefaultIds.slice();
    return stripCatalog
      .filter(function (o) {
        return o.recommended || o.default_enabled !== false;
      })
      .map(function (o) {
        return o.id || o.name;
      });
  }

  function initialStripSelection() {
    var saved = loadStripPrefs();
    var known = {};
    stripCatalog.forEach(function (o) {
      known[o.id || o.name] = true;
    });
    if (!saved) return defaultStripIds().filter(function (id) { return known[id]; });
    if (!saved.customized) return defaultStripIds().filter(function (id) { return known[id]; });
    return (saved.ids || []).filter(function (id) {
      return known[id];
    });
  }

  function updateStripSummary() {
    var countEl = document.getElementById("nestStripCount");
    if (!countEl) return;
    var rec = stripCatalog.filter(function (o) { return o.recommended; }).length;
    countEl.textContent =
      selectedStripPackages().length +
      " of " +
      stripCatalog.length +
      " selected" +
      (rec ? " · " + rec + " recommended" : "");
  }

  function paintStripPresets() {
    var host = document.getElementById("nestStripPresets");
    if (!host) return;
    var presets = stripPresets.length
      ? stripPresets
      : [
          { id: "recommended", label: "Recommended", use_defaults: true, description: "Catalog-matched packages present on this ISO" },
          { id: "all", label: "All packages", option_ids: ["*"], description: "Select every detected package" },
          { id: "none", label: "None", option_ids: [], description: "Clear selection" },
        ];
    host.innerHTML = presets
      .map(function (preset) {
        return (
          '<button type="button" class="nest-strip-preset" data-strip-preset="' +
          escapeHtml(preset.id) +
          '" title="' +
          escapeHtml(preset.description || "") +
          '">' +
          escapeHtml(preset.label || preset.id) +
          "</button>"
        );
      })
      .join("");
    host.querySelectorAll("[data-strip-preset]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var preset = presets.find(function (p) {
          return p.id === btn.getAttribute("data-strip-preset");
        });
        if (preset && preset.id === "none") {
          setStripSelection([]);
        } else {
          setStripSelection(resolvePresetIds(preset));
        }
        host.querySelectorAll(".nest-strip-preset").forEach(function (el) {
          el.classList.toggle("is-active", el === btn);
        });
      });
    });
  }

  function paintStripOptions(options, meta) {
    var host = document.getElementById("nestStripOptions");
    if (!host) return;
    meta = meta || {};
    stripCatalog = (options || []).map(function (opt) {
      var id = opt.id || opt.name;
      return Object.assign({}, opt, { id: id, label: opt.label || opt.name || id });
    });
    if (!stripCatalog.length) {
      host.innerHTML =
        '<p class="nest-strip-empty">' +
        escapeHtml(meta.empty_message || "No packages detected on this ISO.") +
        "</p>";
      updateStripSummary();
      return;
    }
    var selected = {};
    initialStripSelection().forEach(function (id) {
      selected[id] = true;
    });
    var byCat = {};
    stripCatalog.forEach(function (opt) {
      var cat = opt.category || (opt.recommended ? "Recommended" : "Other");
      if (!byCat[cat]) byCat[cat] = [];
      byCat[cat].push(opt);
    });
    var order = (meta.category_order || []).concat(
      Object.keys(byCat).sort(function (a, b) {
        if (a === "Other") return 1;
        if (b === "Other") return -1;
        return a.localeCompare(b);
      })
    ).filter(function (c, i, a) {
      return a.indexOf(c) === i;
    });
    var html = "";
    order.forEach(function (cat) {
      var items = byCat[cat];
      if (!items || !items.length) return;
      var selectedInCat = items.filter(function (o) {
        return selected[o.id];
      }).length;
      html +=
        '<section class="nest-strip-group" data-strip-group="' +
        escapeHtml(cat) +
        '">' +
        '<div class="nest-strip-cat-row"><label class="nest-strip-cat-label">' +
        '<input type="checkbox" data-strip-cat="' +
        escapeHtml(cat) +
        '"' +
        (selectedInCat === items.length ? " checked" : "") +
        " /><span>" +
        escapeHtml(cat) +
        "</span></label>" +
        '<span class="nest-strip-cat-count" data-strip-cat-count="' +
        escapeHtml(cat) +
        '">' +
        selectedInCat +
        " / " +
        items.length +
        "</span></div><div class=\"nest-strip-grid\">";
      items.forEach(function (opt) {
        var descParts = [];
        if (opt.catalog_label) descParts.push(opt.catalog_label);
        if (opt.version) descParts.push(opt.version);
        if (opt.variants && opt.variants.length) {
          descParts.push(opt.variants.length + " variant" + (opt.variants.length === 1 ? "" : "s"));
        }
        if (opt.description) descParts.push(opt.description);
        html +=
          '<label class="nest-strip-option" data-search="' +
          escapeHtml([opt.label, opt.name, opt.category, opt.id, (opt.variants || []).join(" ")].join(" ")) +
          '">' +
          '<input type="checkbox" data-strip-id="' +
          escapeHtml(opt.id) +
          '" data-strip-cat="' +
          escapeHtml(cat) +
          '"' +
          (selected[opt.id] ? " checked" : "") +
          " />" +
          '<span><span class="nest-strip-option-title">' +
          escapeHtml(opt.label || opt.id) +
          "</span>" +
          '<span class="nest-strip-option-desc">' +
          escapeHtml(descParts.join(" · ")) +
          "</span></span></label>";
      });
      html += "</div></section>";
    });
    host.innerHTML = html;
    host.querySelectorAll('input[type="checkbox"][data-strip-id]').forEach(function (el) {
      el.addEventListener("change", function () {
        syncCategoryCheckbox(el.getAttribute("data-strip-cat"));
        updateStripSummary();
        saveStripPrefs(selectedStripPackages());
        var presets = document.getElementById("nestStripPresets");
        if (presets)
          presets.querySelectorAll(".nest-strip-preset").forEach(function (b) {
            b.classList.remove("is-active");
          });
      });
    });
    host.querySelectorAll('input[type="checkbox"][data-strip-cat]').forEach(function (el) {
      el.addEventListener("change", function () {
        var cat = el.getAttribute("data-strip-cat");
        host
          .querySelectorAll('input[type="checkbox"][data-strip-id][data-strip-cat="' + cat + '"]')
          .forEach(function (item) {
            item.checked = el.checked;
          });
        syncCategoryCheckbox(cat);
        updateStripSummary();
        saveStripPrefs(selectedStripPackages());
      });
      syncCategoryCheckbox(el.getAttribute("data-strip-cat"));
    });
    var search = document.getElementById("nestStripSearch");
    applyStripFilter(search && search.value);
    updateStripSummary();
  }

  function formatCapabilities(cap) {
    cap = cap || {};
    var parts = [];
    if (cap.strip_ready) parts.push("Strip ready");
    else if (cap.strip_supported) parts.push("Strip supported (check disk/tools)");
    else if (cap.inventory) parts.push("Inventory only");
    else parts.push("Limited support");
    if (cap.package_manager) parts.push("pkg: " + cap.package_manager);
    if (cap.squashfs_member) parts.push("rootfs: " + cap.squashfs_member);
    if (cap.blockers && cap.blockers.length) parts.push(cap.blockers[0]);
    return parts.join(" · ");
  }

  function paintCapabilityBadge(cap, reasons) {
    var el = document.getElementById("nestCapBadge");
    if (!el) return;
    if (!cap) {
      el.hidden = true;
      return;
    }
    el.hidden = false;
    el.className = "nest-cap-badge" + (cap.strip_ready ? " is-ready" : cap.strip_supported ? " is-warn" : " is-blocked");
    var text = formatCapabilities(cap);
    if (reasons && reasons.length) text += " — " + reasons.slice(0, 2).join("; ");
    el.textContent = text;
  }

  async function loadStripCatalog(opts) {
    if (!canManage) return;
    opts = opts || {};
    var host = document.getElementById("nestStripOptions");
    var isoId = selectedIso || (document.getElementById("nestIsoSelect") || {}).value || "";
    if (!isoId) {
      stripCatalog = [];
      stripRecommendedIds = [];
      if (host) host.innerHTML = '<p class="nest-strip-empty">Select an ISO to inventory packages.</p>';
      updateStripSummary();
      return;
    }
    if (host) {
      host.innerHTML = '<p class="nest-strip-empty">Scanning packages on this ISO…</p>';
    }
    try {
      var q = opts.refresh ? "?refresh=1" : "";
      var data = await api("/api/image-nest/isos/" + encodeURIComponent(isoId) + "/packages" + q);
      if (!data.ok) {
        throw new Error(data.error || data.message || "Inventory failed");
      }
      stripInventoryMeta = data;
      stripRecommendedIds = data.recommended_ids || [];
      stripDefaultIds = stripRecommendedIds.slice();
      stripPresets = [
        {
          id: "recommended",
          label: "Recommended",
          use_defaults: true,
          description: "Packages that match the strip catalog on this ISO",
        },
        { id: "all", label: "All packages", option_ids: ["*"], description: "Select every detected package" },
        { id: "none", label: "None", option_ids: [], description: "Clear selection" },
      ];
      stripCategoryOrder = data.category_order || [];
      paintStripPresets();
      paintStripOptions(data.packages || [], {
        category_order: stripCategoryOrder,
        empty_message: data.error || "No packages detected on this ISO.",
      });
      var sub = document.querySelector(".nest-strip-sub");
      if (sub) {
        var bits = [];
        if (data.platform === "linux") {
          bits.push("Linux packages detected on the ISO");
        } else {
          bits.push("Windows AppX families from install.wim");
        }
        bits.push((data.packages || []).length + " selectable");
        if (data.variant_count) bits.push(data.variant_count + " variants");
        if (data.source) bits.push("source: " + data.source);
        if (data.cached) bits.push("cached");
        sub.textContent = bits.join(" · ") + ". Check packages to remove, then bank.";
      }
      paintCapabilityBadge(data.capabilities, data.detection_reasons);
      updateArtifactHint();
    } catch (err) {
      stripCatalog = [];
      paintCapabilityBadge(null);
      if (host) {
        host.innerHTML =
          '<p class="nest-strip-empty">' + escapeHtml(err.message || "Failed to load packages") + "</p>";
      }
    }
  }

  function paintDisk(disk) {
    disk = disk || {};
    lastDisk = disk;
    var freeEl = document.getElementById("nestFreeDisk");
    var okEl = document.getElementById("nestUploadOk");
    if (freeEl) freeEl.textContent = fmtBytes(disk.free_bytes);
    if (okEl) okEl.textContent = disk.can_accept_upload ? "OK" : "Low";
    var tools = disk.tools || {};
    function tool(id, key) {
      var el = document.getElementById(id);
      if (!el) return;
      el.textContent = tools[key] ? "yes" : "no";
    }
    tool("nestToolWim", "wimlib_imagex");
    tool("nestToolQemu", "qemu_img");
    tool("nestToolVirt", "virt_install");
    var linuxEl = document.getElementById("nestToolLinuxStrip");
    if (linuxEl) {
      linuxEl.textContent = tools.linux_strip_ready ? "yes" : "no";
    }
    tool("nestToolRpm", "rpm");
  }

  var isoCache = [];

  function isoLooksLinux(iso) {
    if (!iso) return false;
    if (String(iso.platform || "").toLowerCase() === "linux") return true;
    if (String(iso.os_family || "").toLowerCase() === "linux") return true;
    var name = String(iso.original_filename || iso.filename || iso.label || "").toLowerCase();
    return /ubuntu|debian|rocky|alma|centos|fedora|rhel|opensuse|archlinux|oracle/.test(name);
  }

  function selectedIsoRow() {
    return (isoCache || []).find(function (i) { return i.id === selectedIso; });
  }

  function outputArtifactForTarget(iso) {
    var linux = isoLooksLinux(iso);
    if (deployTarget === "bare_metal") {
      return {
        type: "iso",
        label: "Bootable ISO",
        field: "source_iso",
        stripBtn: "Strip & bank ISO",
        fullBtn: "Full bank ISO",
        hydrate: linux
          ? "<<IMAGE_NEST:latest-linux-bare-metal-stripped>>"
          : "<<IMAGE_NEST:latest-win11-bare-metal-stripped>>",
      };
    }
    if (deployTarget === "bootable_disk") {
      return {
        type: linux ? "iso+qcow2" : "qcow2",
        label: linux ? "ISO + qcow2 stub" : "Bootable qcow2",
        field: "source_image",
        stripBtn: linux ? "Strip & bank disk pack" : "Strip & bake bootable",
        fullBtn: linux ? "Full bank disk pack" : "Bake bootable disk",
        hydrate: linux
          ? "<<IMAGE_NEST:latest-linux-bootable>>"
          : "<<IMAGE_NEST:latest-win11-bootable>>",
      };
    }
    if (deployTarget === "hyperv") {
      return {
        type: "vhdx",
        label: linux ? "ISO + VHDX stub" : "Hyper-V VHDX",
        field: "source_image",
        stripBtn: "Strip & bank VHDX",
        fullBtn: "Full bank VHDX",
        hydrate: linux
          ? "<<IMAGE_NEST:latest-linux-hyperv>>"
          : "<<IMAGE_NEST:latest-win11-hyperv>>",
      };
    }
    if (deployTarget === "vmware") {
      return {
        type: "vmdk",
        label: linux ? "ISO + VMDK stub" : "VMware VMDK",
        field: "source_image",
        stripBtn: "Strip & bank VMDK",
        fullBtn: "Full bank VMDK",
        hydrate: linux
          ? "<<IMAGE_NEST:latest-linux-vmware>>"
          : "<<IMAGE_NEST:latest-win11-vmware>>",
      };
    }
    if (linux) {
      return {
        type: "iso",
        label: "Bootable ISO",
        field: "source_iso",
        stripBtn: "Strip & bank ISO",
        fullBtn: "Full bank ISO",
        hydrate: "<<IMAGE_NEST:latest-linux-stripped>>",
      };
    }
    return {
      type: "wim",
      label: "install.wim",
      field: "source_image",
      stripBtn: "Strip & bank WIM",
      fullBtn: "Full bank WIM",
      hydrate: "<<IMAGE_NEST:latest-win11-stripped>>",
    };
  }

  function targetLabelFor(t) {
    return (
      {
        bare_metal: "Bare metal",
        hypervisor: "Hypervisor media",
        bootable_disk: "Bootable disk",
        hyperv: "Hyper-V",
        vmware: "VMware",
      }[t] || t
    );
  }

  function updateGuestPanelVisibility() {
    var panel = document.getElementById("nestGuestPanel");
    if (!panel) return;
    var show = ["bootable_disk", "hyperv", "vmware"].indexOf(deployTarget) >= 0;
    panel.hidden = !show;
  }

  function collectUnattend() {
    return {
      hostname: (document.getElementById("nestGuestHostname") || {}).value || "HAYA-NEST",
      username: (document.getElementById("nestGuestUser") || {}).value || "hayabusa",
      password: (document.getElementById("nestGuestPassword") || {}).value || "Hayabusa!ChangeMe",
    };
  }

  function collectDiskGb() {
    var el = document.getElementById("nestGuestDiskGb");
    var n = el ? parseInt(el.value, 10) : 60;
    if (!isFinite(n)) n = 60;
    return Math.max(20, Math.min(200, n));
  }

  function updateArtifactHint() {
    var hint = document.getElementById("nestArtifactHint");
    var stripBtn = document.getElementById("nestStripBtn");
    var fullBtn = document.getElementById("nestFullBtn");
    var foot = document.getElementById("nestBankFoot");
    var iso = selectedIsoRow();
    updateGuestPanelVisibility();
    if (!iso) {
      if (hint) hint.textContent = "Select an ISO to see the output file type for your target.";
      return;
    }
    var art = outputArtifactForTarget(iso);
    var targetLabel = targetLabelFor(deployTarget);
    if (hint) {
      hint.innerHTML =
        "<strong>" +
        escapeHtml(targetLabel) +
        "</strong> will bank <strong>" +
        escapeHtml(art.label) +
        "</strong> (<code>" +
        escapeHtml(art.type) +
        "</code>). Hydrate: <code>" +
        escapeHtml(art.field) +
        "</code> · example <code>" +
        escapeHtml(art.hydrate) +
        "</code>";
    }
    if (stripBtn) stripBtn.textContent = art.stripBtn;
    if (fullBtn) fullBtn.textContent = art.fullBtn;
    if (foot) {
      var feet = {
        bare_metal:
          "Bare metal banks a bootable ISO for ZTP/PXE/USB (Windows and Linux).",
        hypervisor:
          "Hypervisor media: Windows → install.wim (+ empty qcow2 stub); Linux → banked ISO.",
        bootable_disk:
          "Bootable disk: Windows needs virt-install on the controller; Linux banks ISO + qcow2 stub.",
        hyperv:
          "Hyper-V: Windows bootable convert to VHDX; Linux banks ISO + empty VHDX stub.",
        vmware:
          "VMware: Windows bootable convert to VMDK; Linux banks ISO + empty VMDK stub.",
      };
      foot.textContent = feet[deployTarget] || feet.hypervisor;
    }
  }

  function paintIsos(isos) {
    var sel = document.getElementById("nestIsoSelect");
    if (!sel) return;
    isoCache = isos || [];
    var cur = selectedIso || sel.value;
    sel.innerHTML = "";
    if (!isos || !isos.length) {
      var o = document.createElement("option");
      o.value = "";
      o.textContent = "— upload an ISO first —";
      sel.appendChild(o);
      selectedIso = "";
      return;
    }
    isos.forEach(function (iso) {
      var o = document.createElement("option");
      o.value = iso.id;
      var kind = isoLooksLinux(iso) ? "Linux" : "Windows";
      var det = "";
      if (iso.detection_reasons && iso.detection_reasons.length) {
        det = " · " + iso.detection_reasons[0];
      } else if (iso.platform) {
        det = " · " + String(iso.platform) + (iso.distro ? "/" + iso.distro : "");
      }
      o.textContent =
        (iso.original_filename || iso.filename || iso.id) +
        " · " +
        kind +
        det +
        " · " +
        fmtBytes(iso.bytes) +
        (iso.base_manifest ? " · manifest" : "");
      sel.appendChild(o);
    });
    if (cur && isos.some(function (i) { return i.id === cur; })) {
      sel.value = cur;
      selectedIso = cur;
    } else {
      sel.value = isos[0].id;
      selectedIso = isos[0].id;
    }
    loadStripCatalog();
    updateArtifactHint();
  }

  function paintBank(images) {
    bankCache = images || [];
    var body = document.getElementById("nestBankBody");
    if (!body) return;
    var filtered = bankCache.filter(function (img) {
      if (bankFilter === "all") return true;
      return String(img.deploy_target || "") === bankFilter;
    });
    if (!filtered.length) {
      body.innerHTML =
        '<tr><td colspan="9" class="empty">' +
        (bankCache.length ? "No entries for this target filter" : "No banked images yet") +
        "</td></tr>";
      return;
    }
    body.innerHTML = filtered
      .map(function (img) {
        var status = String(img.status || "");
        var target = String(img.deploy_target || "hypervisor");
        var pill =
          status === "ready" ||
          status === "ready_disk_stub" ||
          status === "ready_iso" ||
          status.indexOf("ready_iso") === 0 ||
          status === "cataloged" ||
          status.indexOf("ready_wim") === 0
            ? "ok"
            : status === "failed"
              ? "err"
              : "idle";
        var actions = "";
        if (img.base_manifest) {
          actions +=
            '<button type="button" class="btn btn-ghost nest-manifest-btn" data-name="' +
            escapeHtml(img.base_manifest) +
            '">Base manifest</button> ';
        }
        if (img.deploy_manifest) {
          actions +=
            '<button type="button" class="btn btn-ghost nest-manifest-btn" data-name="' +
            escapeHtml(img.deploy_manifest) +
            '">Deployed</button> ';
        }
        if (
          canManage &&
          (target === "hypervisor" ||
            target === "bootable_disk" ||
            target === "hyperv" ||
            target === "vmware") &&
          (status === "ready" ||
            status === "ready_disk_stub" ||
            status.indexOf("ready") === 0 ||
            status === "cataloged")
        ) {
          actions +=
            '<button type="button" class="btn btn-secondary nest-tofu-btn" data-id="' +
            escapeHtml(img.id) +
            '" data-name="' +
            escapeHtml(img.name || "") +
            '">Hayabusa hand-off</button> ';
        }
        var hasDisk =
          !!(img.qcow2_path || img.disk_path || img.vhdx_path || img.vmdk_path) &&
          status.indexOf("ready") === 0;
        if (canManage && hasDisk) {
          if (!img.vhdx_path) {
            actions +=
              '<button type="button" class="btn btn-ghost nest-convert-btn" data-id="' +
              escapeHtml(img.id) +
              '" data-format="vhdx">→ VHDX</button> ';
          }
          if (!img.vmdk_path) {
            actions +=
              '<button type="button" class="btn btn-ghost nest-convert-btn" data-id="' +
              escapeHtml(img.id) +
              '" data-format="vmdk">→ VMDK</button> ';
          }
          if (!String(img.qcow2_path || "").endsWith(".qcow2") && img.disk_path) {
            actions +=
              '<button type="button" class="btn btn-ghost nest-convert-btn" data-id="' +
              escapeHtml(img.id) +
              '" data-format="qcow2">→ qcow2</button> ';
          }
        }
        if (canManage) {
          actions +=
            '<button type="button" class="btn btn-ghost nest-del-btn" data-id="' +
            escapeHtml(img.id) +
            '">Delete</button>';
        }
        var pillClass =
          target === "bare_metal"
            ? "bare"
            : target === "bootable_disk"
              ? "boot"
              : target === "hyperv"
                ? "hyperv"
                : target === "vmware"
                  ? "vmware"
                  : "hyper";
        var targetPill =
          '<span class="nest-target-pill ' +
          pillClass +
          '">' +
          escapeHtml(img.deploy_target_label || targetLabelFor(target)) +
          "</span>";
        return (
          "<tr data-deploy-target=\"" +
          escapeHtml(target) +
          "\">" +
          "<td><code>" +
          escapeHtml(img.name || img.id) +
          "</code></td>" +
          "<td>" +
          escapeHtml(img.os_family_label || img.os_family || "Windows") +
          "</td>" +
          "<td>" +
          targetPill +
          "</td>" +
          "<td><code>." +
          escapeHtml(img.artifact_type || (target === "bare_metal" || String(img.platform) === "linux" ? "iso" : "wim")) +
          "</code> " +
          escapeHtml(img.artifact_label || "") +
          "</td>" +
          "<td>" +
          escapeHtml(img.flavor || "—") +
          (img.strip_removed_count
            ? " <span class='muted'>(" + escapeHtml(String(img.strip_removed_count)) + " removed)</span>"
            : "") +
          "</td>" +
          "<td>" +
          escapeHtml(fmtWhen(img.created_at_iso, img.created_at)) +
          "</td>" +
          "<td class='muted'>" +
          escapeHtml(img.applies_to || img.core_manifest || "—") +
          (img.hydrate_placeholder
            ? '<code class="nest-hydrate-code">' + escapeHtml(img.hydrate_placeholder) + "</code>"
            : "") +
          (img.registry_ref
            ? "<br><code class='muted'>ref: " + escapeHtml(img.registry_ref) + "</code>"
            : "") +
          "</td>" +
          '<td><span class="pill pill-' +
          pill +
          '">' +
          escapeHtml(status || "—") +
          "</span></td>" +
          "<td class='nest-actions'>" +
          actions +
          "</td>" +
          "</tr>"
        );
      })
      .join("");

    body.querySelectorAll(".nest-manifest-btn").forEach(function (btn) {
      btn.addEventListener("click", function () {
        loadManifest(btn.getAttribute("data-name"));
      });
    });
    body.querySelectorAll(".nest-tofu-btn").forEach(function (btn) {
      btn.addEventListener("click", async function () {
        var id = btn.getAttribute("data-id");
        var def = (btn.getAttribute("data-name") || "desktop").replace(/[^A-Za-z0-9._-]+/g, "-");
        var name = window.prompt("Target VM name for Hayabusa hand-off (tfvars only; no tofu on controller)", def);
        if (!name) return;
        try {
          var res = await api("/api/image-nest/bank/" + encodeURIComponent(id) + "/tofu-handoff", {
            method: "POST",
            body: JSON.stringify({ target_vm_name: name }),
          });
          toast("Wrote hand-off " + (res.path || "tfvars") + " (apply from Hayabusa)", "ok");
          var view = document.getElementById("nestManifestView");
          if (view) view.textContent = res.content || JSON.stringify(res, null, 2);
        } catch (err) {
          toast(err.message || "Hand-off failed", "err");
        }
      });
    });
    body.querySelectorAll(".nest-convert-btn").forEach(function (btn) {
      btn.addEventListener("click", async function () {
        var id = btn.getAttribute("data-id");
        var fmt = btn.getAttribute("data-format") || "vhdx";
        if (!window.confirm("Convert this banked disk to " + fmt + "?")) return;
        try {
          var res = await api("/api/image-nest/bank/" + encodeURIComponent(id) + "/convert", {
            method: "POST",
            body: JSON.stringify({ format: fmt }),
          });
          toast("Converted → " + ((res.image && res.image.name) || fmt), "ok");
          await refresh();
        } catch (err) {
          toast(err.message || "Convert failed", "err");
        }
      });
    });
    body.querySelectorAll(".nest-del-btn").forEach(function (btn) {
      btn.addEventListener("click", async function () {
        if (!window.confirm("Delete this bank entry and its local artifacts?")) return;
        try {
          await api("/api/image-nest/bank/" + encodeURIComponent(btn.getAttribute("data-id")) + "/delete", {
            method: "POST",
            body: "{}",
          });
          toast("Deleted", "ok");
          await refresh();
        } catch (err) {
          toast(err.message || "Delete failed", "err");
        }
      });
    });
  }

  function paintJobs(jobs) {
    var list = document.getElementById("nestJobsList");
    if (!list) return;
    if (!jobs || !jobs.length) {
      list.innerHTML = '<li class="empty">No bake jobs yet</li>';
      return;
    }
    list.innerHTML = jobs
      .map(function (j) {
        var log = (j.log || []).slice(-4).join("\n");
        return (
          '<li><div><strong>' +
          escapeHtml(j.flavor || "job") +
          "</strong> · " +
          escapeHtml(j.status || "") +
          " · <code>" +
          escapeHtml((j.id || "").slice(0, 10)) +
          "…</code></div>" +
          (j.error ? '<div class="muted">error: ' + escapeHtml(j.error) + "</div>" : "") +
          (log
            ? '<pre class="nest-job-log">' + escapeHtml(log) + "</pre>"
            : "") +
          "</li>"
        );
      })
      .join("");
  }

  async function loadManifest(name) {
    var view = document.getElementById("nestManifestView");
    if (!view || !name) return;
    view.textContent = "Loading " + name + "…";
    try {
      var data = await api("/api/image-nest/manifest/" + encodeURIComponent(name));
      view.textContent = data.content || "(empty)";
    } catch (err) {
      view.textContent = err.message || "Failed to load manifest";
    }
  }

  function paintRegistry(reg) {
    var view = document.getElementById("nestRegistryView");
    if (!view) return;
    reg = reg || {};
    var lines = [];
    lines.push("repo_root: " + (reg.repo_root || "—"));
    lines.push("playbook_refs_dir: " + (reg.playbook_refs_dir || "—"));
    lines.push("");
    lines.push("aliases:");
    var aliases = reg.aliases || {};
    Object.keys(aliases).forEach(function (k) {
      lines.push("  " + k + " -> " + aliases[k]);
    });
    lines.push("");
    lines.push("refs:");
    (reg.refs || []).forEach(function (r) {
      lines.push(
        "  " +
          (r.ref || r.label || "?") +
          "  type=" +
          (r.type || "—") +
          "  path=" +
          (r.path || r.iso_path || "—")
      );
      if (r.playbook_vars_file) lines.push("    vars: " + r.playbook_vars_file);
    });
    lines.push("");
    lines.push("bare metal (client):");
    lines.push('  <<IMAGE_NEST:latest-win11-bare-metal>>');
    lines.push("bare metal (server):");
    lines.push('  <<IMAGE_NEST:latest-winserver-bare-metal>>');
    lines.push("hypervisor strip (client / server):");
    lines.push('  <<IMAGE_NEST:latest-win11-stripped>>');
    lines.push('  <<IMAGE_NEST:latest-winserver-stripped>>');
    lines.push("generic latest:");
    lines.push('  <<IMAGE_NEST:latest-windows-stripped>>');
    lines.push("");
    lines.push("placeholders (hydrate on LAN approve):");
    lines.push('  OpenTofu: source_image = "<<IMAGE_NEST:latest-win11-stripped>>"');
    lines.push('  Ansible:  "{{ lookup(\'env\', \'HAYABUSA_IMAGE_NEST_LATEST_WIN11_STRIPPED\') }}"');
    lines.push("  field:    <<IMAGE_NEST:latest-win11-iso:source_iso>>");
    lines.push("");
    lines.push("ansible:  -e @.../playbook-refs/latest-win11-iso.vars.json");
    lines.push("vm image: -e @.../playbook-refs/latest-win11-full.vars.json");
    view.textContent = lines.join("\n") || "(empty registry)";
  }

  function setDeployTarget(target) {
    var allowed = {
      bare_metal: 1,
      hypervisor: 1,
      bootable_disk: 1,
      hyperv: 1,
      vmware: 1,
    };
    deployTarget = allowed[target] ? target : "bare_metal";
    document.querySelectorAll("#nestTargetPanel .nest-target-card").forEach(function (card) {
      var on = card.getAttribute("data-target") === deployTarget;
      card.classList.toggle("is-active", on);
      card.setAttribute("aria-pressed", on ? "true" : "false");
    });
    loadStripCatalog();
    updateArtifactHint();
  }

  async function publishBareMetal() {
    if (!canManage) return;
    var sel = document.getElementById("nestIsoSelect");
    var isoId = (sel && sel.value) || selectedIso;
    if (!isoId) {
      toast("Upload and select an ISO first", "err");
      return;
    }
    try {
      var res = await api("/api/image-nest/publish-bare-metal", {
        method: "POST",
        body: JSON.stringify({ iso_id: isoId }),
      });
      toast("Published ISO as-is · " + ((res.image && res.image.name) || "ok"), "ok");
      bankFilter = "bare_metal";
      document.querySelectorAll("#nestBankFilters .nest-filter-chip").forEach(function (chip) {
        chip.classList.toggle("is-active", chip.getAttribute("data-filter") === "bare_metal");
      });
      await refresh();
    } catch (err) {
      toast(err.message || "Publish failed", "err");
    }
  }

  function loadStripPrefs() {
    try {
      var raw = localStorage.getItem(STRIP_PREFS_KEY);
      if (!raw) return null;
      var parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return { customized: true, ids: parsed };
      if (parsed && Array.isArray(parsed.ids)) {
        return { customized: !!parsed.customized, ids: parsed.ids };
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  function saveStripPrefs(ids) {
    try {
      localStorage.setItem(
        STRIP_PREFS_KEY,
        JSON.stringify({ customized: true, ids: ids || [] })
      );
    } catch (_) {}
  }

  function setStripSelection(ids) {
    var wanted = {};
    (ids || []).forEach(function (id) {
      wanted[id] = true;
    });
    var host = document.getElementById("nestStripOptions");
    if (!host) return;
    host.querySelectorAll('input[type="checkbox"][data-strip-id]').forEach(function (el) {
      el.checked = !!wanted[el.getAttribute("data-strip-id")];
    });
    host.querySelectorAll('input[type="checkbox"][data-strip-cat]:not([data-strip-id])').forEach(function (el) {
      syncCategoryCheckbox(el.getAttribute("data-strip-cat"));
    });
    updateStripSummary();
    saveStripPrefs(selectedStripPackages());
  }

  function syncCategoryCheckbox(category) {
    var host = document.getElementById("nestStripOptions");
    if (!host || !category) return;
    var boxes = host.querySelectorAll(
      'input[type="checkbox"][data-strip-cat="' + category + '"]:not([data-strip-id])'
    );
    var items = host.querySelectorAll(
      'input[type="checkbox"][data-strip-id][data-strip-cat="' + category + '"]'
    );
    var checked = 0;
    items.forEach(function (el) {
      if (el.checked) checked += 1;
    });
    boxes.forEach(function (el) {
      el.indeterminate = checked > 0 && checked < items.length;
      el.checked = items.length > 0 && checked === items.length;
    });
    var countEl = host.querySelector('[data-strip-cat-count="' + category + '"]');
    if (countEl) countEl.textContent = checked + " / " + items.length;
  }

  function applyStripFilter(query) {
    var host = document.getElementById("nestStripOptions");
    if (!host) return;
    var q = String(query || "").trim().toLowerCase();
    host.querySelectorAll(".nest-strip-option").forEach(function (row) {
      row.classList.toggle("is-hidden", q && row.getAttribute("data-search").toLowerCase().indexOf(q) < 0);
    });
    host.querySelectorAll(".nest-strip-group").forEach(function (group) {
      var visible = group.querySelectorAll(".nest-strip-option:not(.is-hidden)").length;
      group.classList.toggle("is-hidden", q && visible === 0);
    });
  }

  function resolvePresetIds(preset) {
    if (!preset) return [];
    if (preset.use_defaults) return defaultStripIds();
    if (preset.option_ids && preset.option_ids.length === 1 && preset.option_ids[0] === "*") {
      return stripCatalog.map(function (o) { return o.id; });
    }
    if (preset.option_ids && preset.option_ids.length) {
      var known = {};
      stripCatalog.forEach(function (o) { known[o.id] = true; });
      return preset.option_ids.filter(function (id) { return known[id]; });
    }
    if (preset.categories && preset.categories.length) {
      var cats = {};
      preset.categories.forEach(function (c) { cats[c] = true; });
      return stripCatalog.filter(function (o) { return cats[o.category]; }).map(function (o) { return o.id; });
    }
    return [];
  }

  function setAllStripOptions(on) {
    setStripSelection(on ? stripCatalog.map(function (o) { return o.id; }) : []);
  }

  function setDefaultStripOptions() {
    setStripSelection(defaultStripIds());
    var presets = document.getElementById("nestStripPresets");
    if (presets) {
      presets.querySelectorAll(".nest-strip-preset").forEach(function (b) {
        b.classList.toggle("is-active", b.getAttribute("data-strip-preset") === "recommended");
      });
    }
  }

  async function refresh() {
    try {
      var data = await api("/api/image-nest/bank");
      paintDisk(data.disk || {});
      paintIsos(data.isos || []);
      paintBank(data.images || []);
      paintJobs(data.jobs || []);
      paintRegistry(data.registry || {});
    } catch (err) {
      toast(err.message || "Refresh failed", "err");
    }
  }

  async function startBuild(flavor) {
    if (!canManage) return;
    var sel = document.getElementById("nestIsoSelect");
    var isoId = (sel && sel.value) || selectedIso;
    if (!isoId) {
      toast("Upload and select an ISO first", "err");
      return;
    }
    if (flavor === "stripped") {
      var chosen = selectedStripPackages();
      if (!chosen.length) {
        if (!window.confirm("No packages selected. Bank without removing any packages?")) {
          return;
        }
      }
    }
    try {
      var payload = {
        iso_id: isoId,
        flavor: flavor,
        deploy_target: deployTarget,
        disk_gb: collectDiskGb(),
      };
      if (flavor === "stripped") {
        payload.strip_packages = selectedStripPackages();
      }
      if (["bootable_disk", "hyperv", "vmware"].indexOf(deployTarget) >= 0) {
        payload.unattend = collectUnattend();
      }
      var res = await api("/api/image-nest/build", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      var art = outputArtifactForTarget(selectedIsoRow());
      toast(
        (flavor === "stripped" ? "Strip & bank" : "Full bank") +
          " queued · " +
          ((res.image && res.image.name) || "job started") +
          (art ? " → ." + art.type : ""),
        "ok"
      );
      bankFilter = deployTarget;
      document.querySelectorAll("#nestBankFilters .nest-filter-chip").forEach(function (chip) {
        chip.classList.toggle("is-active", chip.getAttribute("data-filter") === deployTarget);
      });
      await refresh();
      pollJob(res.job && res.job.id);
    } catch (err) {
      toast(err.message || "Build failed to start", "err");
    }
  }

  function pollJob(jobId) {
    if (!jobId) return;
    var tries = 0;
    function tick() {
      tries += 1;
      api("/api/image-nest/jobs/" + encodeURIComponent(jobId))
        .then(function (data) {
          var st = (data.job && data.job.status) || "";
          if (st === "completed" || st === "failed") {
            refresh();
            toast("Bake " + st, st === "failed" ? "err" : "ok");
            return;
          }
          if (tries < 120) {
            setTimeout(tick, 3000);
          }
          refresh();
        })
        .catch(function () {
          if (tries < 40) setTimeout(tick, 4000);
        });
    }
    setTimeout(tick, 2000);
  }

  async function uploadFile(file) {
    if (!canManage || !file) return;
    var status = document.getElementById("nestUploadStatus");
    var prog = document.getElementById("nestProgress");
    var bar = document.getElementById("nestProgressBar");
    var reserve = (lastDisk && lastDisk.min_free_after_upload_bytes) || 1024 * 1024 * 1024;
    var free = (lastDisk && lastDisk.free_bytes) || 0;
    var need = (file.size || 0) + reserve;
    if (file.size > 0 && free > 0 && need > free) {
      var msg =
        "Need " +
        fmtBytes(need) +
        " (" +
        fmtBytes(file.size) +
        " ISO + " +
        fmtBytes(reserve) +
        " reserve); controller has " +
        fmtBytes(free) +
        " free";
      if (status) status.textContent = msg;
      toast(msg, "err");
      return;
    }
    if (status) status.textContent = "Uploading " + file.name + " (" + fmtBytes(file.size) + ")…";
    if (prog) prog.hidden = false;
    if (bar) bar.style.width = "2%";

    var fd = new FormData();
    fd.append("file", file, file.name);

    try {
      var data = await new Promise(function (resolve, reject) {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "/api/image-nest/upload");
        xhr.withCredentials = true;
        if (file.size > 0) {
          xhr.setRequestHeader("X-Expected-Upload-Bytes", String(file.size));
        }
        xhr.upload.onprogress = function (e) {
          var total = e.lengthComputable ? e.total : file.size;
          var loaded = e.loaded || 0;
          if (bar && total > 0) {
            bar.style.width = Math.max(2, Math.min(99, Math.round((loaded / total) * 100))) + "%";
          }
          if (status) {
            status.textContent =
              "Uploading " +
              file.name +
              " · " +
              fmtBytes(loaded) +
              (total ? " / " + fmtBytes(total) : "");
          }
        };
        xhr.onload = function () {
          var parsed = {};
          try {
            parsed = JSON.parse(xhr.responseText || "{}");
          } catch (_) {}
          if (xhr.status >= 200 && xhr.status < 300 && parsed.ok) {
            resolve(parsed);
            return;
          }
          var msg =
            parsed.error ||
            parsed.message ||
            (xhr.status ? "HTTP " + xhr.status : "Upload failed");
          if (parsed.code === "disk_full" && parsed.disk && parsed.disk.free_bytes != null) {
            msg += " (" + fmtBytes(parsed.disk.free_bytes) + " free on controller)";
          }
          reject(new Error(msg));
        };
        xhr.onerror = function () {
          reject(new Error("Network error during upload"));
        };
        xhr.onabort = function () {
          reject(new Error("Upload cancelled"));
        };
        xhr.send(fd);
      });
      if (bar) bar.style.width = "100%";
      if (status) {
        status.textContent =
          "Uploaded · sha256 " +
          ((data.iso && data.iso.sha256) || "").slice(0, 16) +
          "…" +
          (data.manifest_pending ? " · manifest building…" : "");
      }
      selectedIso = data.iso && data.iso.id;
      toast("ISO stored on controller", "ok");
      await refresh();
    } catch (err) {
      if (status) status.textContent = err.message || "Upload failed";
      if (bar) bar.style.width = "0%";
      toast(err.message || "Upload failed", "err");
    } finally {
      setTimeout(function () {
        if (prog && bar && bar.style.width === "100%") {
          prog.hidden = true;
          bar.style.width = "0%";
        }
      }, 2500);
    }
  }

  var drop = document.getElementById("nestDrop");
  var input = document.getElementById("nestFileInput");
  if (drop && input && canManage) {
    drop.addEventListener("click", function () {
      input.click();
    });
    drop.addEventListener("dragover", function (e) {
      e.preventDefault();
      drop.classList.add("is-drag");
    });
    drop.addEventListener("dragleave", function () {
      drop.classList.remove("is-drag");
    });
    drop.addEventListener("drop", function (e) {
      e.preventDefault();
      drop.classList.remove("is-drag");
      var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
      if (f) uploadFile(f);
    });
    input.addEventListener("change", function () {
      if (input.files && input.files[0]) uploadFile(input.files[0]);
      input.value = "";
    });
  }

  var isoSel = document.getElementById("nestIsoSelect");
  if (isoSel) {
    isoSel.addEventListener("change", function () {
      selectedIso = isoSel.value;
      loadStripCatalog();
      updateArtifactHint();
    });
  }

  var stripBtn = document.getElementById("nestStripBtn");
  var fullBtn = document.getElementById("nestFullBtn");
  var stripAllBtn = document.getElementById("nestStripAllBtn");
  var stripNoneBtn = document.getElementById("nestStripNoneBtn");
  var stripDefaultsBtn = document.getElementById("nestStripDefaultsBtn");
  var stripRefreshBtn = document.getElementById("nestStripRefreshBtn");
  var stripSearch = document.getElementById("nestStripSearch");
  var publishIsoBtn = document.getElementById("nestPublishIsoBtn");
  if (stripBtn) stripBtn.addEventListener("click", function () { startBuild("stripped"); });
  if (fullBtn) fullBtn.addEventListener("click", function () { startBuild("full"); });
  if (publishIsoBtn) publishIsoBtn.addEventListener("click", publishBareMetal);
  document.querySelectorAll("#nestTargetPanel .nest-target-card").forEach(function (card) {
    card.addEventListener("click", function () {
      setDeployTarget(card.getAttribute("data-target") || "bare_metal");
    });
  });
  if (stripAllBtn) stripAllBtn.addEventListener("click", function () { setAllStripOptions(true); });
  if (stripNoneBtn) stripNoneBtn.addEventListener("click", function () { setAllStripOptions(false); });
  if (stripDefaultsBtn) stripDefaultsBtn.addEventListener("click", setDefaultStripOptions);
  if (stripRefreshBtn) {
    stripRefreshBtn.addEventListener("click", function () {
      loadStripCatalog({ refresh: true });
    });
  }
  if (stripSearch) {
    stripSearch.addEventListener("input", function () {
      applyStripFilter(stripSearch.value);
    });
  }
  document.querySelectorAll("#nestBankFilters .nest-filter-chip").forEach(function (chip) {
    chip.addEventListener("click", function () {
      bankFilter = chip.getAttribute("data-filter") || "all";
      document.querySelectorAll("#nestBankFilters .nest-filter-chip").forEach(function (c) {
        c.classList.toggle("is-active", c === chip);
      });
      paintBank(bankCache);
    });
  });
  setDeployTarget("bare_metal");

  var refreshBtn = document.getElementById("nestRefreshBtn");
  if (refreshBtn) refreshBtn.addEventListener("click", refresh);

  loadStripCatalog();
  refresh();
  setInterval(refresh, 15000);
})();
