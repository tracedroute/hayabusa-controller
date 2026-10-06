(() => {
  "use strict";

  const SCRIPT =
    document.currentScript ||
    document.querySelector("script[data-tr-orders-origin]") ||
    document.querySelector('script[src*="blade.js"]');
  const ATTR = (name) => (SCRIPT && SCRIPT.getAttribute(name)) || "";
  const ORDERS = ATTR("data-tr-orders-origin") || window.__TR_ORDERS_ORIGIN || "";
  const STORAGE_KEY = "tr-ecosystem-blade-mode-v3";
  const LEGACY_STORAGE_KEY = "tr-ecosystem-blade-mode";
  const LEGACY_OPEN_KEY = "tr-ecosystem-blade-open";
  const MODES = ["open", "icons", "peek"];
  const SESSION_TIMEOUT_MS = 1200;
  const DEFAULT_MODE = "peek";

  const ICONS = {
    hayabusa:
      '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 14c3-1 5-4 7-8 1 3 3 5 6 6-2 1-3 3-3 6"/><path d="M11 6c2 .5 4 0 6-2"/><path d="M9 12c2 1 3 3 3 5"/></svg>',
    orders:
      '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 7V6a5 5 0 0 1 10 0v1"/><path d="M6 7h12l-1 13H7L6 7z"/><path d="M10 11v4M14 11v4"/></svg>',
    support:
      '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 12a8 8 0 0 1 16 0"/><path d="M4 12v3a2 2 0 0 0 2 2h1v-5H6a2 2 0 0 0-2 2z"/><path d="M20 12v3a2 2 0 0 1-2 2h-1v-5h1a2 2 0 0 1 2 2z"/><path d="M12 19v2M9 21h6"/></svg>',
    website:
      '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 0 1 0 18"/><path d="M12 3a14 14 0 0 0 0 18"/></svg>',
    billing:
      '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="6" width="18" height="12" rx="2"/><path d="M3 10h18"/><path d="M7 15h3"/></svg>',
    donations:
      '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>',
    staff:
      '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3l2.2 4.4L19 8.2l-3.5 3.4.8 4.7L12 14.2 7.7 16.3l.8-4.7L5 8.2l4.8-.8L12 3z"/><path d="M8 19h8"/><path d="M12 14.2V19"/></svg>',
    inbox:
      '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 6h16v12H4z"/><path d="M4 10h5l1.5 2h3L15 10h5"/><path d="M4 6l8 5 8-5"/></svg>',
  };

  function lanHost() {
    const h = (location.hostname || "").trim();
    if (h && h !== "localhost" && h !== "127.0.0.1") return h;
    return "10.0.0.85";
  }

  function portUrl(port, path) {
    const p = path || "/";
    return "http://" + lanHost() + ":" + port + (p.startsWith("/") ? p : "/" + p);
  }

  function ordersOrigin() {
    const raw = String(ORDERS || "").trim().replace(/\/$/, "");
    if (raw) return raw;
    if (/8091|orders|service\.tracedroute/i.test(location.host)) return location.origin;
    // Same-origin Orders pages often leave data-tr-orders-origin empty.
    if (location.pathname.indexOf("/support") === 0 || location.pathname.indexOf("/staff") === 0) {
      return location.origin;
    }
    if (document.querySelector('script[src*="/ecosystem/blade.js"]')) {
      try {
        const src = document.querySelector('script[src*="/ecosystem/blade.js"]').getAttribute("src") || "";
        if (src.startsWith("/") || src.indexOf(location.origin) === 0) return location.origin;
      } catch (_) {}
    }
    return "https://service.tracedroute.net";
  }

  function localSignedIn() {
    const body = document.body;
    if (!body) return false;
    if (body.getAttribute("data-tr-session") === "1") return true;
    if (body.getAttribute("data-peregrine-session-user")) return true;
    if (body.dataset.customerAuthenticated === "true") return true;
    if (window.__TR_SIGNED_IN__ === true) return true;
    if (window.__peregrineSessionUser) return true;
    const stage = document.getElementById("order");
    if (stage && stage.dataset.customerAuthenticated === "true") return true;
    if (body.classList.contains("is-authenticated") || body.classList.contains("logged-in")) {
      return true;
    }
    if (document.querySelector('a[href="/logout"], a[href*="/logout"]')) return true;
    return false;
  }

  async function fetchJson(path, timeoutMs) {
    const base = ordersOrigin();
    if (!base) return null;
    const ctrl = typeof AbortController !== "undefined" ? new AbortController() : null;
    const timer =
      ctrl && timeoutMs
        ? setTimeout(() => {
            try {
              ctrl.abort();
            } catch (_) {}
          }, timeoutMs)
        : null;
    try {
      const res = await fetch(base + path, {
        credentials: "include",
        mode: "cors",
        signal: ctrl ? ctrl.signal : undefined,
      });
      if (!res.ok) return null;
      return await res.json();
    } catch (_) {
      return null;
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  function ensureCss() {
    if (document.querySelector('link[data-tr-blade-css="1"]')) return;
    const link = document.createElement("link");
    link.rel = "stylesheet";
    const src = (SCRIPT && SCRIPT.getAttribute("src")) || "";
    if (src.indexOf("/static/ecosystem/blade") !== -1 || src.indexOf("/ecosystem/blade") !== -1) {
      if (src.indexOf("/static/ecosystem/") !== -1) {
        link.href = "/static/ecosystem/blade.css?v=20260926f";
      } else {
        const origin = ordersOrigin();
        if (!origin) return;
        link.href = origin + "/ecosystem/blade.css?v=20260926f";
      }
    } else {
      link.href = "/static/ecosystem/blade.css?v=20260926f";
    }
    link.setAttribute("data-tr-blade-css", "1");
    document.head.appendChild(link);
  }

  function setBadge(el, count) {
    let badge = el.querySelector(".tr-blade__badge");
    const n = Number(count) || 0;
    if (n <= 0) {
      if (badge) badge.remove();
      return;
    }
    if (!badge) {
      badge = document.createElement("span");
      badge.className = "tr-blade__badge";
      badge.setAttribute("aria-label", n + " notifications");
      el.appendChild(badge);
    }
    badge.textContent = n > 99 ? "99+" : String(n);
  }

  function defaultServices(origin) {
    const hayabusa = ATTR("data-tr-hayabusa-url") || portUrl(8086);
    const website = ATTR("data-tr-website-url") || "https://tracedroute.net";
    const orders = (ATTR("data-tr-orders-url") || origin || "https://service.tracedroute.net").replace(/\/$/, "");
    const support = ATTR("data-tr-support-url") || "https://service.tracedroute.net/support/";
    const staff = ATTR("data-tr-staff-url") || "https://service.tracedroute.net/staff/login";
    return [
      { id: "hayabusa", name: "Hayabusa", url: hayabusa },
      { id: "orders", name: "Orders", url: orders + "/" },
      { id: "support", name: "Support", url: support },
      { id: "website", name: "Website", url: website },
      { id: "donations", name: "Donations", url: "https://service.tracedroute.net", pin: true },
      { id: "billing", name: "Billing", url: orders + "/account/invoices", pin: true },
      { id: "staff", name: "Staff", url: staff, pin: true },
    ];
  }

  function normalizeServices(list, origin) {
    const base = defaultServices(origin);
    const byId = {};
    base.forEach((s) => {
      byId[s.id] = Object.assign({}, s);
    });
    (Array.isArray(list) ? list : []).forEach((s) => {
      if (!s || !s.id || s.id === "management") return;
      const cur = byId[s.id] || { id: s.id, name: s.name || s.id, url: s.url, pin: !!s.pin };
      if (s.name) cur.name = s.name;
      // Keep canonical public URLs for these destinations.
      if (s.id === "orders") cur.url = byId.orders.url;
      else if (s.id === "support") cur.url = byId.support.url;
      else if (s.id === "website") cur.url = byId.website.url;
      else if (s.id === "staff") cur.url = byId.staff.url;
      else if (s.id === "billing") cur.url = byId.billing.url;
      else if (s.id === "donations") cur.url = byId.donations.url;
      else if (s.url) cur.url = s.url;
      if (s.pin) cur.pin = true;
      byId[s.id] = cur;
    });
    const order = ["hayabusa", "orders", "support", "website", "donations", "billing", "staff"];
    const out = [];
    order.forEach((id) => {
      if (byId[id]) out.push(byId[id]);
    });
    Object.keys(byId).forEach((id) => {
      if (order.indexOf(id) === -1) out.push(byId[id]);
    });
    return out;
  }

  function iconMarkup(id) {
    return ICONS[id] || ICONS.website;
  }

  function normalizeMode(raw) {
    const v = String(raw || "").trim().toLowerCase();
    if (MODES.indexOf(v) !== -1) return v;
    if (v === "1" || v === "true") return "open";
    if (v === "0" || v === "false") return "peek";
    return DEFAULT_MODE;
  }

  function preferMode() {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored != null && stored !== "") {
        return normalizeMode(stored);
      }
      // Migrate older keys, but do not keep a one-time auto-"open" as permanent default.
      const legacy = localStorage.getItem(LEGACY_STORAGE_KEY);
      if (legacy != null && legacy !== "") {
        const mode = normalizeMode(legacy);
        localStorage.setItem(STORAGE_KEY, mode === "open" ? DEFAULT_MODE : mode);
        return mode === "open" ? DEFAULT_MODE : mode;
      }
      const legacyOpen = localStorage.getItem(LEGACY_OPEN_KEY);
      if (legacyOpen != null && legacyOpen !== "") {
        const mode = normalizeMode(legacyOpen);
        localStorage.setItem(STORAGE_KEY, mode === "open" ? DEFAULT_MODE : mode);
        return mode === "open" ? DEFAULT_MODE : mode;
      }
      localStorage.setItem(STORAGE_KEY, DEFAULT_MODE);
    } catch (_) {}
    return DEFAULT_MODE;
  }

  function nextMode(mode) {
    // Cycle: open → icons → peek → open
    // (from peek: 1 click icons, 2 clicks open)
    if (mode === "open") return "icons";
    if (mode === "icons") return "peek";
    return "open";
  }

  function applyModeClasses(root, mode) {
    root.classList.toggle("is-open", mode === "open");
    root.classList.toggle("is-peek", mode === "peek");
    root.dataset.mode = mode;
    document.documentElement.classList.toggle("tr-blade-open", mode === "open");
    document.documentElement.classList.toggle("tr-blade-peek", mode === "peek");
  }

  function renderBlade(services, mode, origin) {
    mode = normalizeMode(mode);
    ensureCss();
    document.documentElement.classList.add("tr-blade-ready");

    let root = document.getElementById("tr-ecosystem-blade");
    if (!root) {
      root = document.createElement("aside");
      root.id = "tr-ecosystem-blade";
      root.className = "tr-blade";
      root.setAttribute("aria-label", "Tracedroute apps");
      document.body.appendChild(root);
    }
    applyModeClasses(root, mode);
    root.innerHTML = "";

    let toggle = document.getElementById("tr-ecosystem-blade-toggle");
    if (!toggle) {
      toggle = document.createElement("button");
      toggle.type = "button";
      toggle.id = "tr-ecosystem-blade-toggle";
      toggle.className = "tr-blade__toggle";
      document.body.appendChild(toggle);
    } else {
      // Replace listeners by cloning
      const fresh = toggle.cloneNode(false);
      fresh.id = toggle.id;
      fresh.className = toggle.className;
      toggle.replaceWith(fresh);
      toggle = fresh;
    }
    toggle.setAttribute("aria-expanded", mode === "open" ? "true" : "false");
    if (mode === "open") {
      toggle.title = "Minimize app blade";
      toggle.textContent = "«";
    } else if (mode === "icons") {
      toggle.title = "Hide app blade (edge only)";
      toggle.textContent = "«";
    } else {
      toggle.title = "Show app blade";
      toggle.textContent = "»";
    }
    toggle.addEventListener("click", () => {
      const next = nextMode(mode);
      try {
        localStorage.setItem(STORAGE_KEY, next);
      } catch (_) {}
      renderBlade(services, next, origin);
      applyNotifications();
    });

    const inboxWrap = document.createElement("div");
    inboxWrap.className = "tr-blade__inbox";
    const inboxLink = document.createElement("a");
    inboxLink.className = "tr-blade__link tr-blade__inbox-link";
    inboxLink.href = (originForInbox(origin) || "") + "/account/invoices";
    inboxLink.title = "Invoices";
    inboxLink.dataset.service = "inbox";
    const inboxIcon = document.createElement("span");
    inboxIcon.className = "tr-blade__icon";
    inboxIcon.setAttribute("data-icon", "inbox");
    inboxIcon.innerHTML = iconMarkup("inbox");
    const inboxLabel = document.createElement("span");
    inboxLabel.className = "tr-blade__label";
    inboxLabel.textContent = "Inbox";
    inboxLink.appendChild(inboxIcon);
    inboxLink.appendChild(inboxLabel);
    inboxWrap.appendChild(inboxLink);
    root.appendChild(inboxWrap);

    const list = document.createElement("ul");
    list.className = "tr-blade__list";
    const main = services.filter((s) => !s.pin);
    const foot = services.filter((s) => s.pin);

    function addItem(svc, parent) {
      const li = document.createElement("li");
      li.className = "tr-blade__item";
      const a = document.createElement("a");
      a.className = "tr-blade__link";
      a.href = svc.url || "#";
      a.title = svc.name || svc.id;
      if (svc.id) a.dataset.service = svc.id;
      try {
        const u = new URL(svc.url, location.href);
        if (u.origin === location.origin) a.classList.add("is-active");
        else if (
          svc.id === "donations" &&
          /service\.tracedroute|:8091\b/i.test(location.host) &&
          /donations/i.test(location.hash + location.pathname + location.search)
        ) {
          a.classList.add("is-active");
        }
      } catch (_) {}
      const icon = document.createElement("span");
      icon.className = "tr-blade__icon";
      icon.setAttribute("data-icon", svc.id || "");
      icon.innerHTML = iconMarkup(svc.id);
      const label = document.createElement("span");
      label.className = "tr-blade__label";
      label.textContent = svc.name || svc.id;
      a.appendChild(icon);
      a.appendChild(label);
      li.appendChild(a);
      parent.appendChild(li);
    }

    main.forEach((svc) => addItem(svc, list));
    root.appendChild(list);

    if (foot.length) {
      const footEl = document.createElement("div");
      footEl.className = "tr-blade__foot";
      const footList = document.createElement("ul");
      footList.className = "tr-blade__list";
      foot.forEach((svc) => addItem(svc, footList));
      footEl.appendChild(footList);
      root.appendChild(footEl);
    }

    // Keep Orders origin on the node so notifications can retarget inbox URLs.
    root.dataset.ordersOrigin = originForInbox(origin);
  }

  function originForInbox(origin) {
    return String(origin || ordersOrigin() || "").replace(/\/$/, "");
  }

  async function applyNotifications() {
    const data = await fetchJson("/ecosystem/notifications", 2500);
    if (!data) return;
    const root = document.getElementById("tr-ecosystem-blade");
    if (!root) return;
    const base = root.dataset.ordersOrigin || ordersOrigin();
    const inboxLink = root.querySelector('[data-service="inbox"]');
    if (inboxLink) {
      const items = Array.isArray(data.items) ? data.items : [];
      const first = items.find((it) => it && it.kind === "invoice" && it.url) || items[0];
      if (first && first.url) {
        const u = String(first.url);
        inboxLink.href = u.indexOf("http") === 0 ? u : base + u;
        inboxLink.title = first.title || "Invoice";
      } else {
        inboxLink.href = base + (data.inbox_url || "/account/invoices");
        inboxLink.title = "Invoices";
      }
    }
    if (data.counts) {
      Object.entries(data.counts).forEach(([id, count]) => {
        const link = root.querySelector('[data-service="' + String(id).replace(/"/g, "") + '"]');
        if (link) setBadge(link, count);
      });
    }
  }

  function boot() {
    const origin = ordersOrigin();
    // Always paint the cross-app blade (public destinations like Donations included).
    const mode = preferMode();
    renderBlade(defaultServices(origin), mode, origin);
    applyNotifications();
    setInterval(applyNotifications, 120000);

    fetchJson("/ecosystem/session", SESSION_TIMEOUT_MS).then((session) => {
      if (!(session && session.signed_in && Array.isArray(session.services) && session.services.length)) {
        return;
      }
      renderBlade(normalizeServices(session.services, origin), rootMode(), origin);
      applyNotifications();
    });
  }

  function rootMode() {
    const root = document.getElementById("tr-ecosystem-blade");
    if (!root) return preferMode();
    return normalizeMode(root.dataset.mode || (root.classList.contains("is-open") ? "open" : root.classList.contains("is-peek") ? "peek" : "icons"));
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
  window.__trEcosystemBladeBoot = boot;
  document.addEventListener("tr-ecosystem-session", function () {
    boot();
  });
})();
