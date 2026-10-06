/**
 * Session expiry warning — polls /api/session/status and offers Continue to renew.
 * Shared pattern for Hayabusa (and controller when pointed at /api/session/*).
 */
(function () {
  "use strict";

  var STATUS_URL = "/api/session/status";
  var RENEW_URL = "/api/session/renew";
  var POLL_MS = 30000;
  var FAST_POLL_MS = 5000;
  var dialog = null;
  var timer = null;
  var warnedForExpiry = 0;

  function fmt(sec) {
    sec = Math.max(0, Math.floor(Number(sec) || 0));
    var m = Math.floor(sec / 60);
    var s = sec % 60;
    if (m >= 60) {
      var h = Math.floor(m / 60);
      m = m % 60;
      return h + "h " + m + "m";
    }
    return m + "m " + (s < 10 ? "0" : "") + s + "s";
  }

  function ensureDialog() {
    if (dialog) return dialog;
    dialog = document.createElement("div");
    dialog.id = "hayabusaSessionWarn";
    dialog.setAttribute("role", "dialog");
    dialog.setAttribute("aria-modal", "true");
    dialog.setAttribute("aria-labelledby", "hayabusaSessionWarnTitle");
    dialog.hidden = true;
    dialog.innerHTML =
      '<div class="hayabusa-session-warn__backdrop"></div>' +
      '<div class="hayabusa-session-warn__card">' +
      '  <h2 id="hayabusaSessionWarnTitle">Session expiring soon</h2>' +
      '  <p class="hayabusa-session-warn__body">Your sign-in will end in <strong id="hayabusaSessionWarnRemain">—</strong>. ' +
      "Click Continue to stay signed in, or you will be signed out when time runs out.</p>" +
      '  <div class="hayabusa-session-warn__actions">' +
      '    <button type="button" class="hayabusa-session-warn__btn hayabusa-session-warn__btn--primary" id="hayabusaSessionContinue">Continue session</button>' +
      '    <button type="button" class="hayabusa-session-warn__btn" id="hayabusaSessionDismiss">Dismiss</button>' +
      "  </div>" +
      "</div>";
    var style = document.createElement("style");
    style.textContent =
      "#hayabusaSessionWarn{position:fixed;inset:0;z-index:2147483000;display:flex;align-items:center;justify-content:center;font-family:Sora,system-ui,sans-serif}" +
      "#hayabusaSessionWarn[hidden]{display:none!important}" +
      ".hayabusa-session-warn__backdrop{position:absolute;inset:0;background:rgba(8,12,18,.55)}" +
      ".hayabusa-session-warn__card{position:relative;max-width:420px;margin:1rem;padding:1.25rem 1.35rem;border-radius:12px;background:#121820;color:#e8eef4;border:1px solid rgba(127,214,181,.35);box-shadow:0 18px 50px rgba(0,0,0,.45)}" +
      ".hayabusa-session-warn__card h2{margin:0 0 .6rem;font-size:1.15rem;font-weight:600}" +
      ".hayabusa-session-warn__body{margin:0 0 1rem;line-height:1.45;color:#c5d0da;font-size:.95rem}" +
      ".hayabusa-session-warn__actions{display:flex;flex-wrap:wrap;gap:.6rem}" +
      ".hayabusa-session-warn__btn{cursor:pointer;border-radius:8px;border:1px solid #3a4654;background:#1b2430;color:#e8eef4;padding:.55rem .9rem;font:inherit}" +
      ".hayabusa-session-warn__btn--primary{background:#1f6f5b;border-color:#2f9d7f;font-weight:600}" +
      ".hayabusa-session-warn__btn:hover{filter:brightness(1.08)}";
    document.head.appendChild(style);
    document.body.appendChild(dialog);
    dialog.querySelector("#hayabusaSessionContinue").addEventListener("click", renew);
    dialog.querySelector("#hayabusaSessionDismiss").addEventListener("click", hide);
    return dialog;
  }

  function show(remaining) {
    var d = ensureDialog();
    var el = d.querySelector("#hayabusaSessionWarnRemain");
    if (el) el.textContent = fmt(remaining);
    d.hidden = false;
  }

  function hide() {
    if (dialog) dialog.hidden = true;
  }

  function schedule(ms) {
    if (timer) clearTimeout(timer);
    timer = setTimeout(tick, ms);
  }

  function tick() {
    fetch(STATUS_URL, { credentials: "same-origin", cache: "no-store" })
      .then(function (r) {
        return r.json().then(function (j) {
          return { status: r.status, data: j };
        });
      })
      .then(function (o) {
        var j = o.data || {};
        if (o.status === 401 || j.code === "session_expired" || j.authenticated === false) {
          hide();
          try {
            window.location.href = "/login";
          } catch (_) {}
          return;
        }
        var remaining = Number(j.remaining_sec);
        if (!isFinite(remaining)) {
          schedule(POLL_MS);
          return;
        }
        if (j.should_warn || remaining <= Number(j.warn_before_sec || 300)) {
          if (warnedForExpiry !== Number(j.expires_at || 0)) {
            warnedForExpiry = Number(j.expires_at || 0);
            show(remaining);
          } else if (dialog && !dialog.hidden) {
            var el = dialog.querySelector("#hayabusaSessionWarnRemain");
            if (el) el.textContent = fmt(remaining);
          }
          schedule(FAST_POLL_MS);
          return;
        }
        hide();
        warnedForExpiry = 0;
        schedule(POLL_MS);
      })
      .catch(function () {
        schedule(POLL_MS);
      });
  }

  function renew() {
    var btn = dialog && dialog.querySelector("#hayabusaSessionContinue");
    if (btn) btn.disabled = true;
    fetch(RENEW_URL, {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: "{}",
    })
      .then(function (r) {
        return r.json().then(function (j) {
          return { status: r.status, data: j };
        });
      })
      .then(function (o) {
        if (btn) btn.disabled = false;
        if (o.status >= 400 || !(o.data && o.data.ok)) {
          try {
            window.location.href = "/login";
          } catch (_) {}
          return;
        }
        warnedForExpiry = 0;
        hide();
        schedule(POLL_MS);
      })
      .catch(function () {
        if (btn) btn.disabled = false;
      });
  }

  function start() {
    if (document.body) {
      tick();
    } else {
      document.addEventListener("DOMContentLoaded", tick);
    }
  }

  // Only on authenticated app pages (nav include present or body not login).
  if (/\/login\/?$/.test(location.pathname)) return;
  start();
})();
