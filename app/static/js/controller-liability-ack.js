/**
 * Post-login platform risk acknowledgment — blocking until Accept or Decline (logout).
 */
(function () {
  "use strict";

  var STATUS_URL = "/api/session/status";
  var ACK_URL = "/api/liability/acknowledge";
  var DIALOG_ID = "hayabusaLiabilityAck";
  var TEXT =
    "Welcome to Hayabusa! By using this platform, you acknowledge that Hayabusa can create and modify infrastructure including virtual machines, networks, containers, bare metal instances and more. By using the platform, you recognize the risks associated with using Hayabusa and the other programs within the platform. You release the Hayabusa platform and all related entities from liability and accept full responsibility for any changes made to infrastructure.";

  function ensureDialog() {
    var existing = document.getElementById(DIALOG_ID);
    if (existing) return existing;

    var style = document.createElement("style");
    style.textContent =
      "#" + DIALOG_ID + "{position:fixed;inset:0;z-index:2147483600;display:flex;align-items:center;justify-content:center;font-family:Sora,system-ui,sans-serif}" +
      "#" + DIALOG_ID + "[hidden]{display:none!important}" +
      ".hayabusa-liability__backdrop{position:absolute;inset:0;background:rgba(8,12,18,.72)}" +
      ".hayabusa-liability__card{position:relative;max-width:540px;margin:1rem;padding:1.35rem 1.45rem;border-radius:12px;background:#121820;color:#e8eef4;border:1px solid rgba(127,214,181,.35);box-shadow:0 18px 50px rgba(0,0,0,.5)}" +
      ".hayabusa-liability__card h2{margin:0 0 .75rem;font-size:1.2rem;font-weight:600}" +
      ".hayabusa-liability__body{margin:0 0 1.15rem;line-height:1.5;color:#c5d0da;font-size:.95rem}" +
      ".hayabusa-liability__actions{display:flex;flex-wrap:wrap;gap:.65rem;justify-content:flex-end}" +
      ".hayabusa-liability__btn{cursor:pointer;border-radius:8px;border:1px solid #3a4654;background:#1b2430;color:#e8eef4;padding:.6rem 1rem;font:inherit}" +
      ".hayabusa-liability__btn--primary{background:#1f6f5b;border-color:#2f9d7f;font-weight:600}" +
      ".hayabusa-liability__btn--danger{background:#5a1f2a;border-color:#9a3a4a}" +
      ".hayabusa-liability__btn:hover{filter:brightness(1.08)}" +
      ".hayabusa-liability__btn:disabled{opacity:.6;cursor:wait}";
    document.head.appendChild(style);

    var dialog = document.createElement("div");
    dialog.id = DIALOG_ID;
    dialog.setAttribute("role", "dialog");
    dialog.setAttribute("aria-modal", "true");
    dialog.setAttribute("aria-labelledby", "hayabusaLiabilityAckTitle");
    dialog.hidden = true;
    dialog.innerHTML =
      '<div class="hayabusa-liability__backdrop" aria-hidden="true"></div>' +
      '<div class="hayabusa-liability__card">' +
      '  <h2 id="hayabusaLiabilityAckTitle">Welcome to Hayabusa</h2>' +
      '  <p class="hayabusa-liability__body"></p>' +
      '  <div class="hayabusa-liability__actions">' +
      '    <button type="button" class="hayabusa-liability__btn hayabusa-liability__btn--danger" id="hayabusaLiabilityDecline">I decline</button>' +
      '    <button type="button" class="hayabusa-liability__btn hayabusa-liability__btn--primary" id="hayabusaLiabilityAccept">I accept</button>' +
      "  </div>" +
      "</div>";
    dialog.querySelector(".hayabusa-liability__body").textContent = TEXT;
    document.body.appendChild(dialog);

    dialog.querySelector("#hayabusaLiabilityAccept").addEventListener("click", accept);
    dialog.querySelector("#hayabusaLiabilityDecline").addEventListener("click", decline);
    dialog.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape") {
        ev.preventDefault();
        ev.stopPropagation();
      }
    });
    return dialog;
  }

  function show() {
    var d = ensureDialog();
    d.hidden = false;
    try {
      document.body.style.overflow = "hidden";
    } catch (_) {}
    var btn = d.querySelector("#hayabusaLiabilityAccept");
    if (btn) btn.focus();
  }

  var acked = false;
  var waiters = [];

  function notifyAcked() {
    acked = true;
    hide();
    try {
      document.dispatchEvent(new CustomEvent("hayabusa:liability-acked"));
    } catch (_) {}
    var q = waiters.splice(0, waiters.length);
    q.forEach(function (fn) {
      try {
        fn();
      } catch (_) {}
    });
  }

  function hide() {
    var d = document.getElementById(DIALOG_ID);
    if (d) d.hidden = true;
    try {
      document.body.style.overflow = "";
    } catch (_) {}
  }

  function decline() {
    try {
      window.location.href = "/logout";
    } catch (_) {}
  }

  function accept() {
    var d = ensureDialog();
    var acceptBtn = d.querySelector("#hayabusaLiabilityAccept");
    var declineBtn = d.querySelector("#hayabusaLiabilityDecline");
    if (acceptBtn) acceptBtn.disabled = true;
    if (declineBtn) declineBtn.disabled = true;
    fetch(ACK_URL, {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: "{}",
    })
      .then(function (r) {
        return r.json().then(function (j) {
          return { status: r.status, data: j };
        });
      })
      .then(function (o) {
        if (o.status >= 400 || !(o.data && o.data.ok)) {
          if (acceptBtn) acceptBtn.disabled = false;
          if (declineBtn) declineBtn.disabled = false;
          return;
        }
        notifyAcked();
      })
      .catch(function () {
        if (acceptBtn) acceptBtn.disabled = false;
        if (declineBtn) declineBtn.disabled = false;
      });
  }

  function check() {
    fetch(STATUS_URL, { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } })
      .then(function (r) {
        if (r.status === 401) return null;
        return r.json();
      })
      .then(function (data) {
        if (!data || !data.ok || !data.authenticated) return;
        if (data.liability_acknowledged) {
          notifyAcked();
          return;
        }
        show();
      })
      .catch(function () {});
  }

  /** Run after Accept (or immediately if already acknowledged this session). */
  window.hayabusaWhenLiabilityAcked = function (fn) {
    if (typeof fn !== "function") return;
    if (acked) {
      try {
        fn();
      } catch (_) {}
      return;
    }
    waiters.push(fn);
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", check);
  } else {
    check();
  }
})();
