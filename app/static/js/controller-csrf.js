/**
 * Controller CSRF bootstrap — attaches tokens to fetch/XHR and HTML forms.
 * Token source: <meta name="csrf-token"> and/or X-CSRF-Token response headers.
 */
(function () {
  "use strict";

  function readToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return (meta && meta.getAttribute("content")) || "";
  }

  function writeToken(tok) {
    if (!tok) return;
    var meta = document.querySelector('meta[name="csrf-token"]');
    if (!meta) {
      meta = document.createElement("meta");
      meta.setAttribute("name", "csrf-token");
      if (document.head) document.head.appendChild(meta);
    }
    meta.setAttribute("content", tok);
  }

  function isUnsafe(method) {
    var m = String(method || "GET").toUpperCase();
    return m === "POST" || m === "PUT" || m === "PATCH" || m === "DELETE";
  }

  function sameOrigin(url) {
    try {
      if (!url || url === "" || url.charAt(0) === "/" || url.charAt(0) === "?") return true;
      var u = new URL(url, window.location.href);
      return u.origin === window.location.origin;
    } catch (_) {
      return true;
    }
  }

  if (typeof window.fetch === "function") {
    var rawFetch = window.fetch.bind(window);
    window.fetch = function (input, init) {
      init = init ? Object.assign({}, init) : {};
      var url = typeof input === "string" ? input : (input && input.url) || "";
      var method = init.method;
      if (!method && input && typeof input === "object" && input.method) method = input.method;
      method = method || "GET";
      if (isUnsafe(method) && sameOrigin(url)) {
        var tok = readToken();
        if (tok) {
          var headers;
          try {
            headers = new Headers(init.headers || (input && input.headers) || undefined);
          } catch (_) {
            headers = new Headers();
          }
          if (!headers.has("X-CSRF-Token") && !headers.has("X-CSRFToken")) {
            headers.set("X-CSRF-Token", tok);
          }
          init.headers = headers;
        }
      }
      return rawFetch(input, init).then(function (resp) {
        try {
          var nt = resp.headers.get("X-CSRF-Token") || resp.headers.get("X-CSRFToken");
          if (nt) writeToken(nt);
        } catch (_) {}
        return resp;
      });
    };
  }

  if (window.XMLHttpRequest && window.XMLHttpRequest.prototype) {
    var rawOpen = window.XMLHttpRequest.prototype.open;
    var rawSend = window.XMLHttpRequest.prototype.send;
    window.XMLHttpRequest.prototype.open = function (method, url) {
      this.__hcMethod = method;
      this.__hcUrl = url;
      return rawOpen.apply(this, arguments);
    };
    window.XMLHttpRequest.prototype.send = function (body) {
      try {
        if (isUnsafe(this.__hcMethod) && sameOrigin(this.__hcUrl)) {
          var tok = readToken();
          if (tok) this.setRequestHeader("X-CSRF-Token", tok);
        }
        var xhr = this;
        xhr.addEventListener("load", function () {
          try {
            var nt = xhr.getResponseHeader("X-CSRF-Token") || xhr.getResponseHeader("X-CSRFToken");
            if (nt) writeToken(nt);
          } catch (_) {}
        });
      } catch (_) {}
      return rawSend.apply(this, arguments);
    };
  }

  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("form").forEach(function (form) {
      var method = (form.getAttribute("method") || "GET").toUpperCase();
      if (!isUnsafe(method)) return;
      if (form.querySelector('input[name="csrf_token"], input[name="_csrf"]')) return;
      var tok = readToken();
      if (!tok) return;
      var input = document.createElement("input");
      input.type = "hidden";
      input.name = "csrf_token";
      input.value = tok;
      form.appendChild(input);
    });
  });
})();
