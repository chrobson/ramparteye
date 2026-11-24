// RampartEye UI helpers: theme toggle, confirm dialog, tabs.
// Loaded in <head> (not deferred) so the stored theme applies before paint.
// No inline scripts or eval: the page CSP allows only same-origin scripts.
(function () {
  "use strict";

  var THEME_KEY = "rampart-theme";

  function storedTheme() {
    try {
      return window.localStorage.getItem(THEME_KEY);
    } catch (e) {
      return null;
    }
  }

  if (storedTheme() === "light") {
    document.documentElement.classList.add("light");
  }

  function toggleTheme() {
    var light = document.documentElement.classList.toggle("light");
    try {
      window.localStorage.setItem(THEME_KEY, light ? "light" : "dark");
    } catch (e) {
      // Storage unavailable: the choice lasts until the next page.
    }
  }

  // Forms with data-confirm ask first. The listener runs in the capture
  // phase, before htmx sees the submit, and resubmits after "Confirm".
  function onSubmit(ev) {
    var form = ev.target;
    if (!(form instanceof HTMLFormElement) || !form.hasAttribute("data-confirm")) {
      return;
    }
    if (form.dataset.confirmed === "1") {
      delete form.dataset.confirmed;
      return;
    }
    ev.preventDefault();
    ev.stopPropagation();
    var message = form.getAttribute("data-confirm");
    var dialog = document.getElementById("confirm-dialog");
    if (!dialog || typeof dialog.showModal !== "function") {
      if (window.confirm(message)) {
        resubmit(form);
      }
      return;
    }
    dialog.querySelector("[data-confirm-text]").textContent = message;
    dialog.querySelector("[data-confirm-ok]").textContent =
      form.getAttribute("data-confirm-ok") || "Confirm";
    dialog.returnValue = "";
    dialog.addEventListener("close", function () {
      if (dialog.returnValue === "ok") {
        resubmit(form);
      }
    }, { once: true });
    dialog.showModal();
  }

  function resubmit(form) {
    form.dataset.confirmed = "1";
    if (typeof form.requestSubmit === "function") {
      form.requestSubmit();
    } else {
      form.submit();
    }
  }

  // Tabs: a [data-tabs] element holds buttons [data-tab="id"] and panels
  // [data-panel="id"]; the server renders the initial selection.
  function selectTab(root, id) {
    root.querySelectorAll("[data-tab]").forEach(function (b) {
      b.setAttribute("aria-selected", b.getAttribute("data-tab") === id ? "true" : "false");
    });
    root.querySelectorAll("[data-panel]").forEach(function (p) {
      p.hidden = p.getAttribute("data-panel") !== id;
    });
  }

  function onClick(ev) {
    if (!(ev.target instanceof Element)) {
      return;
    }
    if (ev.target.closest("#theme-toggle")) {
      toggleTheme();
      return;
    }
    var tab = ev.target.closest("[data-tab]");
    var root = tab && tab.closest("[data-tabs]");
    if (root) {
      ev.preventDefault();
      selectTab(root, tab.getAttribute("data-tab"));
    }
  }

  document.addEventListener("submit", onSubmit, true);
  document.addEventListener("click", onClick);
})();
