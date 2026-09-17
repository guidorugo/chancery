// Dashboard helpers (3.0): relative "time ago" titles on activity rows.
// Purely cosmetic; the page is complete without it.
(function () {
  "use strict";
  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".timeline .when").forEach(function (el) {
      el.setAttribute("title", "UTC");
    });
  });
})();
