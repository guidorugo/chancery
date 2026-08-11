// Dashboard "Recent" panels: show as many table rows as fit the panel height,
// and re-fit when the window is resized. The server sends a generous pool of
// rows; this trims the visible ones to the available space so the box is filled
// without a scrollbar. If this script doesn't run, the panel's CSS
// `overflow-y: auto` still keeps every row reachable (graceful fallback).
(function () {
  "use strict";

  function fitTable(table) {
    var body = table.closest(".card-body");
    var tbody = table.tBodies && table.tBodies[0];
    if (!body || !tbody) return;
    var rows = Array.prototype.slice.call(tbody.rows);
    if (!rows.length) return;

    // Reveal every row first so we measure a real row height and true space.
    rows.forEach(function (r) { r.style.display = ""; });
    var rowH = rows[0].getBoundingClientRect().height;
    if (rowH <= 0) return;

    var padBottom = parseFloat(getComputedStyle(body).paddingBottom) || 0;
    var avail = (body.getBoundingClientRect().bottom - padBottom) -
                tbody.getBoundingClientRect().top;
    var fit = Math.max(1, Math.floor((avail + 1) / rowH)); // +1px tolerance

    rows.forEach(function (r, i) {
      r.style.display = i < fit ? "" : "none";
    });
  }

  function fitAll() {
    var tables = document.querySelectorAll("#dashboard-recent table");
    Array.prototype.forEach.call(tables, fitTable);
  }

  var timer = null;
  function schedule() {
    if (timer) { clearTimeout(timer); }
    timer = setTimeout(fitAll, 100);
  }

  if (document.readyState !== "loading") {
    fitAll();
  } else {
    document.addEventListener("DOMContentLoaded", fitAll);
  }
  window.addEventListener("load", fitAll);   // re-fit after fonts/layout settle
  window.addEventListener("resize", schedule);
})();
