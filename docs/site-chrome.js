/* Shared Pages chrome: GoatCounter tracking + public totals, approved reviews.
   Reads window.STIG_SITE_CONFIG from site-config.js. This page never invents
   counts or quotes. */

(function () {
  const cfg = window.STIG_SITE_CONFIG || {};
  const PLACEHOLDER = "YOUR_GOATCOUNTER_CODE";

  function goatCode() {
    return String(cfg.goatcounterCode || "").trim();
  }

  function goatConfigured() {
    const code = goatCode();
    return !!code && code !== PLACEHOLDER && !/^YOUR_/i.test(code);
  }

  function installGoatCounter() {
    if (!goatConfigured()) return;
    if (document.querySelector("script[data-goatcounter]")) return;
    const s = document.createElement("script");
    s.async = true;
    s.src = "https://gc.zgo.at/count.js";
    s.setAttribute("data-goatcounter",
      "https://" + goatCode() + ".goatcounter.com/count");
    document.head.appendChild(s);
  }

  function parseGoatNumber(value) {
    if (value == null) return null;
    const n = parseInt(String(value).replace(/[^\d]/g, ""), 10);
    return Number.isFinite(n) ? n : null;
  }

  function formatCount(n) {
    try {
      return n.toLocaleString("en-US");
    } catch (e) {
      return String(n);
    }
  }

  /* GoatCounter’s official site widget. TOTAL.json is often CDN-stale (0). */
  function parseGcvcViews(html) {
    if (!html) return null;
    const tagged = String(html).match(/id=["']gcvc-views["'][^>]*>([^<]*)/i);
    if (tagged) return parseGoatNumber(tagged[1]);
    try {
      const doc = new DOMParser().parseFromString(html, "text/html");
      const el = doc.getElementById("gcvc-views");
      if (el) return parseGoatNumber(el.textContent);
    } catch (e) {}
    return null;
  }

  const GOAT_PATHS = [
    "/", "/index.html", "/reviews.html", "/demo.html",
    "/evidence.html", "/used.html", "/review-thanks.html",
  ];

  function goatBase() {
    return "https://" + goatCode() + ".goatcounter.com";
  }

  async function fetchGoat(url) {
    const resp = await fetch(url, {cache: "no-store"});
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    return resp;
  }

  async function totalFromWidgetHtml() {
    const resp = await fetchGoat(goatBase() + "/counter/TOTAL.html");
    return parseGcvcViews(await resp.text());
  }

  async function totalFromTotalJson() {
    const resp = await fetchGoat(goatBase() + "/counter/TOTAL.json");
    const data = await resp.json();
    return parseGoatNumber(data.count);
  }

  async function totalFromKnownPaths() {
    const counts = await Promise.all(GOAT_PATHS.map(async function (path) {
      try {
        const resp = await fetchGoat(
          goatBase() + "/counter/" + encodeURIComponent(path) + ".json");
        const data = await resp.json();
        return parseGoatNumber(data.count) || 0;
      } catch (e) {
        return 0;
      }
    }));
    const sum = counts.reduce(function (a, b) { return a + b; }, 0);
    return sum > 0 ? sum : null;
  }

  async function publicGoatTotal() {
    try {
      const n = await totalFromWidgetHtml();
      if (n != null && n > 0) return {n: n, source: "html"};
    } catch (e) {}
    try {
      const n = await totalFromTotalJson();
      if (n != null && n > 0) return {n: n, source: "json"};
    } catch (e) {}
    try {
      const n = await totalFromKnownPaths();
      if (n != null && n > 0) return {n: n, source: "paths"};
    } catch (e) {}
    return null;
  }

  async function fillSiteActivity() {
    const root = document.getElementById("site-activity");
    if (!root) return;
    const visitorsEl = root.querySelector("[data-stat=visitors]");
    const noteEl = root.querySelector("[data-stat=note]");
    const dash = function () {
      if (visitorsEl) visitorsEl.textContent = "—";
    };

    if (!goatConfigured()) {
      dash();
      if (noteEl) {
        noteEl.textContent =
          "GoatCounter is not configured yet. Create a free site at goatcounter.com, " +
          "put the site code in docs/site-config.js (goatcounterCode), and in GoatCounter " +
          "settings enable “Allow adding visitor counts on your website.”";
      }
      return;
    }

    try {
      const got = await publicGoatTotal();
      if (!got) throw new Error("no public total");
      if (visitorsEl) visitorsEl.textContent = formatCount(got.n);
    } catch (e) {
      dash();
      if (noteEl) {
        noteEl.textContent =
          "Public GoatCounter stats are not available yet (site code, visitor-counter " +
          "setting, or network). No numbers are invented.";
      }
    }
  }

  function looksLikeEmail(value) {
    return typeof value === "string" && value.includes("@");
  }

  function escapeHtml(s) {
    return String(s ?? "").replace(/[&<>"]/g, function (c) {
      return ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"})[c];
    });
  }

  async function fillReviews() {
    const list = document.getElementById("reviews-list");
    if (!list) return;
    try {
      const resp = await fetch("data/reviews.json", {cache: "no-store"});
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      const data = await resp.json();
      const raw = Array.isArray(data) ? data : (data.reviews || []);
      const reviews = raw.filter(function (r) {
        if (!r || typeof r !== "object") return false;
        if ("email" in r || looksLikeEmail(r.title) || looksLikeEmail(r.name)
            || looksLikeEmail(r.text)) return false;
        return !!(r.title && r.name && r.text);
      });
      if (!reviews.length) {
        list.innerHTML =
          "<p class=\"muted\">No approved reviews yet. That is the true state — none are invented.</p>";
        return;
      }
      list.innerHTML = reviews.map(function (r) {
        const org = r.organization ? " · " + escapeHtml(r.organization) : "";
        return "<article class=\"review\">" +
          "<p class=\"review-title\"><b>" + escapeHtml(r.title) + "</b></p>" +
          "<p class=\"review-who\">" + escapeHtml(r.name) + org + "</p>" +
          "<p class=\"review-text\">" + escapeHtml(r.text) + "</p>" +
          "</article>";
      }).join("");
    } catch (e) {
      list.innerHTML =
        "<p class=\"muted\">Approved reviews could not be loaded. The list is not invented.</p>";
    }
  }

  installGoatCounter();
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      fillSiteActivity();
      fillReviews();
    });
  } else {
    fillSiteActivity();
    fillReviews();
  }
})();
