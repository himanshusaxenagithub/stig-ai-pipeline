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

  async function fillSiteActivity() {
    const root = document.getElementById("site-activity");
    if (!root) return;
    const opensEl = root.querySelector("[data-stat=opens]");
    const usersEl = root.querySelector("[data-stat=users]");
    const noteEl = root.querySelector("[data-stat=note]");
    const dash = function () {
      if (opensEl) opensEl.textContent = "—";
      if (usersEl) usersEl.textContent = "—";
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

    const url = "https://" + goatCode() + ".goatcounter.com/counter/TOTAL.json";
    try {
      const resp = await fetch(url, {cache: "no-store"});
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      const data = await resp.json();
      const opens = parseGoatNumber(data.count);
      const users = parseGoatNumber(
        data.count_unique != null ? data.count_unique : data.count);
      if (opens == null && users == null) throw new Error("empty totals");
      if (opensEl) opensEl.textContent = opens == null ? "—" : formatCount(opens);
      if (usersEl) usersEl.textContent = users == null ? "—" : formatCount(users);
      const same = opens != null && users != null && opens === users;
      if (noteEl) {
        noteEl.textContent = same
          ? "Approximate public GoatCounter totals (cached up to a few hours). " +
            "GoatCounter’s public counter currently publishes one visitor figure; " +
            "opens and users both use that number. Not DoD adoption figures."
          : "Approximate public GoatCounter totals (cached up to a few hours). " +
            "Opens = every visit GoatCounter records. Users = unique visitors. " +
            "Not DoD adoption figures.";
      }
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
        if ("email" in r || looksLikeEmail(r.name) || looksLikeEmail(r.text)) return false;
        return !!(r.name && r.text);
      });
      if (!reviews.length) {
        list.innerHTML =
          "<p class=\"muted\">No approved reviews yet. That is the true state — none are invented.</p>";
        return;
      }
      list.innerHTML = reviews.map(function (r) {
        const org = r.organization ? " · " + escapeHtml(r.organization) : "";
        return "<article class=\"review\">" +
          "<p class=\"review-who\"><b>" + escapeHtml(r.name) + "</b>" + org + "</p>" +
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
