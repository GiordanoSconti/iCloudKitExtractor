(() => {
  const root =
    document.getElementById("live") ||
    document.getElementById("live-root") ||
    document.querySelector("[data-live-panel]");
  if (!root) return;

  const statusUrl =
    root.dataset.statusUrl ||
    new URL("live/status.json", window.location.href).href;

  const badge = root.querySelector("[data-live-badge]");
  const titleEl = root.querySelector("[data-live-title]");
  const detailEl = root.querySelector("[data-live-detail]");
  const metaEl = root.querySelector("[data-live-meta]");
  const stage = root.querySelector("[data-live-stage]");
  const frame = root.querySelector("[data-live-frame]");
  const placeholder = root.querySelector("[data-live-placeholder]");
  const watchLink = root.querySelector("[data-live-watch]");

  function formatWhen(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "";
    return d.toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    });
  }

  function setOffline(reason) {
    root.hidden = false;
    root.dataset.state = "off";
    if (badge) badge.textContent = "Live Session Off";
    if (titleEl) titleEl.textContent = "No live lab session";
    if (detailEl) {
      detailEl.textContent =
        reason || "When a session is active, this panel shows the operator stream.";
    }
    if (metaEl) metaEl.textContent = "";
    if (stage) stage.hidden = true;
    if (watchLink) watchLink.hidden = true;
  }

  function setOnline(status) {
    root.hidden = false;
    root.dataset.state = "on";
    if (badge) badge.textContent = status.label || "Live Session On";
    if (titleEl) titleEl.textContent = status.title || "Live lab session";
    if (detailEl) {
      detailEl.textContent =
        status.detail || "Operator-led iCloudKit Extractor session.";
    }

    const bits = [];
    const started = formatWhen(status.startedAt);
    const updated = formatWhen(status.updatedAt);
    if (started) bits.push(`Started ${started}`);
    if (updated) bits.push(`Updated ${updated}`);
    if (metaEl) metaEl.textContent = bits.join(" · ");

    const embed = (status.embedUrl || "").trim();
    const watch = (status.watchUrl || "").trim();

    if (watchLink) {
      if (watch && !root.dataset.hideWatchLink) {
        watchLink.href = watch;
        watchLink.hidden = false;
        watchLink.textContent = /twitch\.tv/i.test(watch)
          ? "Watch on Twitch"
          : "Open live page";
        if (/^https?:\/\//i.test(watch)) {
          watchLink.setAttribute("target", "_blank");
          watchLink.setAttribute("rel", "noopener noreferrer");
        }
      } else {
        watchLink.hidden = true;
      }
    }

    if (!stage) return;
    stage.hidden = false;

    if (embed && frame) {
      frame.hidden = false;
      if (placeholder) placeholder.hidden = true;
      if (frame.getAttribute("src") !== embed) {
        frame.setAttribute("src", embed);
        frame.setAttribute("title", status.title || "Live Session");
      }
    } else {
      if (frame) {
        frame.hidden = true;
        frame.removeAttribute("src");
      }
      if (placeholder) {
        placeholder.hidden = false;
        placeholder.textContent =
          "Live Session On — waiting for the operator stream embed. " +
          "Set embedUrl in docs/live/status.json (YouTube Live / Twitch / HLS player).";
      }
    }
  }

  async function refresh() {
    try {
      const res = await fetch(statusUrl, { cache: "no-store" });
      if (!res.ok) throw new Error(`status ${res.status}`);
      const status = await res.json();
      if (status && status.live) setOnline(status);
      else setOffline();
    } catch {
      setOffline("Could not load live status.");
    }
  }

  refresh();
  window.setInterval(refresh, 30_000);
})();
