/* Manual RAM recovery popup.
 *
 * Kept as its own static file rather than inline, per the codebase's standing
 * #1-recurring-bug note (JS strings inside Python f-strings). Built entirely
 * with createElement/textContent -- never innerHTML with interpolated values --
 * so server response data gets the same treatment as any other API response.
 *
 * Honesty rules this UI must hold to, because the underlying facts are subtle:
 *  - zombies are shown with "frees a process slot, not memory", never counted
 *    toward reclaimable bytes;
 *  - a detection failure renders a visible error, never an empty "nothing to
 *    clean" list, which would look identical to a healthy box;
 *  - segments that were CONSIDERED and rejected are shown on request with the
 *    reason, so "nothing offered" is explainable rather than mysterious.
 */
(function () {
  "use strict";

  var CANDIDATES_URL = "/api/ram-recovery/candidates";
  var CLEAN_URL = "/api/ram-recovery/clean";

  function el(tag, opts) {
    var n = document.createElement(tag);
    opts = opts || {};
    if (opts.text) { n.textContent = opts.text; }
    if (opts.cls) { n.className = opts.cls; }
    if (opts.style) { n.setAttribute("style", opts.style); }
    return n;
  }

  function fmtBytes(b) {
    if (typeof b !== "number" || b <= 0) { return "0 B"; }
    var u = ["B", "KB", "MB", "GB"], i = 0, v = b;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i += 1; }
    return (Math.round(v * 10) / 10) + " " + u[i];
  }

  function overlay() {
    var o = el("div", {
      style: "position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:9999;" +
             "display:flex;align-items:center;justify-content:center;"
    });
    o.id = "ramRecoveryOverlay";
    return o;
  }

  function panel() {
    return el("div", {
      style: "background:#1a1a2e;color:#eee;border:1px solid #444;border-radius:8px;" +
             "max-width:720px;width:92%;max-height:82vh;overflow:auto;padding:20px;" +
             "font-family:Arial,sans-serif;"
    });
  }

  function close() {
    var o = document.getElementById("ramRecoveryOverlay");
    if (o && o.parentNode) { o.parentNode.removeChild(o); }
    /* Dismiss any credential prompt this popup opened. Without this the shared
     * modal is left displayed and its pending promise still registered after
     * the reclaim popup goes away, so the next attempt resolves the OLD
     * promise -- whose .then() writes into a panel that is no longer in the
     * document. That is the "retrying does nothing" half of the reported bug;
     * the z-index fix alone would not have covered it. */
    var m = document.getElementById("fwCredModal");
    if (m && m.style.display !== "none" && window.fwCredCancel) {
      window.fwCredCancel();
    }
  }

  function row(labelText, subText, checked) {
    var wrap = el("label", {
      style: "display:flex;gap:10px;align-items:flex-start;padding:8px 6px;" +
             "border-bottom:1px solid #2c2c44;cursor:pointer;"
    });
    var cb = el("input");
    cb.type = "checkbox";
    cb.checked = !!checked;          // defaulted CHECKED, per the spec
    cb.style.marginTop = "3px";
    var txt = el("div");
    txt.appendChild(el("div", { text: labelText }));
    if (subText) {
      txt.appendChild(el("div", {
        text: subText,
        style: "color:#9a9ab0;font-size:.82em;margin-top:2px;"
      }));
    }
    wrap.appendChild(cb);
    wrap.appendChild(txt);
    return { node: wrap, checkbox: cb };
  }

  function render(container, data) {
    container.textContent = "";

    var h = el("h3", { text: "Reclaim memory", style: "margin:0 0 4px 0;" });
    container.appendChild(h);
    container.appendChild(el("p", {
      text: "Only items that are already dead are offered. Nothing here stops " +
            "or kills a running application.",
      style: "color:#9a9ab0;font-size:.85em;margin:0 0 14px 0;"
    }));

    var controls = [];

    /* ── orphaned shared memory: the only category that returns real RAM ── */
    var shm = data.shm_orphans || [];
    container.appendChild(el("h4", {
      text: "Orphaned shared memory (" + fmtBytes(data.reclaimable_bytes || 0) +
            " reclaimable)",
      style: "margin:12px 0 4px 0;"
    }));
    if (!shm.length) {
      container.appendChild(el("p", {
        text: "None found. Orphaned segments are normally left behind only by a " +
              "crash, so a healthy system usually has none.",
        style: "color:#9a9ab0;font-size:.85em;margin:0 0 8px 0;"
      }));
    } else {
      shm.forEach(function (s) {
        var r = row(
          "shmid " + s.shmid + " — " + fmtBytes(s.bytes),
          "created by pid " + s.creator_pid + " (no longer running); " +
            "nattch=" + s.nattch + "; not present in any address space",
          true);
        r.checkbox.setAttribute("data-kind", "shm");
        r.checkbox.setAttribute("data-shmid", String(s.shmid));
        r.checkbox.setAttribute("data-bytes", String(s.bytes));
        controls.push(r.checkbox);
        container.appendChild(r.node);
      });
    }

    /* ── zombies: explicitly NOT memory ── */
    var z = data.zombies || [];
    container.appendChild(el("h4", {
      text: "Zombie processes (" + z.length + ")",
      style: "margin:16px 0 4px 0;"
    }));
    container.appendChild(el("p", {
      text: "Reaping frees a process-table slot, not memory — a zombie has " +
            "already released its memory. Nemesis asks the parent to reap and " +
            "never kills anything.",
      style: "color:#9a9ab0;font-size:.85em;margin:0 0 8px 0;"
    }));
    if (data.zombie_error) {
      container.appendChild(el("p", {
        text: "Zombie detection failed: " + data.zombie_error,
        style: "color:#ff8080;font-size:.85em;"
      }));
    }
    z.forEach(function (p) {
      var parent = (p.parent_name || "?") + " (pid " + p.ppid + ")";
      var label = (p.name || "?") + " (pid " + p.pid + ")";

      /* CASE_REFUSED: shown, explained, and NOT actionable. Acting would kill
       * the session Nemesis itself runs under. No checkbox at all -- an
       * unchecked box still invites a click. */
      if (p.case === "refused_ancestor" || p.actionable === false) {
        var d = el("div", {
          style: "padding:8px 6px;border-bottom:1px solid #2c2c44;"
        });
        d.appendChild(el("div", { text: label + " — no action available" }));
        d.appendChild(el("div", {
          text: "Parent " + parent + ": " + (p.why || "refused"),
          style: "color:#c8a04a;font-size:.82em;margin-top:2px;"
        }));
        container.appendChild(d);
        return;
      }

      /* The two actionable cases are labelled HONESTLY and differently:
       * restarting a service is recoverable; terminating a desktop app is not,
       * and must not be dressed up as a restart. */
      var sub, verb;
      if (p.case === "restartable_service" && p.unit) {
        verb = "Restart " + p.unit;
        sub = "restarts the service that owns it — it should come back "
            + "automatically; frees no memory";
        /* The dashboard cannot reach a logged-in user's systemd manager (no
         * /run/user/<its own uid>), so for a user service it genuinely does
         * not know CanStart yet. Say so rather than presenting a proposal as
         * a settled fact -- nemesis-fwd re-derives it and refuses if it still
         * cannot confirm. */
        if (p.canstart !== "yes") {
          sub += " — restartability is confirmed at action time, and the "
               + "action is refused if it cannot be";
        }
      } else {
        verb = "Terminate " + parent;
        sub = "TERMINATES the parent application — it will NOT be relaunched "
            + "automatically; frees no memory";
      }

      var r = row(label + " — " + verb, sub, true);
      r.checkbox.setAttribute("data-kind", "zombie");
      r.checkbox.setAttribute("data-pid", String(p.pid));
      r.checkbox.setAttribute("data-ppid", String(p.ppid));
      r.checkbox.setAttribute("data-case", p.case || "terminate_only");
      if (p.unit) { r.checkbox.setAttribute("data-unit", p.unit); }
      if (p.user_scope) { r.checkbox.setAttribute("data-user-scope", "1"); }
      if (p.starttime !== null && p.starttime !== undefined) {
        r.checkbox.setAttribute("data-starttime", String(p.starttime));
      }
      controls.push(r.checkbox);
      container.appendChild(r.node);
    });

    /* ── what was considered and rejected, on request ── */
    var considered = (data.shm_considered || []).filter(function (s) {
      return !s.orphan;
    });
    if (considered.length) {
      var det = el("details", { style: "margin-top:14px;" });
      var sum = el("summary", {
        text: "Why " + considered.length + " other segment(s) were not offered",
        style: "cursor:pointer;color:#9a9ab0;font-size:.85em;"
      });
      det.appendChild(sum);
      considered.forEach(function (s) {
        det.appendChild(el("div", {
          text: "shmid " + s.shmid + " (" + fmtBytes(s.bytes) + "): " +
                (s.reasons || []).join("; "),
          style: "color:#9a9ab0;font-size:.8em;padding:3px 0 3px 10px;"
        }));
      });
      container.appendChild(det);
    }

    if (data.maps_unreadable) {
      container.appendChild(el("p", {
        text: data.maps_unreadable + " of " + (data.maps_scanned + data.maps_unreadable) +
              " process maps were unreadable (other users' processes). The " +
              "kernel's own attach counter still covers these, so detection " +
              "remains sound.",
        style: "color:#6f6f88;font-size:.78em;margin-top:12px;"
      }));
    }

    /* ── actions ── */
    var bar = el("div", { style: "margin-top:18px;display:flex;gap:10px;justify-content:flex-end;" });
    var cancel = el("button", { text: "Cancel" });
    cancel.setAttribute("style",
      "padding:8px 14px;background:#2c2c44;color:#eee;border:1px solid #444;" +
      "border-radius:5px;cursor:pointer;");
    cancel.addEventListener("click", close);

    var go = el("button", { text: "Clean selected" });
    go.setAttribute("style",
      "padding:8px 14px;background:#3a6ea5;color:#fff;border:none;" +
      "border-radius:5px;cursor:pointer;");
    if (!controls.length) { go.disabled = true; go.style.opacity = ".5"; }
    go.addEventListener("click", function () {
      var sel = [];
      controls.forEach(function (cb) {
        if (!cb.checked) { return; }
        if (cb.getAttribute("data-kind") === "shm") {
          sel.push({
            kind: "shm",
            shmid: parseInt(cb.getAttribute("data-shmid"), 10),
            bytes: parseInt(cb.getAttribute("data-bytes"), 10)
          });
        } else {
          /* THE PID ONLY. The parent, case, unit and starttime rendered above
           * are display data for the human -- they are deliberately NOT sent.
           * nemesis-fwd re-derives every one of them as root and confirms the
           * pid is genuinely a zombie before acting, so anything asserted from
           * here would be either ignored or, worse, trusted. Same contract as
           * the shm reclaim, which sends only a shmid. */
          sel.push({
            kind: "zombie",
            pid: parseInt(cb.getAttribute("data-pid"), 10)
          });
        }
      });
      /* BOTH kinds are performed by nemesis-fwd as root now, so both carry the
       * same admin re-authentication as every other privileged op. Zombie
       * actions used to run in-process and needed no password; they failed
       * EPERM every time, and moving them behind the helper (2026-08-20) means
       * they are privileged operations like any other. */
      var kinds = {};
      sel.forEach(function (s) { kinds[s.kind] = true; });
      var needsCred = !!(kinds.shm || kinds.zombie);
      var label = kinds.shm && kinds.zombie
        ? "reclaim orphaned memory and clear zombie processes"
        : (kinds.shm ? "reclaim orphaned shared memory"
                     : "clear zombie processes");
      var credPromise = needsCred && window.fwPrompt
        ? window.fwPrompt(label)
        : Promise.resolve(null);

      credPromise.then(function (password) {
        if (needsCred && !password) { return; }   /* cancelled — do nothing */
        go.disabled = true;
        go.textContent = "Cleaning…";
        var payload = { selections: sel };
        if (password) { payload.password = password; }
        fetch(CLEAN_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        }).then(function (r) { return r.json(); })
          .then(function (res) {
            if (res && res.error && window.fwHandleError) {
              window.fwHandleError(res, "Reclaim failed.");
              go.disabled = false;
              go.textContent = "Clean selected";
              return;
            }
            /* If the popup was dismissed while the request was in flight, the
             * panel is detached and rendering into it would silently go
             * nowhere -- the reclaim would appear never to complete even
             * though the server did the work. Re-open a panel so the outcome
             * is always visible. */
            var target = container;
            if (!container.isConnected) {
              var o2 = overlay();
              var p2 = panel();
              o2.appendChild(p2);
              o2.addEventListener("click", function (ev) {
                if (ev.target === o2) { close(); }
              });
              document.body.appendChild(o2);
              target = p2;
            }
            renderResults(target, res);
          })
          .catch(function (e) {
            container.appendChild(el("p", {
              text: "Cleanup request failed: " + e,
              style: "color:#ff8080;"
            }));
          });
      });
    });

    bar.appendChild(cancel);
    bar.appendChild(go);
    container.appendChild(bar);
  }

  function renderResults(container, res) {
    container.textContent = "";
    container.appendChild(el("h3", { text: "Cleanup result", style: "margin:0 0 10px 0;" }));
    container.appendChild(el("p", {
      text: "Memory reclaimed: " + fmtBytes(res.bytes_freed || 0),
      style: "margin:0 0 12px 0;"
    }));
    (res.results || []).forEach(function (r) {
      /* A reap that succeeded and was immediately undone must NOT read as a
       * plain green OK. Measured in production: reaping the speech-dispatcher
       * zombie restarts the unit, the fresh instance probes its output modules,
       * one dies unreaped, and an equivalent zombie exists within the same
       * second. Every reap genuinely worked and the list looked unchanged --
       * which reads as a broken feature when the feature is working. Amber and
       * "CAME BACK" say the true thing instead of the merely-accurate one.
       * "unknown" is kept distinct from "clear" so a check that could not run
       * is never displayed as a check that passed. */
      var label, colour;
      if (!r.ok) {
        label = "FAILED   "; colour = "#ff8080";
      } else if (r.regeneration === "regenerated") {
        label = "CAME BACK   "; colour = "#c8a04a";
      } else if (r.regeneration === "unknown") {
        label = "OK (unconfirmed)   "; colour = "#c8a04a";
      } else {
        label = "OK   "; colour = "#9fd39f";
      }
      container.appendChild(el("div", {
        text: label +
              (r.kind === "shm" ? ("shmid " + r.shmid) : ("pid " + r.pid)) +
              " — " + (r.detail || ""),
        style: "font-size:.85em;padding:4px 0;color:" + colour + ";"
      }));
    });
    var bar = el("div", { style: "margin-top:16px;text-align:right;" });
    var done = el("button", { text: "Close" });
    done.setAttribute("style",
      "padding:8px 14px;background:#3a6ea5;color:#fff;border:none;" +
      "border-radius:5px;cursor:pointer;");
    done.addEventListener("click", function () { close(); location.reload(); });
    bar.appendChild(done);
    container.appendChild(bar);
  }

  window.openRamRecovery = function () {
    close();
    var o = overlay();
    var p = panel();
    p.appendChild(el("p", { text: "Scanning…", style: "color:#9a9ab0;" }));
    o.appendChild(p);
    o.addEventListener("click", function (ev) { if (ev.target === o) { close(); } });
    document.body.appendChild(o);

    fetch(CANDIDATES_URL, { headers: { "Accept": "application/json" } })
      .then(function (r) {
        if (!r.ok) {
          return r.json().then(function (j) {
            throw new Error(j.error || ("HTTP " + r.status));
          });
        }
        return r.json();
      })
      .then(function (data) { render(p, data); })
      .catch(function (e) {
        p.textContent = "";
        p.appendChild(el("h3", { text: "Cannot determine what is reclaimable" }));
        // Deliberately NOT an empty "nothing to clean" list: that would be
        // indistinguishable from a genuinely clean system.
        p.appendChild(el("p", {
          text: String(e && e.message ? e.message : e),
          style: "color:#ff8080;font-size:.9em;"
        }));
        var b = el("button", { text: "Close" });
        b.setAttribute("style",
          "margin-top:14px;padding:8px 14px;background:#2c2c44;color:#eee;" +
          "border:1px solid #444;border-radius:5px;cursor:pointer;");
        b.addEventListener("click", close);
        p.appendChild(b);
      });
  };
})();
