(function () {
  var storedMotion = null;
  try { storedMotion = window.localStorage.getItem("shad0w-motion"); } catch (error) {}
  var motionEnabled = storedMotion !== "off";
  var reducedMotion = !motionEnabled;
  document.documentElement.classList.toggle("motion-enabled", motionEnabled);
  document.documentElement.classList.toggle("motion-paused", !motionEnabled);

  var motionToggle = document.querySelector(".motion-toggle");
  if (motionToggle) {
    var motionLabel = motionToggle.querySelector("em");
    motionToggle.setAttribute("aria-pressed", String(motionEnabled));
    motionToggle.setAttribute("aria-label", motionEnabled ? "Turn motion off" : "Turn motion on");
    if (motionLabel) motionLabel.textContent = motionEnabled ? "ON" : "OFF";
    motionToggle.addEventListener("click", function () {
      try { window.localStorage.setItem("shad0w-motion", motionEnabled ? "off" : "on"); } catch (error) {}
      window.location.reload();
    });
  }

  var reveals = document.querySelectorAll(".reveal");
  if (reducedMotion || !("IntersectionObserver" in window)) {
    reveals.forEach(function (item) { item.classList.add("is-visible"); });
  } else {
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        }
      });
    }, { rootMargin: "0px 0px -6% 0px", threshold: 0.08 });
    reveals.forEach(function (item, index) {
      item.style.transitionDelay = Math.min(index % 4, 3) * 55 + "ms";
      observer.observe(item);
    });
  }

  var progress = document.querySelector(".reading-progress span");
  var updateProgress = function () {
    var scrollable = document.documentElement.scrollHeight - window.innerHeight;
    var ratio = scrollable > 0 ? window.scrollY / scrollable : 0;
    if (progress) progress.style.width = Math.min(100, Math.max(0, ratio * 100)) + "%";
  };
  updateProgress();
  window.addEventListener("scroll", updateProgress, { passive: true });

  document.querySelectorAll("pre").forEach(function (block) {
    var code = block.querySelector("code");
    if (!code || block.querySelector(".copy-code")) return;
    var button = document.createElement("button");
    button.className = "copy-code";
    button.type = "button";
    button.textContent = "COPY";
    button.setAttribute("aria-label", "Copy code to clipboard");
    button.addEventListener("click", function () {
      navigator.clipboard.writeText(code.textContent).then(function () {
        button.textContent = "COPIED";
        window.setTimeout(function () { button.textContent = "COPY"; }, 1400);
      });
    });
    block.appendChild(button);
  });

  var uniqueByUrl = function (items) {
    var seen = {};
    return items.filter(function (item) {
      if (seen[item.url]) return false;
      seen[item.url] = true;
      return true;
    });
  };

  var getSurfaceAudit = function () {
    var resourceSelectors = [
      ["script[src]", "SCRIPT", "src"],
      ["link[rel='stylesheet'][href]", "STYLE", "href"],
      ["img[src]", "IMAGE", "src"],
      ["video[src], source[src]", "MEDIA", "src"]
    ];
    var resources = [];
    resourceSelectors.forEach(function (definition) {
      document.querySelectorAll(definition[0]).forEach(function (element) {
        try {
          var url = new URL(element.getAttribute(definition[2]), window.location.href);
          resources.push({
            url: url.href,
            origin: url.origin,
            kind: definition[1],
            external: url.origin !== window.location.origin,
            integrity: element.hasAttribute("integrity")
          });
        } catch (error) {}
      });
    });
    resources = uniqueByUrl(resources);

    var outboundLinks = [];
    document.querySelectorAll("a[href]").forEach(function (element) {
      try {
        var url = new URL(element.getAttribute("href"), window.location.href);
        if (/^https?:$/.test(url.protocol) && url.origin !== window.location.origin) {
          outboundLinks.push({ url: url.href, origin: url.origin, kind: "LINK", external: true });
        }
      } catch (error) {}
    });
    outboundLinks = uniqueByUrl(outboundLinks);

    var externalOrigins = Array.from(new Set(resources.filter(function (item) { return item.external; }).map(function (item) { return item.origin; })));
    var insecureLoads = resources.filter(function (item) { return window.location.protocol === "https:" && item.url.indexOf("http:") === 0; });
    var inlineHandlers = 0;
    document.querySelectorAll("*").forEach(function (element) {
      Array.from(element.attributes || []).forEach(function (attribute) {
        if (/^on/i.test(attribute.name)) inlineHandlers += 1;
      });
    });
    var openerRisks = Array.from(document.querySelectorAll('a[target="_blank"]')).filter(function (link) {
      return !(link.rel || "").split(/\s+/).some(function (token) { return token === "noopener" || token === "noreferrer"; });
    }).length;
    var cookies = document.cookie ? document.cookie.split(";").filter(Boolean).length : 0;
    var csp = !!document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    var referrerPolicy = document.querySelector('meta[name="referrer"]')?.getAttribute("content") || "";
    var isLocal = /^(localhost|127\.0\.0\.1|::1)$/.test(window.location.hostname);
    var tlsLevel = window.location.protocol === "https:" ? "pass" : (isLocal ? "info" : "warn");

    var checks = [
      { code: "TRANSPORT", level: tlsLevel, message: window.location.protocol === "https:" ? "TLS active" : (isLocal ? "local HTTP development origin" : "TLS not active") },
      { code: "MIXED CONTENT", level: insecureLoads.length ? "warn" : "pass", message: insecureLoads.length ? insecureLoads.length + " insecure resource(s)" : "no insecure resource loads" },
      { code: "CSP", level: csp ? "pass" : "warn", message: csp ? "policy declared" : "policy not declared" },
      { code: "REFERRER", level: referrerPolicy ? "pass" : "warn", message: referrerPolicy || "policy not declared" },
      { code: "DOM HANDLERS", level: inlineHandlers ? "warn" : "pass", message: inlineHandlers + " inline event handler(s)" },
      { code: "OPENER RISK", level: openerRisks ? "warn" : "pass", message: openerRisks + " unsafe new-tab link(s)" },
      { code: "COOKIES", level: cookies ? "info" : "pass", message: cookies + " client-readable cookie(s)" },
      { code: "THIRD PARTY", level: externalOrigins.length ? "info" : "pass", message: externalOrigins.length + " loaded external origin(s)" }
    ];
    var counts = checks.reduce(function (totals, check) {
      totals[check.level] += 1;
      return totals;
    }, { pass: 0, info: 0, warn: 0 });

    return {
      resources: resources,
      links: outboundLinks,
      externalOrigins: externalOrigins,
      inlineHandlers: inlineHandlers,
      csp: csp,
      tls: window.location.protocol === "https:",
      local: isLocal,
      checks: checks,
      counts: counts
    };
  };

  var audit = getSurfaceAudit();
  var auditResources = document.querySelector("[data-audit-resources]");
  var auditOrigins = document.querySelector("[data-audit-origins]");
  var auditSummary = document.querySelector("[data-audit-summary]");
  var liveState = document.querySelector("[data-live-state]");
  var liveSequence = document.querySelector("[data-live-seq]");
  var liveUptime = document.querySelector("[data-live-uptime]");
  var liveEvents = document.querySelector("[data-live-events]");
  var auditMeters = Array.from(document.querySelectorAll("[data-audit-meter]"));
  var auditMatrix = document.querySelector("[data-audit-matrix]");
  var startedAt = Date.now();
  var sequence = 1;
  var checkIndex = 3;

  var formatTime = function () { return new Date().toISOString().slice(11, 19); };
  var formatUptime = function () {
    var seconds = Math.floor((Date.now() - startedAt) / 1000);
    return String(Math.floor(seconds / 60)).padStart(2, "0") + ":" + String(seconds % 60).padStart(2, "0");
  };
  var updateAuditSummary = function () {
    if (auditResources) auditResources.textContent = audit.resources.length + " loaded · " + audit.links.length + " outbound";
    if (auditOrigins) auditOrigins.textContent = audit.externalOrigins.length ? audit.externalOrigins.map(function (origin) { return origin.replace(/^https?:\/\//, ""); }).join(", ") : "None loaded";
    if (auditSummary) auditSummary.textContent = audit.counts.pass + " pass · " + audit.counts.info + " info · " + audit.counts.warn + " warn";
    var diagnosticTls = document.querySelector('[data-diagnostic="tls"]');
    var diagnosticCsp = document.querySelector('[data-diagnostic="csp"]');
    var diagnosticOrigins = document.querySelector('[data-diagnostic="origins"]');
    var diagnosticSinks = document.querySelector('[data-diagnostic="sinks"]');
    if (diagnosticTls) diagnosticTls.textContent = audit.tls ? "ON" : (audit.local ? "DEV" : "OFF");
    if (diagnosticCsp) diagnosticCsp.textContent = audit.csp ? "ON" : "NONE";
    if (diagnosticOrigins) diagnosticOrigins.textContent = String(audit.externalOrigins.length).padStart(2, "0");
    if (diagnosticSinks) diagnosticSinks.textContent = String(audit.inlineHandlers).padStart(2, "0");
    auditMeters.forEach(function (meter, index) {
      var check = audit.checks[index];
      meter.className = check ? "audit-" + check.level : "";
      meter.setAttribute("title", check ? check.code + ": " + check.message : "");
    });
    if (auditMatrix) {
      auditMatrix.innerHTML = "";
      audit.checks.forEach(function (check) {
        var item = document.createElement("div");
        item.className = "audit-matrix-item audit-" + check.level;
        item.title = check.message;
        var label = document.createElement("span");
        var result = document.createElement("b");
        label.textContent = check.code;
        result.textContent = check.level.toUpperCase();
        item.append(label, result);
        auditMatrix.appendChild(item);
      });
    }
  };

  var appendAuditEvent = function (check) {
    if (!liveEvents) return;
    var item = document.createElement("li");
    item.className = "audit-" + check.level + (motionEnabled ? " is-new" : "");
    var time = document.createElement("time");
    var code = document.createElement("span");
    var message = document.createElement("strong");
    time.textContent = formatTime();
    code.textContent = check.code;
    message.textContent = check.message;
    item.append(time, code, message);
    liveEvents.prepend(item);
    while (liveEvents.children.length > 3) liveEvents.removeChild(liveEvents.lastElementChild);
  };

  var runAuditTick = function () {
    audit = getSurfaceAudit();
    var check = audit.checks[checkIndex % audit.checks.length];
    checkIndex += 1;
    sequence += 1;
    appendAuditEvent(check);
    updateAuditSummary();
    if (liveState) liveState.textContent = check.level === "warn" ? "REVIEW" : "MONITORING";
    if (liveSequence) liveSequence.textContent = String(sequence).padStart(4, "0");
    if (liveUptime) liveUptime.textContent = formatUptime();
    var activeMeter = auditMeters[(checkIndex - 1) % auditMeters.length];
    if (activeMeter && motionEnabled) {
      activeMeter.classList.remove("is-active");
      void activeMeter.offsetWidth;
      activeMeter.classList.add("is-active");
    }
  };
  updateAuditSummary();
  if (liveEvents) {
    liveEvents.innerHTML = "";
    audit.checks.slice(0, 3).reverse().forEach(appendAuditEvent);
    window.setInterval(runAuditTick, motionEnabled ? 1800 : 8000);
    window.setInterval(function () { if (liveUptime) liveUptime.textContent = formatUptime(); }, 1000);
  }

  var getProgressiveResult = function (key) {
    audit = getSurfaceAudit();
    var imagesMissingAlt = document.querySelectorAll("img:not([alt])").length;
    var ids = Array.from(document.querySelectorAll("[id]")).map(function (element) { return element.id; });
    var duplicateIds = ids.length - new Set(ids).size;
    var brokenFragments = Array.from(document.querySelectorAll('a[href^="#"]')).filter(function (link) {
      var fragment = link.getAttribute("href").slice(1);
      return fragment && !document.getElementById(fragment);
    }).length;
    var javascriptLinks = document.querySelectorAll('a[href^="javascript:"]').length;
    var iframes = document.querySelectorAll("iframe").length;
    var externalResources = audit.resources.filter(function (resource) { return resource.external; });
    var thirdPartyResources = externalResources.filter(function (resource) {
      try { return new URL(resource.url).hostname !== window.location.hostname; } catch (error) { return true; }
    });
    var missingIntegrity = thirdPartyResources.filter(function (resource) {
      return (resource.kind === "SCRIPT" || resource.kind === "STYLE") && !resource.integrity;
    }).length;
    var insecureOutbound = audit.links.filter(function (link) { return link.url.indexOf("http:") === 0; }).length;
    var openerRisks = Array.from(document.querySelectorAll('a[target="_blank"]')).filter(function (link) {
      return !(link.rel || "").split(/\s+/).some(function (token) { return token === "noopener" || token === "noreferrer"; });
    }).length;
    var mailtoLinks = document.querySelectorAll('a[href^="mailto:"]').length;
    var storageKeys = 0;
    try { storageKeys = window.localStorage.length; } catch (error) {}
    var cookies = document.cookie ? document.cookie.split(";").filter(Boolean).length : 0;
    var analytics = document.querySelectorAll('script[src*="analytics"], script[src*="gtag"], script[src*="google-analytics"]').length;
    var forms = document.querySelectorAll("form").length;

    var definitions = {
      surface: {
        title: "Client attack surface",
        level: audit.counts.warn ? "warn" : (audit.counts.info ? "info" : "pass"),
        summary: "Counts the code, links, and browser controls loaded on this page.",
        details: [["Loaded resources", audit.resources.length], ["Outbound destinations", audit.links.length], ["Current posture", audit.counts.pass + "P / " + audit.counts.info + "I / " + audit.counts.warn + "W"]]
      },
      dom: {
        title: "DOM sink review",
        level: audit.inlineHandlers || javascriptLinks ? "warn" : "pass",
        summary: "Looks for inline handlers, javascript: URLs, and embedded frames.",
        details: [["Inline handlers", audit.inlineHandlers], ["javascript: links", javascriptLinks], ["Embedded frames", iframes]]
      },
      dependencies: {
        title: "Dependency boundary",
        level: missingIntegrity ? "warn" : (thirdPartyResources.length ? "info" : "pass"),
        summary: "Checks what third-party code the page loads and whether it has integrity metadata.",
        details: [["Cross-origin loads", externalResources.length], ["Third-party loads", thirdPartyResources.length], ["Missing SRI", missingIntegrity]]
      },
      content: {
        title: "Content integrity",
        level: imagesMissingAlt || duplicateIds || brokenFragments ? "warn" : "pass",
        summary: "Checks for missing alt text, duplicate IDs, and broken anchor links.",
        details: [["Missing alt text", imagesMissingAlt], ["Duplicate IDs", duplicateIds], ["Broken fragments", brokenFragments]]
      },
      outbound: {
        title: "Outbound-link safety",
        level: insecureOutbound || openerRisks ? "warn" : "pass",
        summary: "Checks external links for plain HTTP and unsafe new-tab behavior.",
        details: [["External links", audit.links.length], ["Insecure HTTP", insecureOutbound], ["Opener risks", openerRisks], ["Mail links", mailtoLinks]]
      },
      privacy: {
        title: "Privacy surface",
        level: analytics || cookies ? "info" : "pass",
        summary: "Checks cookies, local storage, analytics, and forms.",
        details: [["Readable cookies", cookies], ["Local storage keys", storageKeys], ["Analytics scripts", analytics], ["Forms", forms]]
      }
    };
    return definitions[key];
  };

  var scanDrawer = document.querySelector("[data-progressive-audit]");
  var scanToggle = scanDrawer?.querySelector(".scan-drawer-toggle");
  var scanResults = document.querySelector("[data-progressive-results]");
  var scanProgress = document.querySelector("[data-scan-progress]");
  var scanWarnings = document.querySelector("[data-scan-warnings]");
  var scanHeadline = document.querySelector("[data-scan-headline]");
  var scanTargets = Array.from(document.querySelectorAll("[data-scan]"));
  var completedScans = {};
  var warningCount = 0;
  var scanPulseTimer = 0;

  var setScanDrawerOpen = function (open) {
    if (!scanDrawer || !scanToggle) return;
    scanDrawer.classList.toggle("is-open", open);
    scanToggle.setAttribute("aria-expanded", String(open));
  };
  if (scanToggle) {
    scanToggle.addEventListener("click", function () {
      setScanDrawerOpen(!scanDrawer.classList.contains("is-open"));
    });
  }

  var unlockScan = function (key) {
    if (!scanDrawer || !scanResults || completedScans[key]) return;
    var result = getProgressiveResult(key);
    if (!result) return;
    completedScans[key] = true;
    var index = Object.keys(completedScans).length;
    var card = document.createElement("article");
    card.className = "scan-result audit-" + result.level + (motionEnabled ? " is-new" : "");
    var cardHeader = document.createElement("header");
    var cardIndex = document.createElement("span");
    var cardTime = document.createElement("time");
    cardIndex.textContent = "SCAN " + String(index).padStart(2, "0") + " / " + key.toUpperCase();
    cardTime.textContent = formatTime() + " UTC";
    cardHeader.append(cardIndex, cardTime);
    var title = document.createElement("h3");
    var summary = document.createElement("p");
    var details = document.createElement("ul");
    title.textContent = result.title;
    summary.textContent = result.summary;
    result.details.forEach(function (detail) {
      var row = document.createElement("li");
      var label = document.createElement("span");
      var value = document.createElement("b");
      label.textContent = detail[0];
      value.textContent = detail[1];
      row.append(label, value);
      details.appendChild(row);
    });
    card.append(cardHeader, title, summary, details);
    scanResults.prepend(card);
    if (scanProgress) scanProgress.textContent = index + " / " + scanTargets.length;
    if (result.level === "warn") warningCount += 1;
    if (scanWarnings) scanWarnings.textContent = warningCount + " WARN";
    if (scanHeadline) scanHeadline.textContent = result.title + " complete";
    if (motionEnabled) {
      window.clearTimeout(scanPulseTimer);
      scanDrawer.classList.remove("has-update");
      void scanDrawer.offsetWidth;
      scanDrawer.classList.add("has-update");
      scanPulseTimer = window.setTimeout(function () { scanDrawer.classList.remove("has-update"); }, 1200);
    }
  };

  if (scanTargets.length) {
    if ("IntersectionObserver" in window) {
      var scanObserver = new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            unlockScan(entry.target.getAttribute("data-scan"));
            scanObserver.unobserve(entry.target);
          }
        });
      }, { rootMargin: "0px 0px -24% 0px", threshold: 0.18 });
      scanTargets.forEach(function (target) { scanObserver.observe(target); });
    } else {
      scanTargets.forEach(function (target) { unlockScan(target.getAttribute("data-scan")); });
    }
    var scanScrollQueued = false;
    var checkScanPositions = function () {
      scanTargets.forEach(function (target) {
        var rect = target.getBoundingClientRect();
        if (rect.top < window.innerHeight * 0.82 && rect.bottom > window.innerHeight * 0.08) {
          unlockScan(target.getAttribute("data-scan"));
        }
      });
      scanScrollQueued = false;
    };
    window.addEventListener("scroll", function () {
      if (!scanScrollQueued) {
        scanScrollQueued = true;
        window.requestAnimationFrame(checkScanPositions);
      }
    }, { passive: true });
    checkScanPositions();
  }

  var utc = document.querySelector('[data-diagnostic="utc"]');
  var updateDiagnostics = function () {
    var scrollbarWidth = Math.max(0, window.innerWidth - document.documentElement.clientWidth);
    document.documentElement.style.setProperty("--scrollbar-width", scrollbarWidth + "px");
    document.documentElement.style.setProperty("--half-scrollbar-width", (scrollbarWidth / 2) + "px");
    if (utc) utc.textContent = formatTime();
  };
  updateDiagnostics();
  window.setInterval(updateDiagnostics, 1000);
  window.addEventListener("resize", updateDiagnostics, { passive: true });

  var cursorSignal = document.querySelector(".cursor-signal");
  if (cursorSignal && window.matchMedia("(pointer: fine)").matches && motionEnabled) {
    window.addEventListener("pointermove", function (event) {
      cursorSignal.classList.add("is-active");
      cursorSignal.style.transform = "translate3d(" + event.clientX + "px," + event.clientY + "px,0)";
    }, { passive: true });
    document.documentElement.addEventListener("mouseleave", function () { cursorSignal.classList.remove("is-active"); });
  }

  if (motionEnabled && window.matchMedia("(pointer: fine)").matches) {
    document.querySelectorAll(".project-card").forEach(function (card) {
      card.addEventListener("pointermove", function (event) {
        var rect = card.getBoundingClientRect();
        var x = (event.clientX - rect.left) / rect.width - 0.5;
        var y = (event.clientY - rect.top) / rect.height - 0.5;
        card.style.transform = "perspective(900px) rotateX(" + (-y * 2.5) + "deg) rotateY(" + (x * 2.5) + "deg) translateY(-4px)";
        card.style.setProperty("--spot-x", ((x + 0.5) * 100) + "%");
        card.style.setProperty("--spot-y", ((y + 0.5) * 100) + "%");
      });
      card.addEventListener("pointerleave", function () { card.style.transform = ""; });
    });
    document.querySelectorAll(".button, .arrow-link").forEach(function (control) {
      control.addEventListener("pointermove", function (event) {
        var rect = control.getBoundingClientRect();
        control.style.transform = "translate3d(" + ((event.clientX - rect.left - rect.width / 2) * 0.1) + "px," + ((event.clientY - rect.top - rect.height / 2) * 0.16) + "px,0)";
      });
      control.addEventListener("pointerleave", function () { control.style.transform = ""; });
    });
  }

  var heroPrimary = document.querySelector(".hero-primary");
  var signalPanel = document.querySelector(".signal-panel");
  if (heroPrimary && signalPanel && motionEnabled) {
    var parallaxQueued = false;
    var updateParallax = function () {
      var distance = Math.min(window.scrollY, window.innerHeight);
      heroPrimary.style.setProperty("--hero-shift", (distance * 0.055) + "px");
      signalPanel.style.setProperty("--panel-shift", (distance * -0.035) + "px");
      parallaxQueued = false;
    };
    window.addEventListener("scroll", function () {
      if (!parallaxQueued) {
        parallaxQueued = true;
        window.requestAnimationFrame(updateParallax);
      }
    }, { passive: true });
    updateParallax();
  }

  var canvas = document.getElementById("signal-canvas");
  if (canvas) {
    var context = canvas.getContext("2d");
    var graphNodes = [];
    var pointer = { x: -999, y: -999 };
    var frame = 0;
    var mapLabel = document.querySelector("[data-audit-maplabel]");

    var resizeSurfaceMap = function () {
      var rect = canvas.getBoundingClientRect();
      var ratio = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.max(1, Math.round(rect.width * ratio));
      canvas.height = Math.max(1, Math.round(rect.height * ratio));
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
      var surfaceItems = audit.resources.concat(audit.links.slice(0, 8));
      var cx = rect.width / 2;
      var cy = rect.height / 2;
      graphNodes = [{ x: cx, y: cy, baseX: cx, baseY: cy, kind: "PAGE", external: false, root: true, phase: 0 }];
      surfaceItems.forEach(function (item, index) {
        var angle = -Math.PI / 2 + (Math.PI * 2 * index / Math.max(surfaceItems.length, 1));
        var radius = Math.min(rect.width, rect.height) * (item.external ? 0.42 : 0.29);
        graphNodes.push({
          x: cx + Math.cos(angle) * radius,
          y: cy + Math.sin(angle) * radius,
          baseX: cx + Math.cos(angle) * radius,
          baseY: cy + Math.sin(angle) * radius,
          kind: item.kind,
          origin: item.origin,
          external: item.external,
          root: false,
          phase: index * 0.73
        });
      });
      if (mapLabel) mapLabel.textContent = graphNodes.length + " NODES / " + audit.externalOrigins.length + " LOADED EXT";
    };

    var drawSurfaceMap = function () {
      var width = canvas.clientWidth;
      var height = canvas.clientHeight;
      var now = Date.now() / 1000;
      context.clearRect(0, 0, width, height);
      var root = graphNodes[0];
      graphNodes.forEach(function (node, index) {
        if (!node.root && motionEnabled) {
          node.x = node.baseX + Math.sin(now * 0.7 + node.phase) * 3;
          node.y = node.baseY + Math.cos(now * 0.55 + node.phase) * 3;
        }
        if (!node.root) {
          context.strokeStyle = node.external ? "rgba(199,255,74,.34)" : "rgba(241,239,229,.13)";
          context.lineWidth = node.external ? 0.8 : 0.5;
          context.beginPath();
          context.moveTo(root.x, root.y);
          context.lineTo(node.x, node.y);
          context.stroke();
        }
        var distance = Math.hypot(node.x - pointer.x, node.y - pointer.y);
        var highlighted = distance < 22;
        var size = node.root ? 6 : (node.external ? 4 : 3);
        if (node.kind === "LINK") {
          context.save();
          context.translate(node.x, node.y);
          context.rotate(Math.PI / 4);
          context.strokeStyle = "rgba(199,255,74,.92)";
          context.lineWidth = highlighted ? 1.5 : 1;
          context.strokeRect(-size / 2, -size / 2, size, size);
          context.restore();
        } else if (node.root || node.external || highlighted) {
          context.fillStyle = node.external || highlighted ? "rgba(199,255,74,.96)" : "rgba(241,239,229,.82)";
          context.fillRect(node.x - size / 2, node.y - size / 2, size, size);
        } else {
          context.strokeStyle = "rgba(241,239,229,.72)";
          context.lineWidth = .8;
          context.strokeRect(node.x - size / 2, node.y - size / 2, size, size);
        }
        if (!node.root) {
          context.fillStyle = node.external ? "rgba(199,255,74,.72)" : "rgba(152,155,144,.62)";
          context.font = "8px Cascadia Code, Consolas, monospace";
          context.fillText(node.kind, node.x + 6, node.y - 5);
        }
      });
      if (motionEnabled) frame = window.requestAnimationFrame(drawSurfaceMap);
    };

    canvas.addEventListener("pointermove", function (event) {
      var rect = canvas.getBoundingClientRect();
      pointer.x = event.clientX - rect.left;
      pointer.y = event.clientY - rect.top;
      var nearest = graphNodes.reduce(function (best, node) {
        var distance = Math.hypot(node.x - pointer.x, node.y - pointer.y);
        return distance < best.distance ? { node: node, distance: distance } : best;
      }, { node: null, distance: Infinity });
      if (mapLabel && nearest.node && nearest.distance < 26) {
        mapLabel.textContent = nearest.node.kind + " / " + (nearest.node.external ? "EXTERNAL" : "SAME ORIGIN");
      }
    });
    canvas.addEventListener("pointerleave", function () {
      pointer.x = -999;
      pointer.y = -999;
      if (mapLabel) mapLabel.textContent = graphNodes.length + " NODES / " + audit.externalOrigins.length + " LOADED EXT";
    });
    window.addEventListener("resize", function () {
      window.cancelAnimationFrame(frame);
      resizeSurfaceMap();
      drawSurfaceMap();
    });
    resizeSurfaceMap();
    drawSurfaceMap();
  }
})();
