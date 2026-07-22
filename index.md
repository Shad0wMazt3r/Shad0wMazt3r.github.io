---
layout: default
---

<aside class="scan-drawer" data-progressive-audit aria-label="Progressive page security audit">
  <button class="scan-drawer-toggle" type="button" aria-expanded="false" aria-controls="progressive-audit-results">
    <span><i></i> PAGE AUDIT</span>
    <span class="scan-drawer-status"><em data-scan-warnings>0 WARN</em><b data-scan-progress>0 / 6</b></span>
  </button>
  <div class="scan-drawer-body" id="progressive-audit-results">
    <header><span>BACKGROUND CHECKS RUN AS YOU SCROLL</span><strong data-scan-headline aria-live="polite">No checks run yet</strong></header>
    <div class="scan-result-stack" data-progressive-results></div>
  </div>
</aside>

<section class="home-hero reveal" data-scan="surface">
  <div class="hero-primary">
    <p class="kicker"><span>SECURITY RESEARCH</span> / AMES, IA</p>
    <h1 aria-label="I break things. Then I write down why.">
      <span class="hero-line">I break things.</span>
      <span class="hero-line signal-word">Then I write down why.</span>
    </h1>
    <p class="hero-deck">I’m Pratyaksha Beri. I study cybersecurity at Iowa State and spend most of my time on vulnerability research, malware, DFIR, and security agents.</p>
    <div class="hero-actions">
      <a class="button button-primary" href="#latest">Read the notes <span>↓</span></a>
      <a class="button button-ghost" href="https://github.com/Shad0wMazt3r">GitHub <span>↗</span></a>
    </div>
  </div>

  <aside class="signal-panel" aria-label="Research focus">
    <div class="signal-topline">
      <span>LIVE PAGE AUDIT <small>/ CLIENT-SIDE</small></span>
      <span class="signal-state"><i></i> <b data-live-state>INSPECTING</b></span>
    </div>
    <div class="signal-viz" aria-hidden="true">
      <canvas id="signal-canvas"></canvas>
      <div class="scope-ring ring-one"></div>
      <div class="scope-ring ring-two"></div>
      <div class="scope-ring ring-three"></div>
      <div class="scope-crosshair"></div>
      <div class="scope-sweep"></div>
      <span class="scope-coord" data-audit-maplabel>MAPPING SURFACE</span>
      <div class="surface-legend">
        <span><i class="legend-internal"></i>SAME ORIGIN</span>
        <span><i class="legend-external"></i>LOADED EXTERNAL</span>
        <span><i class="legend-link"></i>OUTBOUND LINK</span>
      </div>
    </div>
    <div class="live-console">
      <div class="live-console-head">
        <span>SECURITY CHECKS</span>
        <span>SCAN <b data-live-seq>0001</b> · UP <b data-live-uptime>00:00</b></span>
      </div>
      <ol class="live-events" data-live-events aria-live="off">
        <li><time>00:00:00</time><span>TRANSPORT</span><strong>evaluating protocol</strong></li>
        <li><time>00:00:00</time><span>DEPENDENCIES</span><strong>mapping loaded origins</strong></li>
        <li><time>00:00:00</time><span>DOM SINKS</span><strong>checking inline handlers</strong></li>
      </ol>
      <div class="live-pulse" aria-label="Audit result meter">
        <i data-audit-meter></i><i data-audit-meter></i><i data-audit-meter></i><i data-audit-meter></i>
        <i data-audit-meter></i><i data-audit-meter></i><i data-audit-meter></i><i data-audit-meter></i>
      </div>
    </div>
    <dl class="signal-data">
      <div><dt>RESOURCES</dt><dd data-audit-resources>Mapping…</dd></div>
      <div><dt>EXTERNAL ORIGINS</dt><dd data-audit-origins>Mapping…</dd></div>
      <div><dt>POSTURE</dt><dd data-audit-summary>Audit pending</dd></div>
    </dl>
  </aside>
</section>

<div class="transmission-marquee" aria-hidden="true">
  <div class="transmission-track">
    <span>FIND IT</span><i>◆</i><span>REPRODUCE IT</span><i>◆</i><span>WRITE IT DOWN</span><i>◆</i><span>BUILD THE TOOL</span><i>◆</i>
    <span>FIND IT</span><i>◆</i><span>REPRODUCE IT</span><i>◆</i><span>WRITE IT DOWN</span><i>◆</i><span>BUILD THE TOOL</span><i>◆</i>
  </div>
</div>

<section class="discipline-strip reveal" aria-label="Areas of practice" data-scan="dom">
  <div><span>01</span><strong>Offensive security</strong><small>Find it. Reproduce it.</small></div>
  <div><span>02</span><strong>DFIR & malware</strong><small>Work backward from the evidence.</small></div>
  <div><span>03</span><strong>Security agents</strong><small>Test what actually helps.</small></div>
  <div><span>04</span><strong>Security tooling</strong><small>Automate the boring parts.</small></div>
</section>

<section id="latest" class="latest-section" data-scan="dependencies">
  <div class="section-intro reveal">
    <div>
      <p class="kicker"><span>LATEST WRITING</span></p>
      <h2>What I’ve been working on.</h2>
    </div>
    <a class="arrow-link" href="{{ site.baseurl }}/archive/">View archive <span>↗</span></a>
  </div>

  <div class="featured-posts" data-scan="content">
    {% for post in site.posts limit:1 %}
    <article class="featured-post reveal">
      <a class="featured-number" href="{{ site.baseurl }}{{ post.url }}" aria-label="Read {{ post.title }}">01</a>
      <div class="featured-copy">
        <div class="post-taxonomy">FIELD NOTE · AGENTIC SECURITY</div>
        <h3><a href="{{ site.baseurl }}{{ post.url }}">{{ post.title }}</a></h3>
        <p>{{ post.excerpt | strip_html }}</p>
        <a class="arrow-link" href="{{ site.baseurl }}{{ post.url }}">Read the full note <span>→</span></a>
      </div>
      <div class="featured-meta">
        <span>{{ post.date | date: "%Y.%m.%d" }}</span>
        <span>LONGFORM / RESEARCH</span>
      </div>
    </article>
    {% endfor %}

    <div class="post-list">
      {% for post in site.posts offset:1 %}
      <article class="post-row reveal">
        <span class="post-row-number">0{{ forloop.index | plus: 1 }}</span>
        <div>
          <div class="post-taxonomy">TECHNICAL NOTE · {{ post.date | date: "%Y" }}</div>
          <h3><a href="{{ site.baseurl }}{{ post.url }}">{{ post.title }}</a></h3>
        </div>
        <p>{{ post.excerpt | strip_html | truncate: 170 }}</p>
        <a class="round-arrow" href="{{ site.baseurl }}{{ post.url }}" aria-label="Read {{ post.title }}">↗</a>
      </article>
      {% endfor %}
    </div>
  </div>
</section>

<section class="project-section" data-scan="outbound">
  <div class="section-coordinate reveal" aria-hidden="true">
    <span>SECTOR / PROJECTS</span><span>METHOD / REPRODUCE → VERIFY</span><span>EVIDENCE / SOURCE-CONFIRMED</span>
  </div>
  <div class="section-intro reveal">
    <div>
      <p class="kicker"><span>PROJECTS</span></p>
      <h2>Things I’m building.</h2>
    </div>
    <p class="section-note">Some are experiments. Some are tools I use. All of them started with a security problem I wanted to understand.</p>
  </div>

  <div class="project-grid">
    <article class="project-card project-card-lead reveal">
      <div class="project-card-top"><span>01 / RESEARCH PLATFORM</span><span>IN DEVELOPMENT</span></div>
      <div>
        <h3>The Scaffolding</h3>
        <p>My bug-hunting setup for giving agents the right tools and context without drowning them in either.</p>
      </div>
      <div class="project-tags"><span>AGENTS</span><span>APPSEC</span><span>RESEARCH</span></div>
    </article>

    <article class="project-card reveal">
      <div class="project-card-top"><span>02 / ANALYSIS SYSTEM</span><span>ACTIVE</span></div>
      <div>
        <h3>Lattice Mind</h3>
        <p>A scanner agents can steer: change a payload, rerun a check, and verify a hunch without writing a new script every time.</p>
      </div>
      <div class="project-tags"><span>AI</span><span>WORKFLOWS</span></div>
    </article>

    <a class="project-card reveal" href="https://github.com/Shad0wMazt3r/HoneyEasy">
      <div class="project-card-top"><span>03 / HONEYPOT TOOLING</span><span>GITHUB ↗</span></div>
      <div>
        <h3>HoneyEasy</h3>
        <p>A simpler way to deploy honeypots and keep track of what they collect.</p>
      </div>
      <div class="project-tags"><span>PYTHON</span><span>TELEMETRY</span></div>
    </a>

    <a class="project-card reveal" href="https://github.com/Shad0wMazt3r/CyTTY">
      <div class="project-card-top"><span>04 / EMBEDDED SYSTEMS</span><span>GITHUB ↗</span></div>
      <div>
        <h3>CyTTY</h3>
        <p>A UART terminal I built for CyBot, with voice control, configurable serial settings, and activity logs.</p>
      </div>
      <div class="project-tags"><span>PYTHON</span><span>UART</span></div>
    </a>
  </div>
</section>

<section class="contact-band reveal" data-scan="privacy">
  <p class="kicker"><span>CONTACT</span></p>
  <div>
    <h2>Found something weird?<br>I’d like to hear about it.</h2>
    <a class="button button-primary" href="mailto:pratyakshaberi@gmail.com">Start a conversation <span>↗</span></a>
  </div>
</section>
