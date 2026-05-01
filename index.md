---
layout: default
---

<section class="intro reveal">
  <p class="eyebrow">Pratyaksha Beri / Shad0wMazt3r</p>
  <h1>Security research, tooling, and technical writeups.</h1>
  <p class="hero-copy">Cyber Security Engineering at Iowa State University, with work across malware analysis, DFIR, CTFs, embedded systems, and practical security tooling.</p>
  <div class="intro-actions">
    <a class="text-link" href="https://github.com/Shad0wMazt3r">GitHub</a>
    <a class="text-link" href="{{ site.baseurl }}/about/">About</a>
  </div>
</section>

<section class="profile-strip reveal" aria-label="Profile highlights">
  <div class="profile-item">
    <span>Focus</span>
    <strong>Malware analysis, DFIR, offensive security</strong>
  </div>
  <div class="profile-item">
    <span>Practice</span>
    <strong>CTFs, cyber defense competitions, lab research</strong>
  </div>
  <div class="profile-item">
    <span>Tools</span>
    <strong>Python, C, Bash, Linux, web systems</strong>
  </div>
</section>

<section class="selected-work reveal">
  <div class="section-heading">
    <p class="eyebrow">Selected work</p>
    <h2>Projects and research threads</h2>
  </div>

  <div class="work-list">
    <article class="work-item">
      <span class="work-meta">AI toolkits / vulnerability research</span>
      <strong>The Scaffolding</strong>
      <span>AI-assisted bug-hunting workspace for tracing behavior, building clean proof-of-concept cases, and documenting findings.</span>
    </article>

    <article class="work-item">
      <span class="work-meta">AI toolkits / security analysis</span>
      <strong>Lattice Mind</strong>
      <span>Research and tooling around structured investigation workflows, reasoning artifacts, and turning security context into usable analysis.</span>
    </article>

    <a class="work-item" href="https://github.com/Shad0wMazt3r/HoneyEasy">
      <span class="work-meta">Security tooling / honeypots</span>
      <strong>HoneyEasy</strong>
      <span>Honeypot-oriented security tooling focused on making collection, observation, and lab deployment easier to work with.</span>
    </a>

    <a class="work-item" href="https://github.com/Shad0wMazt3r/CyTTY">
      <span class="work-meta">Python / Embedded systems</span>
      <strong>CyTTY</strong>
      <span>UART terminal tooling for Iowa State CyBot work, with voice input, text fallback, configurable UART settings, and activity logging.</span>
    </a>

    <a class="work-item" href="https://github.com/Shad0wMazt3r/Scammer-List">
      <span class="work-meta">Python / PHP / TypeScript</span>
      <strong>Scammer-List</strong>
      <span>Spam and scam detection project using profile names, website signals, message analysis, and a maintained scammer dataset.</span>
    </a>

    <a class="work-item" href="{{ site.baseurl }}/Linux-DFIR">
      <span class="work-meta">DFIR / Linux / remediation</span>
      <strong>Analyzing a Compromised Linux Machine</strong>
      <span>Security assessment writeup covering vulnerabilities, proof-of-concept evidence, impact, and remediation guidance.</span>
    </a>
  </div>
</section>

<section class="section-heading posts-heading reveal">
  <p class="eyebrow">Writing</p>
  <h2>Latest notes</h2>
</section>

<div class="posts">
  {% for post in site.posts %}
    <article class="post-card reveal">
      <div class="post-meta">{{ post.date | date: "%B %e, %Y" }}</div>

      <h2><a href="{{ site.baseurl }}{{ post.url }}">{{ post.title }}</a></h2>

      <div class="entry">
        {{ post.excerpt }}
      </div>

      <a href="{{ site.baseurl }}{{ post.url }}" class="read-more">Read article</a>
    </article>
  {% endfor %}
</div>
