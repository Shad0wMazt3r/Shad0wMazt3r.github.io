---
layout: page
title: Blog Archive
permalink: /archive/
---

<section class="section-heading">
  <h2>Writing archive.</h2>
</section>

<p class="archive-summary">A chronological index of technical notes, investigations, and project writeups.</p>

<div class="archive-list">
{% for post in site.posts %}
  <a class="archive-item" href="{{ site.baseurl }}{{ post.url }}">
    <span>{{ post.date | date: "%B %e, %Y" }}</span>
    <strong>{{ post.title }}</strong>
    <em>{{ post.excerpt | strip_html | truncate: 150 }}</em>
  </a>
{% endfor %}
</div>
