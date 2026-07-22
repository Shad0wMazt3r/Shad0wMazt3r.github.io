---
layout: page
title: Archive
description: Everything I’ve published, newest first.
permalink: /archive/
---

<div class="archive-list">
{% for post in site.posts %}
  <a class="archive-item" href="{{ site.baseurl }}{{ post.url }}">
    <span class="archive-number">0{{ forloop.index }}</span>
    <span class="archive-date">{{ post.date | date: "%Y.%m.%d" }}</span>
    <strong>{{ post.title }}</strong>
    <em>{{ post.excerpt | strip_html | truncate: 150 }}</em>
    <span class="round-arrow">↗</span>
  </a>
{% endfor %}
</div>
