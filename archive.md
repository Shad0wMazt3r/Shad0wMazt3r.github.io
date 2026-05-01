---
layout: page
title: Blog Archive
permalink: /archive/
---

<div class="archive-list">
{% for post in site.posts %}
  <a class="archive-item" href="{{ site.baseurl }}{{ post.url }}">
    <span>{{ post.date | date: "%B %e, %Y" }}</span>
    <strong>{{ post.title }}</strong>
  </a>
{% endfor %}
</div>
