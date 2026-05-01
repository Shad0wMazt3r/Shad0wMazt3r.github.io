---
layout: default
---

<section class="intro reveal">
  <p class="eyebrow">Security research portfolio</p>
  <h1>Notes and Observations on Cybersecurity.</h1>
  <p class="hero-copy">Writeups, investigation notes, and lessons from hands-on security work.</p>
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
