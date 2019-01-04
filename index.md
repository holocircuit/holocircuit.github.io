---
# You don't need to edit this file, it's empty on purpose.
# Edit theme's home layout instead if you wanna make some changes
# See: https://jekyllrb.com/docs/themes/#overriding-theme-defaults
layout: default
---

# About
Member of [@tq2ctf](https://tq2c.tf).
I studied mathematics, and mainly focus on cryptography challenges.

Theme from [Github Pages](https://github.com/pages-themes/hacker).

# Posts
<ul class="posts">
    {% for post in site.posts %}
      <li><span>{{ post.date | date_to_string }}</span>: <a href="{{ post.url }}">{{ post.title }}</a></li>
    {% endfor %}
</ul>
