---
title: nip4 November progress
---

I've done another month on nip4 -- plotting is in now, and I've done a
first version of the new toolkit browser.

<iframe width="560" height="315" src="https://www.youtube.com/embed/laS5SZzdnAE" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

We were using goffice to render plots, but sadly it's still gtk3. I did
a bit of hacking and got it working with gtk4, but I don't think that's a
very maintainable way forwards. Instead, I've switched to kplot:

https://github.com/kristapsdz/kplot

This is a very simple library, but it can do everything nip4 needs, more
or less. I make a fork and added better axis labeling and picking.

I've also mostly finished the new toolkit browser. I found the nip2 Toolkit
menu difficult to use, so it's now a scrolling bar down the left of the
window. It also supports searching, so you can find things by name as well
as by category.

There are some obvious missing features, and it's still a bit crashy,
but it's now just about possible to use nip4 for work. I'll do a bit more
polishing, then try to make a first alpha release.

