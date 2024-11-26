---
title: nip4 progress
---

libvips.org OpenCollective has generously given me a year of funding [to
complete nip4](https://github.com/jcupitt/nip4). This is an update of [the
libvips GUI, nip2](https://github.com/libvips/nip2), to the gtk4 toolkit,
and to the vips8 API.

nip2 was written between about 1997 and 2003 and depends on a lot of
frameworks from the period. These are becoming extremely elderly now,
and nip2 is getting difficult to maintain. It's also looking increasingly
old-fashioned.

![Screenshot](https://opencollective-production.s3.us-west-1.amazonaws.com/update/c944d166-2a2a-4e96-8afe-2a08389e84ae/screenshot.png)

nip4 is hoping to fix this. It has the following goals:

1. Update from the gtk2 GUI toolkit to gtk4, the current version. This
is a lot of work -- the drawing model is completely different, and there
are many, many changes in best practice. As a test, I [updated `vipsdisp`
to gtk4](https://github.com/jcupitt/vipsdisp). The image display widget in
this viewer is the thing that will display images in nip4.

2. Switch to the vips8 API. We rewrote libvips to make vips8 between about
2010 and 2015, but nip2 was obviously stuck on the old vips7 API. nip4 has
removed all the old vips7 code and redesigned for vips8. nip2 was the last
large-scale user of vips7, as far as I know, so completing nip4 will let
us build libvips with deprecated code removed by default.

3. Complete backwards compatibility. nip4 aims to be able to run the whole
of the nip2 test suite unmodified. 

4. Prettier, simpler, faster, modernised.

nip4 is now loading the first 5 test nip2 workspaces correctly. The big change
from the UI point of view is full animation for interactions. Everything
slides around as you work:

<iframe width="560" height="315" src="https://www.youtube.com/embed/Z4TpOLh2Lno?si=5F-SEp3wS37SYBDv" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

Next steps:

1. Get all the old nip2 test workspaces loading. This will involve
implementing a few more workspace widgets. Plotting is probably the most work.

2. Finish drag/drop and copy/paste. It's only half-there right now.

3. Add the toolkit menu and browser. This will probably be a bar down the left.

4. Perhaps implement a cut down and polished version of the programming
and debugging interface from nip2.

5. UI for per-workspace definitions needs to go in.

6. The image processing menus are all currently designed around vips7. A
new set of vips8 menus could be a useful simplification.

7. Do windows and mac builds. We have win and mac builds for vipsdisp
done already.

And I think that would be enough for a release, hopefully in the first half
of 2025.

