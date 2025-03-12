---
title: nip4 for nip2 users
---

The [test release of nip4 is now out](https://github.com/jcupitt/nip4)
and it seems to work OK on Linux, Windows and macOS. I thought I'd write a few
notes for users of nip2 outlining the big changes and the bits of it that are
still missing. 

## Background

nip2 was mostly finished around 2000, with the final big feature going
in in 2005 (I think). It still works fine, but it was becoming difficult
to maintain since the major libraries it depends on (libvips-7 for image
processing, gtk-2 for the user interface widgets, and goffice-0.8 for
plotting) have long fallen out of maintenance.

It was also starting to look rather crude and old-fashioned! Something
of a trip back in time, with brightly coloured elements and hard edges and
corners everywhere.  And nip2 is something of a "kitchen sink" program ---
it has lots of features which seemed like a good idea at the time, but
which I never ended up using much.

![nip2]({{ site.baseurl }}/assets/images/nip2.png)

nip4 is a rewrite of nip2 with the following aims:

- can load and process all nip2 workspaces

- use the modern gtk-4 user-interface toolkit

- a cleaner, simpler interface

- use libvips-8 for image processing

- use kplot for graphing

- simple build and distribution process for Linux, macOS and Windows

And here nip4 is, running the same very complex workspace:

![nip4]({{ site.baseurl }}/assets/images/nip4-12-mar-25.png)

## New image window

One of the biggest changes is a completely new image view window. It
understands most pyramidal image formats, it does smooth zooming, it runs on
your GPU, it handles alpha, it supports animation and multipage images, and it
should be a lot quicker.

<video src="https://github.com/user-attachments/assets/32a400ed-106a-457d-9390-f5f0142300aa" controls="controls" style="max-width: 730px;">
</video>

The big changes from a user-interface point of view are:

- Drag with the left mouse button to pan
- Scrollwheel to zoom
- Right-click (or "burger menu" in the top right) for the main menu, then 
  **View / Properties** or **Alt-Enter** to view image metadata
- **Save as ...** to save as some file, with a dialog to set file format
  properties
- **View / Display control bar** to get he scale and offset sliders, plus a
  useful menu of visualisation tools
- The display control bar has a thing for the display mode for animated and
  multipage images -- you can pause animation, view the pages or frames as a
  strip, and join separate-plane images into colour images
- **Ctrl-.** and **Ctrl-,** for next page and previous page in multipage 
  images, or to step though frames in an animated image
- You can drag and drop or copy-paste images into and out of the image view
  window, so you can do Print Screen, then ^V to paste a desktop snapshot, for
  example, or crop an image the ^C and ^V into another image editor
- Use the **<** and **>** buttons in the titlebar to step through the images in
  the same directory as this image

Most other things are the same, so number keys for zoom levels, **i**
and **o** for zoom in and out, **Ctrl-drag** to mark regions, cursor keys to
pan, and so on.

## Toolkit bar

The big change in the main window is the new toolkit bar down the left,
replacing the old Toolkits menu.

![nip4]({{ site.baseurl }}/assets/images/nip4-toolkits.png)

It slides left and right as you select items or go back, and it stays open
after clicking on a tool, so you can use several related tools together, which
can be convenient. 

It also supports keyword search. Click on the magnifying glass at the
top-left, then type something related to what you want. Entering "lab", for
example, will show all the tools related to CIELAB colourspace, for example:

![nip4]({{ site.baseurl }}/assets/images/nip4-toolkits-search.png)

Searching is fuzzy, so you don't need to be exact.

## Workspace drag animations

The main workspace view has fancy animations for column and row dragging,
which can help make it easier to see what's going on. The big change from nip2
is that you can now (finally!) drag rows between columns.

You can also left-drag on the workspace background to pan, phew.

## No region context menu

In nip2 there was a right-click menu in image view windows you could use to
delete or edit region properties. This is gone in nip4, you're supposed to go
back to the workspace and right-click on the row for that region. You can
change region properties by opening the row a few times and editing the
members:

![nip4]({{ site.baseurl }}/assets/images/nip4-region.png)

This works for objects: open the row, edit the members. 

## Multiple select on rows

You can now range-select rows, then right-click on a row name and act on
them all. This is useful for deleting or duplicating sets of rows.

## Definitions

If you right-click on the workspace background, the workspace menu includes
**Workspace definitions** and **Edit toolkits ...**. 

The toolkit editor is a bit basic, but does work. 

## What's missing

The paintbox is probably the biggest missing feature, this might come back.

The github repository has [a large TODO
file](https://github.com/jcupitt/nip4/blob/main/TODO) with some other notes
on bugs, ideas and other missing features.

