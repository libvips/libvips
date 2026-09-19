---
title: vipsdisp paintbox
---

[vipsdips 4.2 is out](https://github.com/libvips/vipsdisp/releases), and
it has a fun new feature: a simple image paintbox.

![paintbox](/assets/images/paintbox.png)

It's extremely basic, but it's enough for simple image annotation. 

The only interesting thing about it is that it can draw with pixels in any of
the numeric formats that libvips supports, so for example you can paint with
double-precision complex pixels.

The tools are in the bar at the bottom and from the left they are:

- undo
- redo 
- pointer mode (ie. paintbox is off)
- freehand draw, use the slider to set brush width
- straight line draw, use the slider to set brush width
- draw a box, filled or empty
- draw a circle, filled or empty
- smudge, use the slider to set brush width
- fill until equal to ink
- fill while equal to start pixel
- render text


- ^Z, ^Y, shift-drag


