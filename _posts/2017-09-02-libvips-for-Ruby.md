---
title: libvips for Ruby
---

There's a new major release of `ruby-vips`, the Ruby binding for libvips:
it's now version 2.0. It has the same API (it passes the same test suite),
but it's simpler to install, works on Linux, macOS and Windows, it works
with any Ruby (including JRuby), it's smaller, more stable, and faster.

[https://github.com/libvips/ruby-vips](https://github.com/libvips/ruby-vips)

## Why a new version?

Version 1.x was based on `gobject-introspection`, a gem from the gnome2
project. 

`gobject-introspection` was designed for the desktop rather than the
server. It pulled in a lot of other gems which were not really relevant,
it had a lot of native code which had to be ported to each platform, and
it was not really designed for the kinds of heavily threaded applications
you find on servers, so it was difficult to make it stable under load.

Version 2.0 has completely new underpinnings. It uses `ruby-ffi` to open the
libvips shared library, then uses libvips's own introspection system to make
the operations it finds appear as members of the `Image` class. 

Since we've removed a huge amount of middleware, everything is smaller,
faster, and simpler. Porting is especially easy: the same gem works without
modification on every OS and with every Ruby version. Speed and stability are
noticeably better too. 

It's already in production use on quite a few sites, and there should be
no changes required to user code.
