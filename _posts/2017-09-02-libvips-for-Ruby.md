---
title: libvips for Ruby
---

There's a new major release of `ruby-vips`, the Ruby binding for libvips:
it's now version 2.0. It has the same API (it passes the same test suite),
but it's simpler to install, works on Linux, macOS and Windows, it works
with any Ruby (including JRuby), it's smaller, more stable, and faster.

[https://github.com/jcupitt/ruby-vips](https://github.com/jcupitt/ruby-vips)

## Why a new version?

Version 1.x was based on `gobject-introspection`, a gem from the gnome2
project which binds the whole of gtk+.  It's designed for desktop applications
rather than server code, so it brings in a lot of extras, like Cairo, which
we don't need. It has a lot of native code which need to be ported to each
platform, and it's not really designed for the kids of heavily threaded
applications you find on servers, so it was difficult to make it stable under
load.

Version 2.0 has completely new underpinnings. It uses `ruby-ffi` to open the
libvips shared library, then uses libvips's own introspection system to make
the operations it finds appear as members of the `Image` class. 

Since we've removed a huge layer of middleware, everything is smaller,
faster, and simpler. Porting is especially easy: the same gem works without
modification on every OS and with every Ruby version. Speed and stability are
noticeably better too. 

It's already in production use on quite a few sites, and there should be
no changes required to user code.
