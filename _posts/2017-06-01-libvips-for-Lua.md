---
title: libvips for Lua
---

LuaJIT now has a full libvips binding. It's the whole of libvips, it has a
test-suite which passes with no memory leaks, and it's in `luarocks` so it's
easy to install.

As long as you have a libvips binary on your system, just:

	luarocks install lua-vips

should be all you need. The README in the repository for the binding has more
details:

[https://github.com/jcupitt/lua-vips](https://github.com/jcupitt/lua-vips)

Here's an example program:

```lua
vips = require "vips"

image = vips.Image.text("Hello <i>World!</i>", {dpi = 300})

-- call a method
image = image:invert()

-- use the `..` operator to join images bandwise
image = image .. image .. image

-- add a constant
image = image + 12
-- add a different value to each band
image = image + {1, 2, 3}
-- add two images
image = image + image

-- split bands up again
b1, b2, b3 = image:bandsplit()

-- read a pixel from coordinate (10, 20)
r, g, b = image(10, 20)

-- make all pixels less than 128 bright blue
image = image:less(128):ifthenelse({0, 0, 255}, image)

-- go to Yxy colourspace
image = image:colourspace("yxy")

image:write_to_file("x.png")

-- fast thumbnail generator
image = vips.Image.thumbnail("somefile.jpg", 128)
image:write_to_file("tiny.jpg")
```

There's a small repo here which benchmarks it against `magick`, the ImageMagick
binding for Lua:

[https://github.com/jcupitt/lua-vips-bench](https://github.com/jcupitt/lua-vips-bench)

On that test and on my laptop, `lua-vips` is 7.5x faster and needs 10x less 
memory.

# How it works

We've done quite a few bindings for libvips now. This one takes a slightly
different approach: it uses the very nice ffi (Foreign Function Interface)
system in LuaJIT and uses that to call directly into libvips. Once inside,
it uses GObject and libvips' introspection facilities to link operations
on Lua objects to operations in the libvips library.

For example, consider the Lua code:

```lua
image = image:hough_circle()
```

Which does a Hough transform. Lua knows that the image object belongs to
`lua-vips` from the metatable. It won't find anything called `hough_circle`
there, so it passes control to the `__index` metamethod on the
object. 

This jumps into libvips and searches for an operation of that name. It then
examines the operation and discovers what arguments it needs, what type they
are, and what options the operation supports (no required args, but quite a few
options, in this example). 

It then walks the arguments that were supplied, setting what it can, and
invokes the operation. On return, it extracts the results and repackages them
for Lua.

This dynamic approach via ffi has several nice properties:

* As operations are added to libvips, they will immediately appear in
  `lua-vips`, with no maintenance effort required. This binding should
  always be up to date.

* The whole binding, exposing all 300 vips operations, is less than 1,000
  lines of Lua. There is no native code, so it'll work immediately on any 
  platform that has LuaJIT and a libvips library. 

  In fact `lua-vips` is about 1,500 lines of code, but a lot of that is things
  like the definitions of operator overloads, and a set of convenience
  functions. The binding itself is tiny. 

* Since `lua-vips` is a very thin skin over libvips, you can use the existing C
  documentation directly. 

* Other bindings we've done have used a similar approach, but they've all used
  some kind of middleware. This has saved us some work, but it has added
  complexity, sometimes reduced reliability, and made installation harder for
  users. Here, there's nothing but LuaJIT and the libvips shared library. 

It's rather tempting to try remaking the Python and Ruby bindings on top of ffi. 
