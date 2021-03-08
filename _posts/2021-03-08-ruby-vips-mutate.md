---
title: ruby-vips and image mutability
---

ruby-vips is now at version 2.1 with a few useful bug fixes and an interesting
new `mutate` feature. This new block makes it possible to modify images
efficiently and safely. 

# Draw operations

Up until now, ruby-vips has been purely functional, in other words, all
operations created new images, and no operations modified their arguments. 

For example, you could draw a circle on an image, but you were given a new
image back and the original was not changed. 

```ruby
y = x.draw_circle 255, 50, 50, 10, fill: true
```

This takes image `x`, makes a copy in memory, draws a circle with
centre at (50, 50) and radius 10 filled with pixels of value 255, and returns
this new image as `y`.

Purely functional operations have the huge advantage of allowing safe
sharing: if another part of your program is using image referred to by
`x`, it won't see a circle unexpectedly appear on its image. This is fine
for small images, but can become very slow for large ones. And what if you
want to draw a series of circles? It becomes very painful indeed. For example:

```ruby
#!/usr/bin/ruby

require 'vips'

x = Vips::Image.new_from_file ARGV[0]

1000.times do
  x = x.draw_circle Array.new(3){rand(255)},
    rand(x.width), rand(x.height), rand(100), fill: true
end

x.write_to_file ARGV[1]
```

I can run the program like this (`nina.jpg` is 6,000 x 4,000 pixels, not
unusual for modern DSLR camera):

```
$ /usr/bin/time -f %M:%e ./circles.rb ~/pics/nina.jpg x.jpg
4700668:13.29
```

To make this:

![random circles]({{ site.baseurl }}/assets/images/circles1.jpg)

It works but, on a powerful desktop machine, 13s and almost 5gb of memory 
to draw 1,000 circles is really not good. 

# Metadata

There's a second case where mutability is important: metadata updates.

ruby-vips lets you set image metadata, for example, you can set the EXIF
orientation tag on an image like this:

```ruby
x = Vips::Image.new_from_file "k2.jpg"
x.set "orientation", 6
x.write_to_file "x.jpg"
```

It works in simple cases, but actually, this is not correct. The `x.set`
is modifying image `x` (though only modifying the image metadata rather
than any pixels) and in a large program, `x` could be shared. To be safe,
you need to make a private copy of the image before you change it, like this:

```ruby
x = Vips::Image.new_from_file "k2.jpg"
x = x.copy
x.set "orientation", 6
x.write_to_file "x.jpg"
```

This is annoying, and ruby-vips does not enforce this rule so, in some large
programs, you can get bizarre behaviour and even races and crashes.

# The `mutate` block

ruby-vips 2.1 has a new feature that
tries to fix both these problems: [the `mutate`
method](https://www.rubydoc.info/gems/ruby-vips/2.1.0/Vips/Image#mutate-instance_method).
You use it like this:

```ruby
#!/usr/bin/ruby

require 'vips'

x = Vips::Image.new_from_file ARGV[0]

x = x.mutate do |y|
  1000.times do 
    y.draw_circle! Array.new(3) {rand(255)},
      rand(x.width), rand(x.height), rand(100), fill: true
  end
end

x.write_to_file ARGV[1]
```

The `mutate` method builds a private copy of the image,
uses it to construct an instance of [a new class called
`MutableImage`](https://www.rubydoc.info/gems/ruby-vips/2.1.0/Vips/MutableImage),
and then yields that instance to the block.

An instance of `MutableImage` behaves just like an image object, except
that it is guaranteed not to be shared. There are new destructive versions
of operations like `draw_circle` (with the usual `!` naming convention)
which really do modify their argument. 

After the block finishes, `mutate` unwraps the mutable image and returns a
new `Image` object. Because it manages the transition to `MutableImage` and
back, ruby-vips can enforce all the obvious rules to guarantee run-time
safety.

Performance is much better. I see:

```
$ /usr/bin/time -f %M:%e ./circles-mutate.rb ~/pics/nina.jpg x.jpg
290348:1.04
```

It's 13x faster and needs 15x less memory. It's now fast enough that
operations like `draw_circle!` could actually be useful.

You can use `mutate` to safely modify image metadata too:

```ruby
x = Vips::Image.new_from_file "k2.jpg"
x = x.mutate do |y|
  y.set! "orientation", 6
  y.remove! "icc-profile-data"
end
x.write_to_file "x.jpg"
```

For compatibility, the old `set` and `remove` methods are still there,
but we plan to make them start issuing warnings at some point.

The other libvips language bindings probably need a feature like this too,
but for now it's just ruby-vips.
