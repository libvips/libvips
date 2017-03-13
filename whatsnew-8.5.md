This branch has a new implementation of sequential mode:

https://github.com/jcupitt/libvips/tree/remove-seq-stalling

It'd be great to get this merged to master for 8.5, but it needs some testing.

How seq used to work:

* The vips sink functions create a set of N threads and scan images
top-to-bottom in tiles, allocating tiles to workers as they finish.

* They have extra logic to keep workers together. They track the position
of the most-delayed worker and if the lead thread gets more than M scanlines
ahead, it stalls until the stragglers catch up.

* There is more logic in the loaders: they keep track of the current
Y position, and if the lead request thread gets ahead of the current
read point, it stalls with a 60s timeout until the intermediate tiles are
requested. This logic is implemented in the `vips_sequential()` operation.

The point of trying to keep thread locality and ordering is that we want
to limit the number of scanlines that loaders have to keep behind the read
point. We want to stream images through memory, not be forced into a load /
process / save model.

This works reasonably well for simple cases, like thumbnailing single images,
but can fail in more complex cases, such as repeated `vips_insert()`. Consider
this Python program:

```python 
#!/usr/bin/python

import sys import random

import gi gi.require_version('Vips', '8.0') from gi.repository import Vips

composite = Vips.Image.black(100000, 100000)

for filename in sys.argv[2:]:
    tile = Vips.Image.new_from_file(filename, access = Vips.Access.SEQUENTIAL)
    x = random.randint(0, composite.width - tile.width) y = random.randint(0,
    composite.height - tile.height) composite = composite.insert(tile, x, y)

composite.write_to_file(sys.argv[1]) 
```

This makes a 100,000 x 100,000 pixel black image, then inserts a lot of
other files into it and writes the result.

With vips8.4, this could very easily fail. Imagine this situation:

* image1 is very tall and thin

* image2 is short and fat, and by chance covers the centre of image1

* we'll write the top part of image1, then write the body of image2

* after image2 has been written, we need to write the bottom of image1,
so a thread will ask for a set of pixels near the end of image1

* image1 knows that the previous request was for some scanlines near the top,
so it thinks this request must be from a thread that has run way ahead of
the pack and stalls it

And we have a deadlock. In fact, vips wouldn't deadlock, it would just
pause on a 60s timeout on each thread. Sad!

Here's how the new seq works:

* Sinks work as before.

* Loaders use a revised `vips_sequential()` with the stalling logic
removed. All it does now is track the read position, cache a few 100 lines
behind the read point, and makes sure that lines are evaluated in order
with no missing areas.

* Operations like `vips_shrinkv()` which can cause large non-local references
have an extra bit of code which, if the input comes from a sequential source,
adds a an extra `vips_sequential()` operator on the output. This forces
`vips_shrinkv()` input to be sequential.

The old one constrained thread location on output, and on input as well. The
new idea is to get rid of input constraints, and instead add extra code
to the operations which could trigger large non-local references. Rather
than tying threads down to stop them drifting apart, it makes sure they
can never get too far apart in the first place.

Running the test program with git master gives this result:

``` 
real    1m2.317s 
user    2m58.472s 
sys     0m7.568s 
peak mem: 10gb 
```

Not bad!
