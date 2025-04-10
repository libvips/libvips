Title: Operator index > By section > Draw

<!-- libvips/draw -->

These operations directly modify the image. They do not thread, on 32-bit
machines they will be limited to 2GB images, and a little care needs to be
taken if you use them as part of an image pipeline. They are mostly supposed
to be useful for paintbox-style programs.

libvips operations are all functional: they take zero or more existing input
images and generate zero or more new output images. Images are never altered,
you always create new images. This means libvips can cache and thread very
aggressively.

The downside is that creating entirely fresh images each time can be very
slow. libvips has a range of tricks to avoid these problems, but there are
still times when you really have to be able to modify an image. An example
might be drawing a curved line from a set of straight line segments: if you
need to draw 1,000 straight lines, a 1,000 operation-deep pipeline is going
to be a slow way to do it. This is where the draw operations come in.

To use these operations, use [method@Image.copy_memory] to make a private
memory copy of the image you want to modify, then call a series of draw
operations.

Once you are done drawing, return to normal use of vips operations. Any time
you want to start drawing again, you'll need to copy again.

## Functions

* [method@Image.draw_rect]
* [method@Image.draw_rect1]
* [method@Image.draw_point]
* [method@Image.draw_point1]
* [method@Image.draw_image]
* [method@Image.draw_mask]
* [method@Image.draw_mask1]
* [method@Image.draw_line]
* [method@Image.draw_line1]
* [method@Image.draw_circle]
* [method@Image.draw_circle1]
* [method@Image.draw_flood]
* [method@Image.draw_flood1]
* [method@Image.draw_smudge]

## Enumerations

* [enum@CombineMode]
