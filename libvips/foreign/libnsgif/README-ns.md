LibNSGIF: NetSurf GIF decoder
=============================

LibNSGIF is a C library for decoding GIF format images and animations.
It is licenced under the MIT licence.

This library aims to provide a simple API for robust decoding of GIF files.

Details
-------

The GIF source data is scanned prior to decoding, allowing for efficient
decoding. The scanning phase will scan currently available data and will
resume from where it left off when called with additional data.

Only one frame is ever fully decoded to a bitmap at a time, reducing memory
usage for large GIFs.

Using
-----

LibNSGIF allows the client to allocate the bitmap into which the GIF is
decoded. The client can have an arbitrary bitmap structure, that is simply
a void pointer to LibNSGIF. The client must provide a callback table for
interacting with bitmaps, and the required client bitmap pixel format.
The bitmap table must include as a minimum functions to create and destroy
bitmaps, and a function to get a pointer to the bitmap's pixel data buffer.

LibNSGIF always decodes to a 32bpp, 8 bits per channel bitmap pixel format,
however it allows the client to control the colour component ordering.

To load a GIF, first create an nsgif object with `nsgif_create()`.

```c
	err = nsgif_create(&bitmap_callbacks, NSGIF_BITMAP_FMT_R8G8B8A8, &gif);
	if (err != NSGIF_OK) {
		fprintf(stderr, "%s\n", nsgif_strerror(err));
		// Handle error
	}
```

Now you can load the GIF source data into the nsgif object with
`nsgif_data_scan()`:

```c
	err = nsgif_data_scan(gif, size, data);
	if (err != NSGIF_OK) {
		fprintf(stderr, "%s\n", nsgif_strerror(err));
		// Handle error
	}
```

This scans the source data and decodes information about each frame, however
it doesn't decode any of the bitmap data for the frames. The client may call
`nsgif_data_scan()` multiple times as source data is fetched. The early frames
can be decoded before the later frames are scanned. Frames have to be scanned
before they can be decoded.

This function will sometimes return an error. That is OK, and even expected.
It is fine to proceed to decoding any frames that are available after a scan.
Some errors indicate that there is a flaw in the source GIF data (not at all
uncommon, GIF is an ancient format that has had many broken encoders), or that
it has reached the end of the source data.

> **Note**: The client must not free the data until after calling
> `nsgif_destroy()`. You can move the data, e.g. if you realloc to a bigger
> buffer. Just be sure to call `nsgif_data_scan()` again with the new pointer
> before making any other calls against that nsgif object.

When all the source data has been provided to `nsgif_data_scan()` it is
advisable to call `nsgif_data_complete()` (see below), although this is not
necessary to start decoding frames.

To decode the frames, you can call `nsgif_get_info()` to get the frame_count,
and then call `nsgif_frame_decode()` for each frame, and manage the animation,
and non-displayable frames yourself, or you can use the helper function,
`nsgif_frame_prepare()`:

```c
	err = nsgif_frame_prepare(gif, &area, &delay_cs, &frame_new);
	if (err != NSGIF_OK) {
		fprintf(stderr, "%s\n", nsgif_strerror(err));
		// Handle error
	}

	// Update our bitmap to know it should be showing `frame_new` now.
	// Trigger redraw of `area` of image.

	if (delay_cs != NSGIF_INFINITE) {
		// Schedule next frame in delay_cs.
	}
```

This will return the number of the next frame to be decoded, the delay in cs
before the next frame should be decoded, and the area of the bitmap that needs
to be redrawn.

> **Note**: GIF frames may only occupy a portion of the overall bitmap, and only
> redrawing the area that has changed may be more efficient than redrawing the
> whole thing. The returned area comprises both any region that has been
> changed in the disposal of the previous frame and the new frame.

GIF files can limit the number of animation loops to a finite number or they
may only have one frame. In either of these cases, the returned delay is
`NSGIF_INFINITE` indicating that the animation is complete. Subsequent calls
to `nsgif_frame_prepare()` will return `NSGIF_ERR_ANIMATION_END`.

To force the repeat of an animation, call `nsgif_reset()`.

One reason for the two-step decoding of frames is that it enables deferred
decoding. You can call `nsgif_frame_prepare()` and cause a redraw of that
portion of your document. If the GIF is off screen (another tab, or scrolled
out of sight), there is no need to decode it at all.

Once the bitmap is needed for a redraw, you can decode the correct frame
on-demand with:

```c
	err = nsgif_frame_decode(gif, frame_new, &bitmap);
	if (err != NSGIF_OK) {
		fprintf(stderr, "%s\n", nsgif_strerror(err));
		// Handle error
	}
```

Note that this will be a no-op if the requested frame already happens to be
the decoded frame.

You can call `nsgif_frame_prepare()` and `nsgif_frame_decode()` before all
of the GIF data has been provided using `nsgif_data_scan()` calls. For example
if you want to make a start decoding and displaying the early frames of the GIF
before the entire animation file has been downloaded.

When you do this, `nsgif_frame_prepare()` will not loop the animation back to
the start unless you call `nsgif_data_complete()` to indicate all of the data
has been fetched. Calling `nsgif_data_complete()` also lets libnsgif display
any trailing truncated frame.

```c
	nsgif_data_complete(gif);
```

Once you are done with the GIF, free up the nsgif object with:

```c
	nsgif_destroy(gif);
```
