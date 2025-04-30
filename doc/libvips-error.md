Title: Operator index > By section > Error

<!-- libvips/iofuncs/error.c -->

libvips maintains an error buffer (a log of localised text messages), a set
of functions for adding messages, and a way to access and clear the buffer.

The error buffer is global, that is, it is shared between all threads. You
can add to the buffer from any thread (there is a lock to prevent
corruption), but it's sensible to only read and clear the buffer from the
main thread of execution.

The general principle is: if you detect an error, log a message for the
user. If a function you call detects an error, just propagate it and don't
add another message.

```c
VipsImage *im;

if (!(im = vips_image_new_from_file(filename, NULL)))
    // vips_image_new_from_file() will set a message, we don't need to
    return -1;

if (vips_image_get_width(im) < 100) {
    // we have detected an error, we must set a message
    vips_error("myprogram", "%s", _("width too small"));
    return -1;
}
```

The domain argument most of these functions take is not localised and is
supposed to indicate the component which failed.

libvips uses [func@GLib.warning] and [func@GLib.info] to send warning and
information messages to the user. You can use the usual GLib mechanisms to
display or divert these messages. For example, info messages are hidden by
default, but you can see them with:

```bash
$ G_MESSAGES_DEBUG=VIPS vipsthumbnail k2.jpg
VIPS-INFO: thumbnailing k2.jpg
VIPS-INFO: selected loader is VipsForeignLoadJpegFile
VIPS-INFO: input size is 1450 x 2048
VIPS-INFO: loading jpeg with factor 8 pre-shrink
VIPS-INFO: converting to processing space srgb
VIPS-INFO: residual reducev by 0.5
VIPS-INFO: 13 point mask
VIPS-INFO: using vector path
VIPS-INFO: residual reduceh by 0.5
VIPS-INFO: 13 point mask
VIPS-INFO: thumbnailing k2.jpg as ./tn_k2.jpg
```

## Functions

* [func@error_buffer]
* [func@error_buffer_copy]
* [func@error_clear]
* [func@error_freeze]
* [func@error_thaw]
* [func@error]
* [func@verror]
* [func@error_system]
* [func@verror_system]
* [func@error_g]
* [func@g_error]
* [func@error_exit]
* [func@check_uncoded]
* [func@check_coding]
* [func@check_coding_known]
* [func@check_coding_noneorlabq]
* [func@check_coding_same]
* [func@check_mono]
* [func@check_bands]
* [func@check_bands_1or3]
* [func@check_bands_atleast]
* [func@check_bands_1orn]
* [func@check_bands_1orn_unary]
* [func@check_bands_same]
* [func@check_bandno]
* [func@check_int]
* [func@check_uint]
* [func@check_uintorf]
* [func@check_noncomplex]
* [func@check_complex]
* [func@check_twocomponents]
* [func@check_format]
* [func@check_u8or16]
* [func@check_8or16]
* [func@check_u8or16orf]
* [func@check_format_same]
* [func@check_size_same]
* [func@check_oddsquare]
* [func@check_vector_length]
* [func@check_vector]
* [func@check_hist]
* [func@check_matrix]
* [func@check_separable]
* [func@check_precision_intfloat]
