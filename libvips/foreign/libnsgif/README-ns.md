libnsgif - Decoding GIF files
=============================

The functions provided by this library allow for efficient progressive
GIF decoding. Whilst the initialisation does not ensure that there is
sufficient image data to complete the entire frame, it does ensure
that the information provided is valid. Any subsequent attempts to
decode an initialised GIF are guaranteed to succeed, and any bytes of
the image not present are assumed to be totally transparent.

To begin decoding a GIF, the 'gif' structure must be initialised with
the 'gif_data' and 'buffer_size' set to their initial values. The
'buffer_position' should initially be 0, and will be internally
updated as the decoding commences. The caller should then repeatedly
call gif_initialise() with the structure until the function returns 1,
or no more data is avaliable.

Once the initialisation has begun, the decoder completes the variables
'frame_count' and 'frame_count_partial'. The former being the total
number of frames that have been successfully initialised, and the
latter being the number of frames that a partial amount of data is
available for. This assists the caller in managing the animation
whilst decoding is continuing.

To decode a frame, the caller must use gif_decode_frame() which
updates the current 'frame_image' to reflect the desired frame. The
required 'disposal_method' is also updated to reflect how the frame
should be plotted. The caller must not assume that the current
'frame_image' will be valid between calls if initialisation is still
occuring, and should either always request that the frame is decoded
(no processing will occur if the 'decoded_frame' has not been
invalidated by initialisation) or perform the check itself.

It should be noted that gif_finalise() should always be called, even
if no frames were initialised.  Additionally, it is the responsibility
of the caller to free 'gif_data'.
