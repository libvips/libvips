Title: Using > Threads

This section tries to summarise the rules for threaded programs using
libvips. Generally, libvips is threaded and thread-safe, with a few
exceptions.

## Images

On startup, you need to call [func@INIT] single-threaded. After that,
you can freely create images in any thread and read them in any other
thread. See the example at the end of this chapter.
Note that results can also be shared between threads for you by the
libvips operation cache.

The exception is the drawing operators, such as [method@Image.draw_circle].
These operations modify their image argument so you can't call them on
the same image from more than one thread. Reading from an image while
another thread is writing to it with one of the draw operations will
obviously also fail.

When libvips calculates an image, by default it will use as many
threads as you have CPU cores. Use [func@concurrency_set] to change this.

## Error handling

libvips has a single error code (-1 or %NULL) returned by all functions
on error. Error messages are not returned, instead they are logged
in a single global error buffer shared by all threads, see
[func@error_buffer].

This makes error handling very simple but the obvious downside is that
because error returns and error messages are separate, when you
detect an error return you can't be
sure that what's in the error buffer is the message that matches your
error.

The simplest way to handle this is to present the whole error log to
the user on the next interaction and leave it to them to decide what
action caused the failure.

## Using [class@Region] between threads

[class@Image] objects are immutable and can be shared between
threads very simply. However the lower-level [class@Region] object
used to implement [class@Image] (see [extending libvips](extending.html)) is
mutable and you can only use a [class@Region] from one thread at once.

In fact it's worse than that: to reduce locking, [class@Region] keeps a
lot of state in per-thread storage. If you want to create a region in
one thread and use it in another, you have to first tag the region as
unowned from the creating thread with `vips__region_no_ownership()`, then
in the receiving thread take ownership with
`vips__region_take_ownership()`. See the source for operations like
[method@Image.tilecache] if you're curious how this works.

libvips includes a set of sanity checks for region ownership and will
fail if you don't pass ownership correctly.

## Example

This example runs many [method@Image.resize] in parallel from many threads.

```c
/* Read from many threads.
 *
 * Compile with:
 *
 *     gcc -g -Wall soak.c `pkg-config vips --cflags --libs`
 *
 * Run with:
 *
 *     rm -rf x
 *     mkdir x
 *     for i in {0..10}; do ./a.out ~/pics/k2.jpg; done
 *
 */

#include <stdio.h>
#include <glib.h>

#include <vips/vips.h>

/* How many pings we run at once.
 */
#define NUM_IN_PARALLEL (50)

/* Number of tests we do in total.
 */
#define TOTAL_TESTS (NUM_IN_PARALLEL * 20)

/* Workers queue up on this.
 */
GMutex allocation_lock;

/* Our set of threads.
 */
GThread *workers[NUM_IN_PARALLEL];

/* Number of calls so far.
 */
int n_calls = 0;

/* Our test function. This is called by NUM_IN_PARALLEL threads a total of
 * TOTAL_TESTS times.
 */
static int
test(const char *filename)
{
    VipsImage *im, *x;
    char output_file[256];

    snprintf(output_file, 256, "x/tmp-%p.jpg", g_thread_self());

    if (!(im = vips_image_new_from_file(filename,
              "access", VIPS_ACCESS_SEQUENTIAL,
              NULL)))
        return -1;

    if (vips_resize(im, &x, 0.1, NULL)) {
        g_object_unref(im);
        return -1;
    }
    g_object_unref(im);
    im = x;

    if (vips_image_write_to_file(im, output_file, NULL)) {
        g_object_unref(im);
        return -1;
    }
    g_object_unref(im);

    return 0;
}

/* What we run as a thread.
 */
static void *
worker(void *data)
{
    const char *filename = (const char *) data;

    for (;;) {
        gboolean done;

        done = FALSE;
        g_mutex_lock(&allocation_lock);
        n_calls += 1;
        if (n_calls > TOTAL_TESTS)
            done = TRUE;
        g_mutex_unlock(&allocation_lock);

        if (done)
            break;

        if (test(filename))
            vips_error_exit(NULL);
    }

    return NULL;
}

int
main(int argc, char **argv)
{
    int i;

    if (VIPS_INIT(argv[0]))
        vips_error_exit(NULL);

    for (i = 0; i < NUM_IN_PARALLEL; i++)
        workers[i] = g_thread_new(NULL, (GThreadFunc) worker, argv[1]);

    for (i = 0; i < NUM_IN_PARALLEL; i++)
        g_thread_join(workers[i]);

    return 0;
}
```
