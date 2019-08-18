---
title: libvips in OSS Fuzz
---

Thanks to work by @omira-sch, libvips has been in [OSS
Fuzz](https://github.com/google/oss-fuzz) for about three weeks. I'm very
happy to be able to report that only one real bug has been found so far,
and none in the last five days.

# Background

Feedback-fuzzing has been around for a few years. I stumbled upon AFL
([American Fuzzy Lop](http://lcamtuf.coredump.cx/afl/)) in 2016 via this
interesting blog post:

[https://lcamtuf.blogspot.com/2014/11/pulling-jpegs-out-of-thin-air.html](https://lcamtuf.blogspot.com/2014/11/pulling-jpegs-out-of-thin-air.html)

All the author did was:

```
echo hello world > indir/hello; afl-fuzz -i indir -o outdir djpeg
```

You let it run for a few minutes and a valid JPEG file appears, apparently
from nowhere. Magic!

AFL knows nothing about JPEGs --- all it does is mutate the input string
`hello world` while running `djpeg`, the IJG JPEG decoder program. The secret
is that it watches the *insides* of `djpeg` as it executes and modifies
the input in order to explore all the possible paths in the binary. Since
decompressing a JPEG file is a path of execution, the input file must
eventually become a JPEG image. AFL finds this path impressively quickly.

Testing programs by throwing random data at them is as old as the hills
of Manjare. The innovation here is watching the insides of the program as
it executes and using that feedback to guide the evolution of the test data.

It's a very powerful technique and has been used to automatically find a
lot of bugs in many projects. We've put libvips through AFL testing several
times, though it's a bit of an effort.

# OSS Fuzz

Google have jumped on this idea too, and really gone with it. 

They've added a set of sanitisers, each specialized in a certain type of
test (address handling, undefined behaviour, threading, etc.) to clang, the
LLVM-derived compiler that they and Apple contribute to. We've previously
tested libvips with these too.

Next, they've made a feedback fuzzer on top of the sanitisers, and then
built a lot of infrastructure for collecting and running sets of tests and
tracking issues. Finally, they've opened it to popular open-source projects
--- including libvips.

Whenever Google's clusters have some spare time, they are now fuzzing us. It's
done continuously, so every commit we make will be tested within about 24h.

# Implementation

We added two things: first, there's a `fuzz` directory in libvips that's
integrated into our build system:

[https://github.com/libvips/libvips/tree/master/fuzz])(https://github.com/libvips/libvips/tree/master/fuzz)

That defines five fuzz targets testing different parts of the system. They are
pretty simple --- for example, here's the one for any format load to PNG write:

[https://github.com/libvips/libvips/blob/master/fuzz/pngsave_buffer_fuzzer.cc](https://github.com/libvips/libvips/blob/master/fuzz/pngsave_buffer_fuzzer.cc)

There are directories holding inputs that have previously raised issues,
so we can immediately spot regressions as part of `make check`.

Second, `oss-fuzz` has a libvips project directory that builds the library
and runs the fuzzers:

[https://github.com/google/oss-fuzz/tree/master/projects/libvips](https://github.com/google/oss-fuzz/tree/master/projects/libvips)

Everything else is automatic. It's rather slick.

# Results

It's found 34 issues, but only two had security implications, and one of
those was actually in ImageMagick.

The other ones in libvips were a mixture of undefined behaviour (3 issues),
int overflow when computing int32 images (5 issues) and divide by zero (2
issues). The remaining 22 were either false positives (it took us a while
to get image size handling working), or errors in libraries used by libvips
(all now reported upstream).

There's a bit more we can do to expose more loaders to fuzzing. Perhaps in the
next version.
