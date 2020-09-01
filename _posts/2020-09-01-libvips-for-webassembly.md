---
title: libvips for WebAssembly
excerpt: There's a new full libvips binding for the browser and Node.js. It supports reading and writing JPEG, PNG, WebP and TIFF images, it's on NPM, and it comes with TypeScript declarations.
---

There's a new full libvips binding for the browser and Node.js. It supports
reading and writing JPEG, PNG, WebP and TIFF images out-of-the-box on browsers
that [supports the SharedArrayBuffer API](https://caniuse.com/#feat=sharedarraybuffer),
it's on NPM, and it comes with TypeScript declarations.

All the features of libvips can be viewed and executed in the browser within
this playground:

[https://kleisauke.github.io/wasm-vips/playground](https://kleisauke.github.io/wasm-vips/playground)

The README in the repository for the binding has more details, including some
install notes and an example:

[https://github.com/kleisauke/wasm-vips](https://github.com/kleisauke/wasm-vips)

But briefly, just enter:

```bash
npm install wasm-vips
```

# How it's done

The whole of libvips and its dependencies has been compiled to WebAssembly
with [Emscripten](https://emscripten.org/). The resulting WASM binary is
~4.6 MB in size. It took several patches to make libvips usable in the
browser:

* The thread pool has been patched to reuse already started threads
  ([#1492](https://github.com/libvips/libvips/issues/1492)). The aim is that
  this will also be integrated into a further version of libvips, as this
  could also be useful for native environments.

* A couple of [function pointer issues](
  https://emscripten.org/docs/porting/guidelines/function_pointer_issues.html)
  has been fixed ([#1697](https://github.com/libvips/libvips/pull/1697)).

* libffi needed to be ported to WebAssembly. See these blog posts for
  background info:  
  [emscripten fun: porting libffi to WebAssembly part 1](
  https://brionv.com/log/2018/05/06/emscripten-fun-porting-libffi-to-webassembly-part-1/)  
  [emscripten fun: libffi on WebAssembly part 2](
  https://brionv.com/log/2018/05/27/emscripten-fun-libffi-on-webassembly-part-2/)

* GLib needed a couple of patches throughout the build system
  ([emscripten-core/emscripten#11066](
  https://github.com/emscripten-core/emscripten/issues/11066)).

# Performance

It's rather tempting to benchmark how close WebAssembly gets to native speed,
and how much faster it is than pure JS image processing libraries (i.e.
no native code). The repo includes [benchmarks which test the performance
against alternative Node.js modules](
https://github.com/kleisauke/wasm-vips/tree/master/test/bench), including
sharp and jimp.

On this benchmark and on my pc, sharp is 8.3x faster for JPEG, 3.6x faster
for PNG, and 2.2x faster for WebP images in comparison with wasm-vips.

wasm-vips on the other hand is 5.9x faster for JPEG and 8% faster for PNG 
images in comparison with jimp.

<table>
    <thead>
        <tr>
            <th>Image format</th>
            <th>Module</th>
            <th>Ops/sec</th>
            <th>Speed-up</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td rowspan="3">JPEG</td>
            <td>jimp</td>
            <td>0.91</td>
            <td>1.0</td>
        </tr>
        <tr>
            <td>wasm-vips</td>
            <td>5.36</td>
            <td>5.9</td>
        </tr>
        <tr>
            <td>sharp</td>
            <td>44.35</td>
            <td>45.8</td>
        </tr>
        <tr>
            <td rowspan="3">PNG</td>
            <td>jimp</td>
            <td>5.20</td>
            <td>1.0</td>
        </tr>
        <tr>
            <td>wasm-vips</td>
            <td>5.63</td>
            <td>1.1</td>
        </tr>
        <tr>
            <td>sharp</td>
            <td>20.30</td>
            <td>3.9</td>
        </tr>
        <tr>
            <td rowspan="3">WebP</td>
            <td>wasm-vips</td>
            <td>6.20</td>
            <td>1.0</td>
        </tr>
        <tr>
            <td>sharp</td>
            <td>13.73</td>
            <td>2.2</td>
        </tr>
    </tbody>
</table>

The substantial slowdown for JPEG images could be caused due to
`libjpeg-turbo` is compiled _without_ SIMD support. This dependency uses
native inline SIMD assembly, which is currently not supported in Emscripten.
All code should be written using SIMD intrinsic functions or compiler vector
extensions.

Although the dependencies for the other image formats (i.e. `libspng` and
`libwebp`) are compiled with SIMD support there is still a slowdown
noticeable. A possible reason for that is that `liborc` is not built for
WebAssembly. This dependency is used by libvips to improve the performance of
the resize, blur and sharpen operations, but this is quite difficult to
compile for WebAssembly as it generates SIMD instructions on-the-fly.

Note that these benchmarks are expected to run faster when the WebAssembly
proposals for [SIMD](https://github.com/WebAssembly/simd) and [threads](
https://github.com/WebAssembly/threads) have been standardized.

# How it works

All libvips operations and enumerations are exposed through
[Embind](https://emscripten.org/docs/porting/connecting_cpp_and_javascript/embind.html),
so that the compiled code can be used in JavaScript.

The binding itself is a variant of
[libvips' C++ API]({{ site.baseurl }}/API/current/using-from-cpp.html),
with additional support for the `emscripten::val` C++ class to transliterate
JavaScript code to C++. For example, consider this JavaScript code:

```javascript
// Image source: https://www.flickr.com/photos/jasonidzerda/3987784466
const thumbnail = vips.Image.thumbnail('owl.jpg', 128, {
    height: 128,
    crop: vips.Interesting.attention /* or: 'attention' */
});
```

Which shrinks an image to fit within a 128×128 box. Excess pixels are trimmed
away using the `attention` strategy that positioned the crop box over the
most significant feature:

[![Attention strategy]({{ site.baseurl }}/API/current/tn_owl.jpg)]({{ site.baseurl }}/API/current/tn_owl.jpg)

This function and enumeration was automatically generated within C++ as:
```cpp
EMSCRIPTEN_BINDINGS(my_module) {
    enum_<VipsInteresting>("Interesting")
        .value("none", VIPS_INTERESTING_NONE)
        .value("centre", VIPS_INTERESTING_CENTRE)
        .value("entropy", VIPS_INTERESTING_ENTROPY)
        .value("attention", VIPS_INTERESTING_ATTENTION)
        .value("low", VIPS_INTERESTING_LOW)
        .value("high", VIPS_INTERESTING_HIGH)
        .value("all", VIPS_INTERESTING_ALL);

    class_<Image>("Image")
        .constructor<>()
        .function("thumbnail", &Image::thumbnail);
}
```
