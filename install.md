---
---

Most unix-like operating systems have libvips packages, check your package
manager. For macOS, there are packages in Homebrew, MacPorts and Fink. For
Windows, there are pre-compiled binaries in the [Download area]({{
site.github.releases_url }}).

## Installing on macOS with homebrew

Install [homebrew](https://brew.sh/), then enter:

	brew install vips

That will install vips with most optional add-ons included.

## Installing the Windows binary

Download `vips-dev-w64-web-x.y.z.zip` from the [Download area]({{
site.github.releases_url }}) and unzip it somewhere. At the command-prompt,
`cd` to `vips-x.y.z/bin` and run (for example):

	vips.exe invert some/input/file.jpg some/output/file.jpg

If you want to run `vips.exe` from some other directory on your PC,
you'll need to set your `PATH`.

The zipfile includes all the libraries and headers for developing with C with
any compiler. For C++, you must build with `clang++`, or rebuild the C++ API
with your compiler, or just use the C API.

The
<code class="highlight">vips-dev-w64-<span class="o">web</span>-x.y.z.zip</code>
is built with a small set of relatively secure file format readers and can be used
in a potentially hostile environment. The much larger
<code class="highlight">vips-dev-w64-<span class="o">all</span>-x.y.z.zip</code>
includes all the file format readers that libvips supports and care should be
taken before public deployment.

The Windows binary is built
by [build-win64-mxe](https://github.com/libvips/build-win64-mxe). This is a
containerised MinGW-w64 build system: on any host, install Docker,
clone the project, and type `./build.sh`. The README has notes.

## Building libvips from source

If the packaged version is too old, you can also build from source.

libvips uses the [Meson](https://mesonbuild.com) build system, version
0.55 or later. Meson can use ninja, Visual Studio or XCode as a backend,
so you'll also need one of them.

libvips must have `build-essential`, `pkg-config`, `libglib2.0-dev`,
`libexpat1-dev`. See the Dependencies section below for a full list of the
libvips optional dependencies.

Download the sources from the [Download area]({{
site.github.releases_url }}), then something like:

	tar xf libvips-x.y.z.tar.gz
	cd libvips-x.y.z
	meson setup build --prefix /my/install/prefix
	cd build
	meson compile
	meson test
	meson install

Check the output of meson setup carefully and make sure it found everything
you wanted it to find. Add arguments to `meson setup` to change the build
configuration.

 * Add flags like `-Dnsgif=false` to turn options on and off, see
   `meson_options.txt` for a list of all the build options libvips supports.

 * Add flags like `-Dmagick=disabled` to turn libvips dependencies on and off,
   see `meson_options.txt` and the list linked below for a summary of all the
   libvips dependencies.

 * You might need to add `--libdir lib` on Debian if you don't want the arch
   name in the library path.

 * Add `--default-library static` for a static build.

 * Use e.g. `CC=clang CXX=clang++ meson setup ...` to change compiler.

 * You can have an alternative build directory, pick whatever names you like,
   for example one for release and one for debug.

You'll need the dev packages for the file format support you
want. For basic jpeg and tiff support, you'll need `libtiff5-dev`,
`libjpeg-turbo8-dev`, and `libarchive-dev`. The [optional dependencies
section](https://github.com/libvips/libvips#optional-dependencies) in the
README lists all the things that libvips can be configured to use.

We have detailed guides on the wiki for [building for
Windows](https://github.com/libvips/libvips/wiki/Build-for-Windows) and
[building for macOS](https://github.com/libvips/libvips/wiki/Build-for-macOS).
