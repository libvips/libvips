---
title: libvips for .NET
---

There's a new full libvips binding for .NET. It has a test-suite which passes
with no memory leaks, it's in `NuGet`, so it's easy to install on Linux,
macOS and Windows, and it has nice documentation:

[https://kleisauke.github.io/net-vips](https://kleisauke.github.io/net-vips)

The README in the repository for the binding has more details, including some 
install notes and an example:

[https://github.com/kleisauke/net-vips](https://github.com/kleisauke/net-vips)

But briefly, just [get the libvips shared library on your
system](/install.html) and enter:

	Install-Package NetVips

Here's an example program:

```csharp
using NetVips;

// fast thumbnail generator
var image = Image.Thumbnail("somefile.jpg", 128);
image.WriteToFile("tiny.jpg");

// make a new image with some text rendered on it
image = Image.Text("Hello <i>World!</i>", dpi: 300);

// call a method
image = image.Invert();

// join images bandwise
image = image.Bandjoin(image);

// add a constant
image = image + 12;

// add a different value to each band
image = image + new[] {1, 2, 3};

// add two images
image = image + image;

// split bands up again
var images = image.Bandsplit();
var b1 = images[0];
var b2 = images[1];
var b3 = images[2];

// read a pixel from coordinate (10, 20)
var pixel = image.Getpoint(10, 20);
var r = pixel[0];
var g = pixel[1];
var b = pixel[2];

// make all pixels less than 128 bright blue
//    (image < 128) makes an 8-bit image where each band is 255 (true) if that 
//       value is less than 128, and 0 (false) if it's >= 128 ... you can use
//       images or new[] {1, 2, 3} constants as well as simple values
//    .BandAnd() joins all image bands together with bitwise AND, so you get a
//        one-band image which is true where all bands are true
//    condition.Ifthenelse(then, else) takes a condition image and uses true or
//        false values to pick pixels from the then or else images ... then and
//        else can be constants or images
image = (image < 128).BandAnd().Ifthenelse(new[] {0, 0, 255}, image);

// go to Yxy colourspace
image = image.Colourspace("yxy");

// pass options to a save operation
image.WriteToFile("x.png", new VOption
{
    {"compression", 9}
});
```

The repo includes [benchmarks which test the performance against
`Magick.NET`](https://github.com/kleisauke/net-vips/tree/master/tests/NetVips.Benchmarks),
the ImageMagick binding for .NET. On that test and on my pc, `NetVips`
is 8x faster than `Magick.NET`.

# How it works

This binding uses the P/Invoke (Platform Invocation Services) 
system in .NET to call directly into the libvips DLL. Once inside, 
it uses GObject and libvips' introspection facilities to link operations 
on C# objects to operations in the libvips library.

All libvips operations were generated automatically to a PascalCase method 
in NetVips. For example, consider the C# code:

```csharp
image = image.HoughCircle();
```

Which does a Hough transform. By taking advantage of nullable types 
(which allows you to omit any parameters in any position), we are able to 
call libvips operations that have optional arguments. See for example:

```csharp
public Image HoughCircle(int? scale = null, int? minRadius = null, int? maxRadius = null)
{
    // Call hough_circle with the corresponding options.
}
```

When `HoughCircle` is called it jumps into libvips and searches for an operation 
called `hough_circle` (the non PascalCase variant). It then examines the
operation and discovers what arguments it needs, what type they are, and what
options the operation supports (no required args, but quite a few options,
in this example).

It then walks the arguments that were supplied, setting what it can, and 
invokes the operation. On return, it extracts the results and repackages them 
for C#.

This dynamic approach via P/Invoke has several nice properties: 

* There is no native code, so it'll work immediately on any platform that has 
  .NET and a libvips library.

* Since `NetVips` is a very thin skin over libvips, you can use the existing C 
  documentation directly.

* Other bindings we've done have used a similar approach, but they've all used 
  some kind of middleware. This has saved us some work, but it has added 
  complexity, sometimes reduced reliability, and made installation harder for 
  users. Here, there's nothing but .NET and the libvips shared library.

However, there is also a downside (due to limitation of C#):

* As operations are added to libvips, they will not immediately appear in 
  `NetVips`, they are callable through `Operation.Call()` but the 
  auto-generated methods needs to be regenerated.
