<refmeta>
  <refentrytitle>How to write bindings</refentrytitle>
  <manvolnum>3</manvolnum>
  <refmiscinfo>libvips</refmiscinfo>
</refmeta>

<refnamediv>
  <refname>Binding</refname>
  <refpurpose>Writing bindings for libvips</refpurpose>
</refnamediv>

There are full libvips bindings for quite a few environments now: C, C++,
command-line, Ruby, PHP, Lua, Python and JavaScript (node). 

This chapter runs through the four main styles that have been found to work
well. If you want to write a new binding, one of these should be close
to what you need. 

# Don't bind the top-level C API

The libvips C API (vips_add() and so on) was designed to be easy for humans
to write. It is inconvenient and dangerous to use from other languages due
to its heavy use of varargs.

It's much better to use the layer below. This lower layer is structured as:

- Create operator. You can use vips_operation_new() to make a new
  `VipsOperation` object from an operator nickname, like `"add"`.

- Set parameters. You can loop over the operation with vips_argument_map() to
  get the name and type of each input argument.  For each argument, you
  need to get the value from your language, convert to a `GValue`, then
  use g_object_set_property() to set that value on the operator.

- Execute with vips_cache_operation_build().

- Extract results. Again, you loop over the operator arguments with
  vips_argument_map(), but instead of inputs, this time you look for output
  arguments. You extract their value with g_object_get_property(), and pass
  the value back to your language.

For example, you can execute vips_invert() like this:

```C
/* compile with
 *
 * gcc -g -Wall callvips.c `pkg-config vips --cflags --libs`
 *
 */

#include <vips/vips.h>

int
main( int argc, char **argv )
{
	VipsImage *in;
	VipsImage *out;
	VipsOperation *op;
	VipsOperation *new_op;
	GValue gvalue = { 0 };

	if( VIPS_INIT( argv[0] ) ) 
		/* This shows the vips error buffer and quits with a fail exit
		 * code.
		 */
		vips_error_exit( NULL ); 

	/* This will print a table of any ref leaks on exit, very handy for
	 * development.
	 */
	vips_leak_set( TRUE );

	if( argc != 3 )
		vips_error_exit( "usage: %s input-filename output-filename", 
			argv[0] );

	if( !(in = vips_image_new_from_file( argv[1], NULL )) )
		vips_error_exit( NULL ); 

	/* Create a new operator from a nickname. NULL for unknown operator.
	 */
	op = vips_operation_new( "invert" );

	/* Init a gvalue as an image, set it to in, use the gvalue to set the
	 * operator property.
	 */
	g_value_init( &gvalue, VIPS_TYPE_IMAGE );
	g_value_set_object( &gvalue, in );
	g_object_set_property( G_OBJECT( op ), "in", &gvalue );
	g_value_unset( &gvalue );

	/* We no longer need in: op will hold a ref to it as long as it needs
	 * it. 
	 */
	g_object_unref( in ); 

	/* Call the operation. This will look up the operation+args in the vips
	 * operation cache and either return a previous operation, or build
	 * this one. In either case, we have a new ref we must release.
	 */
	if( !(new_op = vips_cache_operation_build( op )) ) {
		g_object_unref( op );
		vips_error_exit( NULL ); 
	}
	g_object_unref( op );
	op = new_op;

	/* Now get the result from op. g_value_get_object() does not ref the
	 * object, so we need to make a ref for out to hold.
	 */
	g_value_init( &gvalue, VIPS_TYPE_IMAGE );
	g_object_get_property( G_OBJECT( op ), "out", &gvalue );
	out = VIPS_IMAGE( g_value_get_object( &gvalue ) );
	g_object_ref( out ); 
	g_value_unset( &gvalue );

	/* All done: we can unref op. The output objects from op actually hold
	 * refs back to it, so before we can unref op, we must unref them. 
	 */
	vips_object_unref_outputs( VIPS_OBJECT( op ) ); 
	g_object_unref( op );

	if( vips_image_write_to_file( out, argv[2], NULL ) )
		vips_error_exit( NULL ); 

	g_object_unref( out );

	return( 0 ); 
}
```

# Compiled language which can call C

The C++ binding uses this lower layer to define a function called
`VImage::call()` which can call any libvips operator with a set of variable
arguments.

A small Python program walks the set of all libvips operators and generates a
set of static bindings. For example:

```c++
VImage VImage::invert( VOption *options )
{
    VImage out;

    call( "invert", (options ? options : VImage::option()) ->
        set( "in", *this ) ->
        set( "out", &out ) );

    return( out );
}
```

So from C++ you can call any libvips operator (though without static
typechecking) with `VImage::call()`, or use the member functions on `VImage`
to get type-checked calls for at least the required operator arguments.

The `VImage` class also adds automatic reference counting, constant expansion,
operator overloads, and various other useful features.

# Dynamic language with FFI

Languages like Ruby, Python, JavaScript and LuaJIT can't call C directly, but
they do support FFI. The bindings for these languages work rather like C++,
but use FFI to call into libvips and run operations.

Since these languages are dynamic, they can add another trick: they intercept
the method-missing hook and attempt to run any method calls not implemented by
the `Image` class as libvips operators. In effect, the binding is generated at
runtime.

# Dynamic langauge without FFI

PHP does not have a useful FFI, unfortunately, so for this language a small
C module implements the general `vips_call()` function for PHP language
types, and a larger pure PHP layer makes it convenient to use.

# gobject-introspection

The C source code to libvips has been marked up with special comments
describing the interface in a standard way. These comments are read by
the `gobject-introspection` package when libvips is compiled and used to
generate a typelib, a description of how to call the library. Many languages
have gobject-introspection packages: all you need to do to call libvips
from your favorite language is to start g-o-i, load the libvips typelib,
and you should have the whole library available. For example, from Python
it's as simple as:

```python
from gi.repository import Vips
```

You can now use all of the libvips introspection machinery, as noted above. 

Unfortunately g-o-i has some strong disadvantages. It is not very portable,
since you will need a g-o-i layer for whatever platform you are targetting;
it does not cross-compile well, since typelibs include a lot of very-low
level data (such as exact structure layouts); and installation for your
users is likely to be tricky.

If you have a choice, I would recommend simply using FFI. 

# Documentation

You can generate searchable docs from a <code>.gir</code> (the thing that 
is built from scanning libvips and which in turn turn the typelib is 
made from) with <command>g-ir-doc-tool</command>, for example:

```
$ g-ir-doc-tool --language=Python -o ~/mydocs Vips-8.0.gir
```

Then to view them, either:

```
$ yelp ~/mydocs 
```

Or perhaps:

```
$ cd ~/mydocs 
$ yelp-build html .
```

To make HTML docs. This is an easy way to see what you can call in the 
library.
