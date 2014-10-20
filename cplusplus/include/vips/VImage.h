// VIPS image wrapper

/*

    This file is part of VIPS.
    
    VIPS is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef VIPS_VIMAGE_H
#define VIPS_VIMAGE_H

#include <list>
#include <complex>
#include <vector>

#include <vips/vips.h>

VIPS_NAMESPACE_START

/* vips_init() and vips_shutdown as namespaced C++ functions.
 */
void init( const char *argv0 = "nothing" ) throw( VError );
void thread_shutdown( void ); 
void shutdown( void ); 

/* VIPS image class.
 */
class VImage {
protected:
	VipsImage *im = NULL;		// Underlying vips pointer

public:
	VImage() 
	{
		im = NULL; 
	}

	// ref the VipsImage ... see new_steal() for one that steals the
	// caller's ref
	VImage( VipsImage *vips_image )
	{
		g_assert( !im );

		im = vips_image;
		g_object_ref( im ); 
	}

	// make a VImage, stealing the caller's ref
	VImage new_steal( VipsImage *vips_image )
	{
		VImage image;

		g_assert( !image.im );

		image.im = vips_image;
	}

	VImage( const char *filename, const char *mode = "r" ) 
		throw( VError )
	{
		vips_check_init();

		if( !(im = vips_image_new_mode( filename, mode )) )
			throw VError();
	}

	// see vips_image_new_from_file()
	VImage( const char *name, ... ) 
		__attribute__((sentinel)) throw( VError );

	// see vips_image_new_from_buffer()
	VImage( void *buffer, size_t length, const char *option_string, ... )
		__attribute__((sentinel)) throw( VError );

	// see vips_image_new_from_memory()
	VImage( void *data, size_t size, int width, int height, 
		int bands, VipsBandFormat format ) throw( VError )
	{
		vips_check_init();

		if( !(im = vips_image_new_from_memory( data, size, 
			width, height, bands, format )) )
			throw VError();
	}

	// also do
	// vips_image_new_matrix()
	// vips_image_new_matrixv()
	// vips_image_new_matrix_from_array()
	// vips_image_new_from_file_raw:()
	// vips_image_new_from_file_RW()
	// vips_image_new_memory()

	// Copy constructor 
	VImage( const VImage &a )
	{
		g_assert( !im );

		im = a.im;
		g_object_ref( im );
	}

	// Assignment - delete old ref
	VImage &operator=( const VImage &a ) 
	{
		VIPS_UNREF( im );
		im = a.im;
		g_object_ref( im );
	}

	// Destructor
	~VImage() throw( VError ) { VIPS_UNREF( im ); }

	// Peek at the underlying VipsImage pointer
	VipsImage *image() const { return( im ); }

	// get a pointer to the pixels ... can be very slow! this may render
	// the whole image to a memory buffer
	void *data()
		throw( VError )
	{
		if( vips_image_wio_input( im ) )
			throw VError();

		return( VIPS_IMAGE_ADDR( im, 0, 0 ) ); 
	}

	// Write this to another VImage, to a file, or to a mem buffer
	void write( VImage out ) 
		throw( VError )
	{
		if( vips_image_write( im, out.im ) )
			throw VError(); 
	}

	void write( const char *name, ... ) 
		throw( VError );
	{
		if( vips_image_write_to_file( im, out.im ) )
			throw VError(); 
	}

	// see vips_image_write_to_buffer()
	void *write( const char *suffix, size_t *size, ... )
		throw( VError );

	// also need
	//  vips_image_write_to_memory()

	// Projection functions to get header fields
	int width() { return( im->Xsize ); } 
	int height() { return( im->Ysize ); } 
	int bands() { return( im->Bands ); } 
	VipsBandFormat format() { return( im->BandFmt ); } 
	VipsCoding coding() { return( im->Coding ); } 
	VipsInterpretation interpretation() { return( im->Type ); } 
	float xres() { return( im->Xres ); } 
	float yres() { return( im->Yres ); } 
	int xoffset() { return( im->Xoffset ); } 
	int yoffset() { return( im->Yoffset ); } 

	// Derived fields
	const char *filename() { return( im->filename ); } 
	const char *hist() { return( vips_image_get_history( im ) ); } 

	// metadata

	/*

	// base functionality
	void meta_set( const char *field, GValue *value ) throw( VError );
	void meta_get( const char *field, GValue *value_copy ) throw( VError );
	gboolean meta_remove( const char *field );
	GType meta_get_typeof( const char *field );

	// convenience functions
	int meta_get_int( const char *field ) throw( VError );
	double meta_get_double( const char *field ) throw( VError );
	const char *meta_get_string( const char *field ) throw( VError );
	void *meta_get_area( const char *field ) throw( VError );
	void *meta_get_blob( const char *field, size_t *length ) 
		throw( VError );

	void meta_set( const char *field, int value ) throw( VError );
	void meta_set( const char *field, double value ) throw( VError );
	void meta_set( const char *field, const char *value ) throw( VError );

	void meta_set( const char *field, 
		VCallback free_fn, void *value ) 
		throw( VError );
	void meta_set( const char *field, 
		VCallback free_fn, void *value, size_t length ) 
		throw( VError );

	// Set header fields
	void initdesc( int, int, int, 
		VipsBandFormat, VipsCoding, VipsInterpretation, 
		float = 1.0, float = 1.0, int = 0, int = 0 ) throw( VError );
	 */

	/* Insert automatically generated headers.
	 */
#include "vips-operators.h"

	/*

	// And some in-line operator equivalences done by hand
	friend VImage operator+( VImage a, VImage b ) throw( VError ) 
		{ return( a.add( b ) ); }
	friend VImage operator+( double a, VImage b ) throw( VError )
		{ return( b.lin( 1.0, a ) ); }
	friend VImage operator+( VImage a, double b ) throw( VError )
		{ return( a.lin( 1.0, b ) ); }

	friend VImage operator-( VImage a, VImage b ) throw( VError )
		{ return( a.subtract( b ) ); }
	friend VImage operator-( double a, VImage b ) throw( VError )
		{ return( b.lin( -1.0, a ) ); }
	friend VImage operator-( VImage a, double b ) throw( VError )
		{ return( a.lin( 1.0, -b ) ); }

	friend VImage operator*( VImage a, VImage b ) throw( VError )
		{ return( a.multiply( b ) ); }
	friend VImage operator*( double a, VImage b ) throw( VError )
		{ return( b.lin( a, 0.0 ) ); }
	friend VImage operator*( VImage a, double b ) throw( VError )
		{ return( a.lin( b, 0.0 ) ); }

	friend VImage operator/( VImage a, VImage b ) throw( VError )
		{ return( a.divide( b ) ); }
	friend VImage operator/( double a, VImage b ) throw( VError )
		{ return( b.pow( -1.0 ).lin( a, 0.0 ) ); }
	friend VImage operator/( VImage a, double b ) throw( VError )
		{ return( a.lin( 1.0/b, 0.0 ) ); }

	friend VImage operator%( VImage a, VImage b ) throw( VError )
		{ return( a.remainder( b ) ); }
	friend VImage operator%( VImage a, double b ) throw( VError )
		{ return( a.remainder( b ) ); }

	friend VImage operator<( VImage a, VImage b ) throw( VError )
		{ return( a.less( b ) ); }
	friend VImage operator<( double a, VImage b ) throw( VError )
		{ return( b.more( a ) ); }
	friend VImage operator<( VImage a, double b ) throw( VError )
		{ return( a.less( b ) ); }

	friend VImage operator<=( VImage a, VImage b ) throw( VError )
		{ return( a.lesseq( b ) ); }
	friend VImage operator<=( double a, VImage b ) throw( VError )
		{ return( b.moreeq( a ) ); }
	friend VImage operator<=( VImage a, double b ) throw( VError )
		{ return( a.lesseq( b ) ); }

	friend VImage operator>( VImage a, VImage b ) throw( VError )
		{ return( a.more( b ) ); }
	friend VImage operator>( double a, VImage b ) throw( VError )
		{ return( b.less( a ) ); }
	friend VImage operator>( VImage a, double b ) throw( VError )
		{ return( a.more( b ) ); }

	friend VImage operator>=( VImage a, VImage b ) throw( VError )
		{ return( a.moreeq( b ) ); }
	friend VImage operator>=( double a, VImage b ) throw( VError )
		{ return( b.lesseq( a ) ); }
	friend VImage operator>=( VImage a, double b ) throw( VError )
		{ return( a.moreeq( b ) ); }

	friend VImage operator==( VImage a, VImage b ) throw( VError )
		{ return( a.equal( b ) ); }
	friend VImage operator==( double a, VImage b ) throw( VError )
		{ return( b.equal( a ) ); }
	friend VImage operator==( VImage a, double b ) throw( VError )
		{ return( a.equal( b ) ); }

	friend VImage operator!=( VImage a, VImage b ) throw( VError )
		{ return( a.notequal( b ) ); }
	friend VImage operator!=( double a, VImage b ) throw( VError )
		{ return( b.notequal( a ) ); }
	friend VImage operator!=( VImage a, double b ) throw( VError )
		{ return( a.notequal( b ) ); }

	friend VImage operator&( VImage a, VImage b ) throw( VError )
		{ return( a.andimage( b ) ); }
	friend VImage operator&( int a, VImage b ) throw( VError )
		{ return( b.andimage( a ) ); }
	friend VImage operator&( VImage a, int b ) throw( VError )
		{ return( a.andimage( b ) ); }

	friend VImage operator|( VImage a, VImage b ) throw( VError )
		{ return( a.orimage( b ) ); }
	friend VImage operator|( int a, VImage b ) throw( VError )
		{ return( b.orimage( a ) ); }
	friend VImage operator|( VImage a, int b ) throw( VError )
		{ return( a.orimage( b ) ); }

	friend VImage operator^( VImage a, VImage b ) throw( VError )
		{ return( a.eorimage( b ) ); }
	friend VImage operator^( int a, VImage b ) throw( VError )
		{ return( b.eorimage( a ) ); }
	friend VImage operator^( VImage a, int b ) throw( VError )
		{ return( a.eorimage( b ) ); }

	friend VImage operator<<( VImage a, int b ) throw( VError )
		{ return( a.shiftleft( b ) ); }
	friend VImage operator>>( VImage a, int b ) throw( VError )
		{ return( a.shiftright( b ) ); }

	friend VImage operator-( VImage a ) throw( VError )
		{ return( a * -1 ); }
	 */

};

VIPS_NAMESPACE_END

#endif /*VIPS_VIMAGE_H*/
