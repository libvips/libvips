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

#ifndef IM_VIMAGE_H
#define IM_VIMAGE_H

/* SWIG includes this file directly rather than going through vipscpp.h ... so
 * we have to define these macros here as well.
 */
#ifdef SWIG
# define VIPS_NAMESPACE_START namespace vips {
# define VIPS_NAMESPACE_END }
#endif /*SWIG*/

/* Don't include these when parsing for SWIG.
 */
#ifndef SWIG
# include <list>
# include <complex>
# include <vector>
#endif /*!SWIG*/

/* Wrap pointers to these, but we don't want to import all the old C API. Just 
 * declare them.
 */
extern "C" {
	struct _VipsImage;

	/* Needed by Vargv, see below.
	 */
	struct im__function;
	typedef void *im__object;
}

VIPS_NAMESPACE_START

/* A VIPS callback, our name for im_callback_fn.
 */
typedef int (*VCallback)( void *, void * );

/* VIPS image class.
 *
 * Slightly tricky: we have two sorts of sharing. Several VImage can share one
 * refblock (while results are being returned from functions, for example),
 * and several other refblocks can have IMAGEs which depend upon this IMAGE
 * for their result.
 */
class VImage {
	/* We'd like this to be protected so that user subclasses can define
	 * their own member wrappers. But sadly C++ doesn't work like that:
	 * subclasses of VImage can only refer to protected members via
	 * this->, which isn't what we need. Just make it public and hope no
	 * one touches it.
	 */
public:
/* Doesn't need to be wrapped.
 */
#ifndef SWIG
	// Count ref etc. in one of these. One for each open VIPS image.
	struct refblock {
		_VipsImage *im;			// IMAGE pointer
		int close_on_delete;		// Set if we must im_close()
		int nrefs;			// Number of refs to us
		std::list<refblock*> orefs;	// Refs im makes 

		// Construct/destruct
		refblock();
		virtual ~refblock() throw( VError );

		// Add a ref - this (output image) depends upon IMAGE in
		void addref( refblock *in ) throw( VError );

		// Remove a ref
		void removeref() throw( VError );

		// Debugging
		void debug_print();

		// Linked list needs "==" -- use address equivalence
		friend int operator==( const refblock &left, 
			const refblock &right ) { return( &left == &right ); }
	};

	refblock *_ref;
#endif /*!SWIG*/

public:
#ifdef DEBUG
	/* All the refblocks in the world.
	 */
	static std::list<refblock*> all_refblock;
#endif /*DEBUG*/

	/* Print all refblocks ... debugging. Compile with DEBUG to enable
	 * this.
	 */
	static void print_all();

	/* Typedefs and enums we need.
	 */

	// Type type
	enum TType {
		MULTIBAND      = 0,
		B_W            = 1,
		LUMINACE       = 2,
		XRAY           = 3,
		IR             = 4,
		YUV            = 5,
		RED_ONLY       = 6,
		GREEN_ONLY     = 7,
		BLUE_ONLY      = 8,
		POWER_SPECTRUM = 9,
		HISTOGRAM      = 10,
		LUT            = 11,
		XYZ            = 12,
		LAB            = 13,
		CMC            = 14,
		CMYK           = 15,
		LABQ           = 16,
		RGB            = 17,
		UCS            = 18,
		LCH            = 19,
		LABS           = 21,
		sRGB	       = 22,
		YXY	       = 23,
		FOURIER	       = 24,
		RGB16	       = 25,
		GREY16	       = 26
	};

	// Format type
	enum TBandFmt {
		FMTNOTSET      = -1,
		FMTUCHAR       = 0,
		FMTCHAR        = 1,
		FMTUSHORT      = 2,
		FMTSHORT       = 3,
		FMTUINT        = 4,
		FMTINT         = 5,
		FMTFLOAT       = 6,
		FMTCOMPLEX     = 7,
		FMTDOUBLE      = 8,
		FMTDPCOMPLEX   = 9
	};

	// Coding type
	enum TCoding {
		NOCODING              = 0,
		COLQUANT              = 1,
		LABPACK               = 2,
		LABPACK_COMPRESSED    = 3,
		RGB_COMPRESSED        = 4,
		LUM_COMPRESSED        = 5,
		RAD        	      = 6
	};

	// Compression type
	enum TCompression {
		NO_COMPRESSION        = 0,
		TCSF_COMPRESSION      = 1,
		JPEG_COMPRESSION      = 2
	};

	/* Start of wrappers for iofuncs.
	 */

	// Plain constructors
	VImage( const char *name, const char *mode = "rd" ) throw( VError );
	VImage( void *data, int width, int height, 
		int bands, TBandFmt format ) throw( VError );
	VImage( _VipsImage *image );
	VImage() throw( VError );

	// Convert to a disc file, eg:
	// 	VImage fred = VImage::convert2disc( "im_jpeg2vips", 
	// 		"file.jpg", "temp.v" );
	// Runs im_jpeg2vips to the temp file, then opens that and returns
	// it. Useful for opening very large files without using a lot of RAM.
	// Now superseded by the format API, though that's not yet wrapped in
	// C++
	// Also replaced by the new default "rd" mode
	static VImage convert2disc( const char* convert, 
		const char* in, const char* disc ) throw( VError );

	// Copy constructor 
	VImage( const VImage &a );

	// Assignment - delete old ref
	VImage &operator=( const VImage &a ) throw( VError );

	// Destructor
	virtual ~VImage() throw( VError ) { _ref->removeref(); }

	// Extract underlying IMAGE* pointer
	_VipsImage *image() const { return( _ref->im ); }

	// Extract underlying data pointer
	void *data() const throw( VError );

	// Write this to another VImage, to a file, or to a mem buffer
	VImage write( VImage out ) throw( VError );
	VImage write( const char *name ) throw( VError );
	VImage write() throw( VError );

	// Debugging ... print header fields
	void debug_print();

	// Projection functions to get header fields
	int Xsize();
	int Ysize();
	int Bands();
	TBandFmt BandFmt();
	TCoding Coding();
	TType Type();
	float Xres();
	float Yres();
	int Length();
	TCompression Compression();
	short Level();
	int Xoffset();
	int Yoffset();

	// Derived fields
	const char *filename();
	const char *Hist();

	// metadata
#ifndef SWIG
	// base functionality
	// we don't wrap GValue, so we can't wrap these for now
	void meta_set( const char *field, GValue *value ) throw( VError );
	void meta_get( const char *field, GValue *value_copy ) throw( VError );
#endif /*SWIG*/

	// We can wrap these, fwiw
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

#ifndef SWIG
	// we don't wrap callbacks yet, so we can't wrap these for now
	void meta_set( const char *field, 
		VCallback free_fn, void *value ) 
		throw( VError );
	void meta_set( const char *field, 
		VCallback free_fn, void *value, size_t length ) 
		throw( VError );
#endif /*SWIG*/

	// Set header fields
	void initdesc( int, int, int, TBandFmt, TCoding, TType, 
		float = 1.0, float = 1.0, int = 0, int = 0 ) throw( VError );

	/* Insert automatically generated headers.
	 */
#include "vipsc++.h"

/* No point getting SWIG to wrap these ... we do this by hand later so we can
 * handle things like "a + 12" correctly.
 */
#ifndef SWIG
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

	// Type conversion: VImage to VDMask and VIMask
	operator VDMask() throw( VError ) 
		{ return( this->vips2mask() ); }
	operator VIMask() throw( VError ) 
		{ return( VIMask( VDMask( *this ) ) ); }
#endif /*!SWIG*/
};

/* Don't include these when parsing for SWIG.
 */
#ifndef SWIG

/* Class wrapping up a vargv. Member function wrappers need this. It needs to
 * be part of the public API in case people subclass VImage and add their own
 * members.
 */
class Vargv {
	// Function we are args to
	im__function *fn;

	// Base of object vector
	im__object *base;

public:
	Vargv( const char *name );
	~Vargv();

	// Reference to element of base
	im__object &data( int i = 0 ) { return( base[i] ); };

	// Invoke function
	void call();
};

#endif /*!SWIG*/

VIPS_NAMESPACE_END

// Other VIPS protos we need 
extern "C" {
extern int im_init_world( const char *argv0 ); 
extern void im__print_all(); 
extern void im_col_Lab2XYZ( 
	float, float, float,
	float *, float *, float * );
}

#endif /*IM_VIMAGE_H*/
