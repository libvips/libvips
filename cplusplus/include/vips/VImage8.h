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

enum VSteal {
	NOSTEAL = 0,
	STEAL = 1
};

/* A smart VipsObject pointer class ... use g_object_ref()/_unref() for
 * lifetime management.
 */
class VObject
{
private:
	// can be NULL, see eg. VObject()
	VipsObject *vobject; 

public:
	VObject( VipsObject *new_vobject, VSteal steal = STEAL ) : 
		vobject( new_vobject )
	{
		// we allow NULL init, eg. "VImage a;"
		g_assert( !new_vobject ||
			VIPS_IS_OBJECT( new_vobject ) ); 

#ifdef DEBUG
		printf( "VObject constructor, obj = %p, steal = %d\n",
			new_vobject, steal ); 
		if( new_vobject ) { 
			printf( "   obj " ); 
			vips_object_print_name( VIPS_OBJECT( new_vobject ) );
			printf( "\n" ); 
		}
#endif /*DEBUG*/

		if( !steal ) {
#ifdef DEBUG
			printf( "   reffing object\n" ); 
#endif /*DEBUG*/
			g_object_ref( vobject ); 
		}
	}

	VObject() :
		vobject( 0 )
	{
	}

	// copy constructor 
	VObject( const VObject &a ) : 
		vobject( a.vobject )
	{
		g_assert( VIPS_IS_OBJECT( a.vobject ) ); 

#ifdef DEBUG
		printf( "VObject copy constructor, obj = %p\n", 
			vobject ); 
		printf( "   reffing object\n" ); 
#endif /*DEBUG*/
		g_object_ref( vobject );
	}

	// assignment ... we must delete the old ref
	// old can be NULL, new must not be NULL
	VObject &operator=( const VObject &a )
	{
		VipsObject *old_vobject;

#ifdef DEBUG
		printf( "VObject assignment\n" );  
		printf( "   reffing %p\n", a.vobject ); 
		printf( "   unreffing %p\n", vobject ); 
#endif /*DEBUG*/

		g_assert( !vobject ||
			VIPS_IS_OBJECT( vobject ) ); 
		g_assert( a.vobject &&
			VIPS_IS_OBJECT( a.vobject ) ); 

		// delete the old ref at the end ... otherwise "a = a;" could
		// unref before reffing again 
		old_vobject = vobject;
		vobject = a.vobject;
		g_object_ref( vobject ); 
		if( old_vobject )
			g_object_unref( old_vobject );

		return( *this ); 
	}

	// this mustn't be virtual: we want this class to only be a pointer,
	// no vtable allowed
	~VObject()
	{
#ifdef DEBUG
		printf( "VObject destructor\n" );  
		printf( "   unreffing %p\n", vobject ); 
#endif /*DEBUG*/

		g_assert( !vobject ||
			VIPS_IS_OBJECT( vobject ) ); 
		
		if( vobject ) 
			g_object_unref( vobject ); 
	}

	VipsObject *get_object()
	{
		g_assert( !vobject ||
			VIPS_IS_OBJECT( vobject ) ); 

		return( vobject ); 
	}

};

class VImage; 
class VOption; 

class VOption
{
private:
	struct Pair {
		const char *name;

		// the thing we pass to VipsOperation
		GValue value;

		// an input or output parameter ... we guess the direction
		// from the arg to set()
		bool input; 

		union {
			// we need to box and unbox VImage ... keep a pointer 
			// to the VImage from C++ here
			VImage *vimage;

			// output double
			double *vdouble;

			// output int
			int *vint;

			// output doublearray
			std::vector<double> *vvector;

			// output Blob
			VipsBlob **vblob;

			// output bool
			bool *vbool;
		}; 

		Pair( const char *name ) : 
			name( name ), input( false ), vimage( 0 )
		{
			G_VALUE_TYPE( &value ) = 0;
		}

		~Pair()
		{
			g_value_unset( &value );
		}
	};

	std::list<Pair *> options;

public:
	VOption()
	{
	}

	virtual ~VOption();

	VOption *set( const char *name, bool value ); 
	VOption *set( const char *name, int value );
	VOption *set( const char *name, double value );
	VOption *set( const char *name, const char *value );
	VOption *set( const char *name, VImage value );
	VOption *set( const char *name, std::vector<VImage> value );
	VOption *set( const char *name, std::vector<double> value );
	VOption *set( const char *name, VipsBlob *value ); 

	VOption *set( const char *name, bool *value ); 
	VOption *set( const char *name, int *value );
	VOption *set( const char *name, double *value );
	VOption *set( const char *name, VImage *value );
	VOption *set( const char *name, std::vector<double> *value );
	VOption *set( const char *name, VipsBlob **blob ); 

	void set_operation( VipsOperation *operation );
	void get_operation( VipsOperation *operation );

};

class VImage : VObject
{
public:
	VImage( VipsImage *image, VSteal steal = STEAL ) : 
		VObject( (VipsObject *) image, steal )
	{
	}

	// an empty (NULL) VImage, eg. "VImage a;"
	VImage() :
		VObject( 0 )
	{
	}

	VipsImage *get_image()
	{
		return( (VipsImage *) VObject::get_object() );
	}

	int width()
	{
		return( vips_image_get_width( get_image() ) ); 
	}

	int height()
	{
		return( vips_image_get_height( get_image() ) ); 
	}

	int bands()
	{
		return( vips_image_get_bands( get_image() ) ); 
	}

	VipsBandFormat format()
	{
		return( vips_image_get_format( get_image() ) ); 
	}

	VipsCoding coding()
	{
		return( vips_image_get_coding( get_image() ) ); 
	}

	VipsInterpretation interpretation()
	{
		return( vips_image_get_interpretation( get_image() ) ); 
	}

	VipsInterpretation guess_interpretation()
	{
		return( vips_image_guess_interpretation( get_image() ) ); 
	}

	double xres()
	{
		return( vips_image_get_xres( get_image() ) ); 
	}

	double yres()
	{
		return( vips_image_get_yres( get_image() ) ); 
	}

	double xoffset()
	{
		return( vips_image_get_xoffset( get_image() ) ); 
	}

	double yoffset()
	{
		return( vips_image_get_yoffset( get_image() ) ); 
	}

	const char *filename()
	{
		return( vips_image_get_filename( get_image() ) ); 
	}

	double scale()
	{
		return( vips_image_get_scale( get_image() ) ); 
	}

	double offset()
	{
		return( vips_image_get_offset( get_image() ) ); 
	}

	const void *data()
	{
		return( vips_image_get_data( get_image() ) ); 
	}

	static VOption *option()
	{
		return( new VOption() );
	}

	static void call_option_string( const char *operation_name, 
		const char *option_string, VOption *options = 0 ) 
		throw( VError );
	static void call( const char *operation_name, VOption *options = 0 ) 
		throw( VError );

	static VImage new_from_file( const char *name, VOption *options = 0 )
		throw( VError );
	VImage new_from_image( std::vector<double> pixel )
		throw( VError );
	VImage new_from_image( double pixel )
		throw( VError );

	void write_to_file( const char *name, VOption *options = 0 )
		throw( VError );

#include "vips-operators.h"

	// a few useful things
	
	VImage linear( double a, double b, VOption *options = 0 )
		throw( VError );

	std::vector<VImage> bandsplit( VOption *options = 0 )
		throw( VError );

	VImage bandjoin( VImage other, VOption *options = 0 )
		throw( VError );

	std::complex<double> minpos( VOption *options = 0 )
		throw( VError );

	std::complex<double> maxpos( VOption *options = 0 )
		throw( VError );

	VImage floor( VOption *options = 0 )
		throw( VError )
	{
		return( round( VIPS_OPERATION_ROUND_FLOOR, options ) ); 
	}

	VImage ceil( VOption *options = 0 )
		throw( VError )
	{
		return( round( VIPS_OPERATION_ROUND_CEIL, options ) ); 
	}

	VImage rint( VOption *options = 0 )
		throw( VError )
	{
		return( round( VIPS_OPERATION_ROUND_RINT, options ) ); 
	}

	VImage real( VOption *options = 0 )
		throw( VError )
	{
		return( complexget( VIPS_OPERATION_COMPLEXGET_REAL, options ) );
	}

	VImage imag( VOption *options = 0 )
		throw( VError )
	{
		return( complexget( VIPS_OPERATION_COMPLEXGET_IMAG, options ) );
	}

	VImage polar( VOption *options = 0 )
		throw( VError )
	{
		return( complex( VIPS_OPERATION_COMPLEX_POLAR, options ) );
	}

	VImage rect( VOption *options = 0 )
		throw( VError )
	{
		return( complex( VIPS_OPERATION_COMPLEX_RECT, options ) );
	}

	VImage conj( VOption *options = 0 )
		throw( VError )
	{
		return( complex( VIPS_OPERATION_COMPLEX_CONJ, options ) );
	}

	VImage sin( VOption *options = 0 )
		throw( VError )
	{
		return( math( VIPS_OPERATION_MATH_SIN, options ) );
	}

	VImage cos( VOption *options = 0 )
		throw( VError )
	{
		return( math( VIPS_OPERATION_MATH_COS, options ) );
	}

	VImage tan( VOption *options = 0 )
		throw( VError )
	{
		return( math( VIPS_OPERATION_MATH_TAN, options ) );
	}

	VImage asin( VOption *options = 0 )
		throw( VError )
	{
		return( math( VIPS_OPERATION_MATH_ASIN, options ) );
	}

	VImage acos( VOption *options = 0 )
		throw( VError )
	{
		return( math( VIPS_OPERATION_MATH_ACOS, options ) );
	}

	VImage atan( VOption *options = 0 )
		throw( VError )
	{
		return( math( VIPS_OPERATION_MATH_ATAN, options ) );
	}

	VImage log( VOption *options = 0 )
		throw( VError )
	{
		return( math( VIPS_OPERATION_MATH_LOG, options ) );
	}

	VImage log10( VOption *options = 0 )
		throw( VError )
	{
		return( math( VIPS_OPERATION_MATH_LOG10, options ) );
	}

	VImage exp( VOption *options = 0 )
		throw( VError )
	{
		return( math( VIPS_OPERATION_MATH_EXP, options ) );
	}

	VImage exp10( VOption *options = 0 )
		throw( VError )
	{
		return( math( VIPS_OPERATION_MATH_EXP10, options ) );
	}

	/*
	VImage ifthenelse( double th, VImage el, VOption *options = 0 )
		throw( VError );
	VImage ifthenelse( VImage th, double el, VOption *options = 0 )
		throw( VError );
	VImage ifthenelse( double th, double el, VOption *options = 0 )
		throw( VError );

	VImage ifthenelse( std::vector<double> th, VImage el, 
		VOption *options = 0 )
		throw( VError );
	VImage ifthenelse( VImage th, std::vector<double> el, 
		VOption *options = 0 )
		throw( VError );
	VImage ifthenelse( std::vector<double> th, std::vector<double> el, 
		VOption *options = 0 )
		throw( VError );
	 */

};

VIPS_NAMESPACE_END

#endif /*VIPS_VIMAGE_H*/
