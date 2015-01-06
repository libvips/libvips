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

#include <string.h>

#include <vips/vips.h>

VIPS_NAMESPACE_START

/* Small utility things.
 */

std::vector<double> to_vectorv( int n, ... ); 
std::vector<double> to_vector( double value );
std::vector<double> to_vector( int n, double array[] );
std::vector<double> negate( std::vector<double> value ); 
std::vector<double> invert( std::vector<double> value ); 

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

#ifdef VIPS_DEBUG_VERBOSE
		printf( "VObject constructor, obj = %p, steal = %d\n",
			new_vobject, steal ); 
		if( new_vobject ) { 
			printf( "   obj " ); 
			vips_object_print_name( VIPS_OBJECT( new_vobject ) );
			printf( "\n" ); 
		}
#endif /*VIPS_DEBUG_VERBOSE*/

		if( !steal ) {
#ifdef VIPS_DEBUG_VERBOSE
			printf( "   reffing object\n" ); 
#endif /*VIPS_DEBUG_VERBOSE*/
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

#ifdef VIPS_DEBUG_VERBOSE
		printf( "VObject copy constructor, obj = %p\n", 
			vobject ); 
		printf( "   reffing object\n" ); 
#endif /*VIPS_DEBUG_VERBOSE*/
		g_object_ref( vobject );
	}

	// assignment ... we must delete the old ref
	// old can be NULL, new must not be NULL
	VObject &operator=( const VObject &a )
	{
		VipsObject *old_vobject;

#ifdef VIPS_DEBUG_VERBOSE
		printf( "VObject assignment\n" );  
		printf( "   reffing %p\n", a.vobject ); 
		printf( "   unreffing %p\n", vobject ); 
#endif /*VIPS_DEBUG_VERBOSE*/

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
#ifdef VIPS_DEBUG_VERBOSE
		printf( "VObject destructor\n" );  
		printf( "   unreffing %p\n", vobject ); 
#endif /*VIPS_DEBUG_VERBOSE*/

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

		// the thing we pass to and from our caller
		GValue value; 

		// an input or output parameter ... we guess the direction
		// from the arg to set()
		bool input; 

		// the pointer we write output values to
		union {
			bool *vbool;
			int *vint;
			double *vdouble;
			VImage *vimage;
			std::vector<double> *vvector;
			VipsBlob **vblob;
		}; 

		Pair( const char *name ) : 
			name( name ), input( false ), vimage( 0 )
		{
			// argh = {0} won't work wil vanilla C++
			memset( &value, 0, sizeof( GValue ) ); 
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

	VipsImage *
	get_image()
	{
		return( (VipsImage *) VObject::get_object() );
	}

	int 
	width()
	{
		return( vips_image_get_width( get_image() ) ); 
	}

	int 
	height()
	{
		return( vips_image_get_height( get_image() ) ); 
	}

	int 
	bands()
	{
		return( vips_image_get_bands( get_image() ) ); 
	}

	VipsBandFormat 
	format()
	{
		return( vips_image_get_format( get_image() ) ); 
	}

	VipsCoding 
	coding()
	{
		return( vips_image_get_coding( get_image() ) ); 
	}

	VipsInterpretation 
	interpretation()
	{
		return( vips_image_get_interpretation( get_image() ) ); 
	}

	VipsInterpretation 
	guess_interpretation()
	{
		return( vips_image_guess_interpretation( get_image() ) ); 
	}

	double 
	xres()
	{
		return( vips_image_get_xres( get_image() ) ); 
	}

	double 
	yres()
	{
		return( vips_image_get_yres( get_image() ) ); 
	}

	double 
	xoffset()
	{
		return( vips_image_get_xoffset( get_image() ) ); 
	}

	double 
	yoffset()
	{
		return( vips_image_get_yoffset( get_image() ) ); 
	}

	const char *
	filename()
	{
		return( vips_image_get_filename( get_image() ) ); 
	}

	const void *
	data()
	{
		return( vips_image_get_data( get_image() ) ); 
	}

	void 
	set( const char *field, int value )
	{
		vips_image_set_int( this->get_image(), field, value ); 
	}

	void 
	set( const char *field, double value )
	{
		vips_image_set_double( this->get_image(), field, value ); 
	}

	void 
	set( const char *field, const char *value )
	{
		vips_image_set_string( this->get_image(), field, value ); 
	}

	void 
	set( const char *field, 
		VipsCallbackFn free_fn, void *data, size_t length )
	{
		vips_image_set_blob( this->get_image(), field, 
			free_fn, data, length ); 
	}

	int 
	get_typeof( const char *field )
	{
		return( vips_image_get_typeof( this->get_image(), field ) ); 
	}

	int 
	get_int( const char *field )
		throw( VError )
	{
		int value;

		if( vips_image_get_int( this->get_image(), field, &value ) )
			throw( VError() ); 

		return( value ); 
	}

	double 
	get_double( const char *field )
		throw( VError )
	{
		double value;

		if( vips_image_get_double( this->get_image(), field, &value ) )
			throw( VError() ); 

		return( value ); 
	}

	const char *
	get_string( const char *field )
		throw( VError )
	{
		const char *value; 

		if( vips_image_get_string( this->get_image(), field, &value ) )
			throw( VError() ); 

		return( value ); 
	}

	const void *
	get_blob( const char *field, size_t *length )
	{
		void *value; 

		if( vips_image_get_blob( this->get_image(), field, 
			&value, length ) )
			throw( VError() ); 

		return( value ); 
	}

	static VOption *
	option()
	{
		return( new VOption() );
	}

	static void call_option_string( const char *operation_name, 
		const char *option_string, VOption *options = 0 ) 
		throw( VError );
	static void call( const char *operation_name, VOption *options = 0 ) 
		throw( VError );

	static VImage 
	new_memory()
	{
		return( VImage( vips_image_new_memory() ) ); 
	}

	static VImage 
	new_temp_file( const char *file_format = ".v" )
		throw( VError ) 
	{
		VipsImage *image;

		if( !(image = vips_image_new_temp_file( file_format )) )
			throw( VError() ); 

		return( VImage( image ) ); 
	}

	static VImage new_from_file( const char *name, VOption *options = 0 )
		throw( VError );

	static VImage new_from_memory( void *data, size_t size,
		int width, int height, int bands, VipsBandFormat format )
		throw( VError )
	{
		VipsImage *image;

		if( !(image = vips_image_new_from_memory( data, size, 
			width, height, bands, format )) )
			throw( VError() ); 

		return( VImage( image ) ); 
	}

	static VImage new_from_buffer( void *buf, size_t len,
		const char *option_string, VOption *options = 0 )
		throw( VError );

	static VImage new_matrix( int width, int height );

	static VImage new_matrix( int width, int height, 
		double *array, int size )
		throw( VError )
	{
		VipsImage *image;

		if( !(image = vips_image_new_matrix_from_array( width, height,
			array, size )) )
			throw( VError() ); 

		return( VImage( image ) ); 
	}

	static VImage new_matrixv( int width, int height, ... );

	VImage new_from_image( std::vector<double> pixel )
		throw( VError );
	VImage new_from_image( double pixel )
		throw( VError );

	void write( VImage out )
		throw( VError );

	void write_to_file( const char *name, VOption *options = 0 )
		throw( VError );

	void write_to_buffer( const char *suffix, void **buf, size_t *size, 
		VOption *options = 0 )
		throw( VError );

	void *write_to_memory( size_t *size )
		throw( VError )
	{
		void *result;

		if( !(result = vips_image_write_to_memory( this->get_image(), 
			size )) )
			throw( VError() ); 

		return( result ); 
	}

#include "vips-operators.h"

	// a few useful things

	VImage
	linear( double a, double b, VOption *options = 0 )
		throw( VError )
	{
		return( this->linear( to_vector( a ), to_vector( b ), 
			options ) ); 
	}

	VImage
	linear( std::vector<double> a, double b, VOption *options = 0 )
		throw( VError )
	{
		return( this->linear( a, to_vector( b ), options ) ); 
	}

	VImage
	linear( double a, std::vector<double> b, VOption *options = 0 )
		throw( VError )
	{
		return( this->linear( to_vector( a ), b, options ) ); 
	}

	std::vector<VImage> bandsplit( VOption *options = 0 )
		throw( VError );

	VImage bandjoin( VImage other, VOption *options = 0 )
		throw( VError );

	VImage
	bandjoin( double other, VOption *options = 0 )
		throw( VError )
	{
		return( bandjoin( this->new_from_image( other ), options ) ); 
	}

	VImage
	bandjoin( std::vector<double> other, VOption *options = 0 )
		throw( VError )
	{
		return( bandjoin( this->new_from_image( other ), options ) ); 
	}

	std::complex<double> minpos( VOption *options = 0 )
		throw( VError );

	std::complex<double> maxpos( VOption *options = 0 )
		throw( VError );

	VImage 
	floor( VOption *options = 0 )
		throw( VError )
	{
		return( round( VIPS_OPERATION_ROUND_FLOOR, options ) ); 
	}

	VImage 
	ceil( VOption *options = 0 )
		throw( VError )
	{
		return( round( VIPS_OPERATION_ROUND_CEIL, options ) ); 
	}

	VImage 
	rint( VOption *options = 0 )
		throw( VError )
	{
		return( round( VIPS_OPERATION_ROUND_RINT, options ) ); 
	}

	VImage 
	real( VOption *options = 0 )
		throw( VError )
	{
		return( complexget( VIPS_OPERATION_COMPLEXGET_REAL, options ) );
	}

	VImage 
	imag( VOption *options = 0 )
		throw( VError )
	{
		return( complexget( VIPS_OPERATION_COMPLEXGET_IMAG, options ) );
	}

	VImage 
	polar( VOption *options = 0 )
		throw( VError )
	{
		return( complex( VIPS_OPERATION_COMPLEX_POLAR, options ) );
	}

	VImage 
	rect( VOption *options = 0 )
		throw( VError )
	{
		return( complex( VIPS_OPERATION_COMPLEX_RECT, options ) );
	}

	VImage 
	conj( VOption *options = 0 )
		throw( VError )
	{
		return( complex( VIPS_OPERATION_COMPLEX_CONJ, options ) );
	}

	VImage 
	sin( VOption *options = 0 )
		throw( VError )
	{
		return( math( VIPS_OPERATION_MATH_SIN, options ) );
	}

	VImage 
	cos( VOption *options = 0 )
		throw( VError )
	{
		return( math( VIPS_OPERATION_MATH_COS, options ) );
	}

	VImage 
	tan( VOption *options = 0 )
		throw( VError )
	{
		return( math( VIPS_OPERATION_MATH_TAN, options ) );
	}

	VImage 
	asin( VOption *options = 0 )
		throw( VError )
	{
		return( math( VIPS_OPERATION_MATH_ASIN, options ) );
	}

	VImage 
	acos( VOption *options = 0 )
		throw( VError )
	{
		return( math( VIPS_OPERATION_MATH_ACOS, options ) );
	}

	VImage 
	atan( VOption *options = 0 )
		throw( VError )
	{
		return( math( VIPS_OPERATION_MATH_ATAN, options ) );
	}

	VImage 
	log( VOption *options = 0 )
		throw( VError )
	{
		return( math( VIPS_OPERATION_MATH_LOG, options ) );
	}

	VImage 
	log10( VOption *options = 0 )
		throw( VError )
	{
		return( math( VIPS_OPERATION_MATH_LOG10, options ) );
	}

	VImage 
	exp( VOption *options = 0 )
		throw( VError )
	{
		return( math( VIPS_OPERATION_MATH_EXP, options ) );
	}

	VImage 
	exp10( VOption *options = 0 )
		throw( VError )
	{
		return( math( VIPS_OPERATION_MATH_EXP10, options ) );
	}

	VImage 
	pow( VImage other, VOption *options = 0 )
		throw( VError )
	{
		return( math2( other, VIPS_OPERATION_MATH2_POW, options ) );
	}

	VImage 
	pow( double other, VOption *options = 0 )
		throw( VError )
	{
		return( math2_const( to_vector( other ), 
			VIPS_OPERATION_MATH2_POW, options ) );
	}

	VImage 
	pow( std::vector<double> other, VOption *options = 0 )
		throw( VError )
	{
		return( math2_const( other, 
			VIPS_OPERATION_MATH2_POW, options ) );
	}

	VImage 
	wop( VImage other, VOption *options = 0 )
		throw( VError )
	{
		return( math2( other, VIPS_OPERATION_MATH2_WOP, options ) );
	}

	VImage 
	wop( double other, VOption *options = 0 )
		throw( VError )
	{
		return( math2_const( to_vector( other ), 
			VIPS_OPERATION_MATH2_WOP, options ) );
	}

	VImage 
	wop( std::vector<double> other, VOption *options = 0 )
		throw( VError )
	{
		return( math2_const( other, 
			VIPS_OPERATION_MATH2_WOP, options ) );
	}

	VImage 
	ifthenelse( std::vector<double> th, VImage el, VOption *options = 0 )
		throw( VError )
	{
		return( ifthenelse( el.new_from_image( th ), el, options ) ); 
	}

	VImage 
	ifthenelse( VImage th, std::vector<double> el, VOption *options = 0 )
		throw( VError )
	{
		return( ifthenelse( th, th.new_from_image( el ), options ) ); 
	}

	VImage 
	ifthenelse( std::vector<double> th, std::vector<double> el, 
		VOption *options = 0 )
		throw( VError )
	{
		return( ifthenelse( new_from_image( th ), new_from_image( el ),
			options ) ); 
	}

	VImage 
	ifthenelse( double th, VImage el, VOption *options )
		throw( VError )
	{
		return( ifthenelse( to_vector( th ), el, options ) ); 
	}

	VImage 
	ifthenelse( VImage th, double el, VOption *options )
		throw( VError )
	{
		return( ifthenelse( th, to_vector( el ), options ) ); 
	}

	VImage 
	ifthenelse( double th, double el, VOption *options )
		throw( VError )
	{
		return( ifthenelse( to_vector( th ), to_vector( el ), 
			options ) );
	}

	// Operator overloads

	double operator()( int x, int y, int z = 0 )
	{
		return( this->getpoint( x, y )[z] ); 
	}

	friend VImage operator+( VImage a, VImage b ) 
		throw( VError ) 
	{
		return( a.add( b ) );
	}

	friend VImage operator+( double a, VImage b ) 
		throw( VError )
	{
		return( b.linear( 1.0, a ) ); 
	}

	friend VImage operator+( VImage a, double b ) 
		throw( VError )
	{ 
		return( a.linear( 1.0, b ) ); 
	}

	friend VImage operator+( std::vector<double> a, VImage b ) 
		throw( VError )
	{
		return( b.linear( 1.0, a ) ); 
	}

	friend VImage operator+( VImage a, std::vector<double> b ) 
		throw( VError )
	{ 
		return( a.linear( 1.0, b ) ); 
	}

	friend VImage operator-( VImage a, VImage b ) 
		throw( VError ) 
	{
		return( a.subtract( b ) );
	}

	friend VImage operator-( double a, VImage b ) 
		throw( VError )
	{
		return( b.linear( -1.0, a ) ); 
	}

	friend VImage operator-( VImage a, double b ) 
		throw( VError )
	{ 
		return( a.linear( 1.0, -b ) ); 
	}

	friend VImage operator-( std::vector<double> a, VImage b ) 
		throw( VError )
	{
		return( b.linear( -1.0, a ) ); 
	}

	friend VImage operator-( VImage a, std::vector<double> b ) 
		throw( VError )
	{ 
		return( a.linear( 1.0, vips::negate( b ) ) ); 
	}

	friend VImage operator*( VImage a, VImage b ) 
		throw( VError ) 
	{
		return( a.multiply( b ) );
	}

	friend VImage operator*( double a, VImage b ) 
		throw( VError )
	{
		return( b.linear( a, 0.0 ) ); 
	}

	friend VImage operator*( VImage a, double b ) 
		throw( VError )
	{ 
		return( a.linear( b, 0.0 ) ); 
	}

	friend VImage operator*( std::vector<double> a, VImage b ) 
		throw( VError )
	{
		return( b.linear( a, 0.0 ) ); 
	}

	friend VImage operator*( VImage a, std::vector<double> b ) 
		throw( VError )
	{ 
		return( a.linear( b, 0.0 ) ); 
	}

	friend VImage operator/( VImage a, VImage b ) 
		throw( VError ) 
	{
		return( a.divide( b ) );
	}

	friend VImage operator/( double a, VImage b ) 
		throw( VError )
	{
		return( b.pow( -1.0 ).linear( a, 0.0 ) ); 
	}

	friend VImage operator/( VImage a, double b ) 
		throw( VError )
	{ 
		return( a.linear( 1.0 / b, 0.0 ) ); 
	}

	friend VImage operator/( std::vector<double> a, VImage b ) 
		throw( VError )
	{
		return( b.pow( -1.0 ).linear( a, 0.0 ) ); 
	}

	friend VImage operator/( VImage a, std::vector<double> b ) 
		throw( VError )
	{ 
		return( a.linear( vips::invert( b ), 0.0 ) ); 
	}

	friend VImage operator%( VImage a, VImage b ) 
		throw( VError ) 
	{
		return( a.remainder( b ) );
	}

	friend VImage operator%( VImage a, double b ) 
		throw( VError )
	{ 
		return( a.remainder_const( to_vector( b ) ) ); 
	}

	friend VImage operator%( VImage a, std::vector<double> b ) 
		throw( VError )
	{ 
		return( a.remainder_const( b ) ); 
	}

	friend VImage operator<( VImage a, VImage b ) 
		throw( VError ) 
	{
		return( a.relational( b, VIPS_OPERATION_RELATIONAL_LESS ) );
	}

	friend VImage operator<( double a, VImage b ) 
		throw( VError )
	{
		return( b.relational_const( to_vector( a ), 
			VIPS_OPERATION_RELATIONAL_MORE ) );
	}

	friend VImage operator<( VImage a, double b ) 
		throw( VError )
	{ 
		return( a.relational_const( to_vector( b ), 
			VIPS_OPERATION_RELATIONAL_LESS ) );
	}

	friend VImage operator<( std::vector<double> a, VImage b ) 
		throw( VError )
	{
		return( b.relational_const( a, 
			VIPS_OPERATION_RELATIONAL_MORE ) );
	}

	friend VImage operator<( VImage a, std::vector<double> b ) 
		throw( VError )
	{ 
		return( a.relational_const( b, 
			VIPS_OPERATION_RELATIONAL_LESS ) );
	}

	friend VImage operator<=( VImage a, VImage b ) 
		throw( VError ) 
	{
		return( a.relational( b, VIPS_OPERATION_RELATIONAL_LESSEQ ) );
	}

	friend VImage operator<=( double a, VImage b ) 
		throw( VError )
	{
		return( b.relational_const( to_vector( a ), 
			VIPS_OPERATION_RELATIONAL_MOREEQ ) );
	}

	friend VImage operator<=( VImage a, double b ) 
		throw( VError )
	{ 
		return( a.relational_const( to_vector( b ), 
			VIPS_OPERATION_RELATIONAL_LESSEQ ) );
	}

	friend VImage operator<=( std::vector<double> a, VImage b ) 
		throw( VError )
	{
		return( b.relational_const( a, 
			VIPS_OPERATION_RELATIONAL_MOREEQ ) );
	}

	friend VImage operator<=( VImage a, std::vector<double> b ) 
		throw( VError )
	{ 
		return( a.relational_const( b, 
			VIPS_OPERATION_RELATIONAL_LESSEQ ) );
	}

	friend VImage operator>( VImage a, VImage b ) 
		throw( VError ) 
	{
		return( a.relational( b, VIPS_OPERATION_RELATIONAL_MORE ) );
	}

	friend VImage operator>( double a, VImage b ) 
		throw( VError )
	{
		return( b.relational_const( to_vector( a ), 
			VIPS_OPERATION_RELATIONAL_LESS ) );
	}

	friend VImage operator>( VImage a, double b ) 
		throw( VError )
	{ 
		return( a.relational_const( to_vector( b ), 
			VIPS_OPERATION_RELATIONAL_MORE ) );
	}

	friend VImage operator>( std::vector<double> a, VImage b ) 
		throw( VError )
	{
		return( b.relational_const( a, 
			VIPS_OPERATION_RELATIONAL_LESS ) );
	}

	friend VImage operator>( VImage a, std::vector<double> b ) 
		throw( VError )
	{ 
		return( a.relational_const( b, 
			VIPS_OPERATION_RELATIONAL_MORE ) );
	}

	friend VImage operator>=( VImage a, VImage b ) 
		throw( VError ) 
	{
		return( a.relational( b, VIPS_OPERATION_RELATIONAL_MOREEQ ) );
	}

	friend VImage operator>=( double a, VImage b ) 
		throw( VError )
	{
		return( b.relational_const( to_vector( a ), 
			VIPS_OPERATION_RELATIONAL_LESSEQ ) );
	}

	friend VImage operator>=( VImage a, double b ) 
		throw( VError )
	{ 
		return( a.relational_const( to_vector( b ), 
			VIPS_OPERATION_RELATIONAL_MOREEQ ) );
	}

	friend VImage operator>=( std::vector<double> a, VImage b ) 
		throw( VError )
	{
		return( b.relational_const( a, 
			VIPS_OPERATION_RELATIONAL_LESSEQ ) );
	}

	friend VImage operator>=( VImage a, std::vector<double> b ) 
		throw( VError )
	{ 
		return( a.relational_const( b, 
			VIPS_OPERATION_RELATIONAL_MOREEQ ) );
	}

	friend VImage operator==( VImage a, VImage b ) 
		throw( VError ) 
	{
		return( a.relational( b, VIPS_OPERATION_RELATIONAL_EQUAL ) );
	}

	friend VImage operator==( double a, VImage b ) 
		throw( VError )
	{
		return( b.relational_const( to_vector( a ), 
			VIPS_OPERATION_RELATIONAL_EQUAL ) );
	}

	friend VImage operator==( VImage a, double b ) 
		throw( VError )
	{ 
		return( a.relational_const( to_vector( b ), 
			VIPS_OPERATION_RELATIONAL_EQUAL ) );
	}

	friend VImage operator==( std::vector<double> a, VImage b ) 
		throw( VError )
	{
		return( b.relational_const( a, 
			VIPS_OPERATION_RELATIONAL_EQUAL ) );
	}

	friend VImage operator==( VImage a, std::vector<double> b ) 
		throw( VError )
	{ 
		return( a.relational_const( b, 
			VIPS_OPERATION_RELATIONAL_EQUAL ) );
	}

	friend VImage operator!=( VImage a, VImage b ) 
		throw( VError ) 
	{
		return( a.relational( b, VIPS_OPERATION_RELATIONAL_NOTEQ ) );
	}

	friend VImage operator!=( double a, VImage b ) 
		throw( VError )
	{
		return( b.relational_const( to_vector( a ), 
			VIPS_OPERATION_RELATIONAL_NOTEQ ) );
	}

	friend VImage operator!=( VImage a, double b ) 
		throw( VError )
	{ 
		return( a.relational_const( to_vector( b ), 
			VIPS_OPERATION_RELATIONAL_NOTEQ ) );
	}

	friend VImage operator!=( std::vector<double> a, VImage b ) 
		throw( VError )
	{
		return( b.relational_const( a, 
			VIPS_OPERATION_RELATIONAL_NOTEQ ) );
	}

	friend VImage operator!=( VImage a, std::vector<double> b ) 
		throw( VError )
	{ 
		return( a.relational_const( b, 
			VIPS_OPERATION_RELATIONAL_NOTEQ ) );
	}

	friend VImage operator&( VImage a, VImage b ) 
		throw( VError ) 
	{
		return( a.boolean( b, VIPS_OPERATION_BOOLEAN_AND ) );
	}

	friend VImage operator&( double a, VImage b ) 
		throw( VError )
	{
		return( b.boolean_const( to_vector( a ), 
			VIPS_OPERATION_BOOLEAN_AND ) );
	}

	friend VImage operator&( VImage a, double b ) 
		throw( VError )
	{ 
		return( a.boolean_const( to_vector( b ), 
			VIPS_OPERATION_BOOLEAN_AND ) );
	}

	friend VImage operator&( std::vector<double> a, VImage b ) 
		throw( VError )
	{
		return( b.boolean_const( a, VIPS_OPERATION_BOOLEAN_AND ) );
	}

	friend VImage operator&( VImage a, std::vector<double> b ) 
		throw( VError )
	{ 
		return( a.boolean_const( b, VIPS_OPERATION_BOOLEAN_AND ) );
	}

	friend VImage operator|( VImage a, VImage b ) 
		throw( VError ) 
	{
		return( a.boolean( b, VIPS_OPERATION_BOOLEAN_OR ) );
	}

	friend VImage operator|( double a, VImage b ) 
		throw( VError )
	{
		return( b.boolean_const( to_vector( a ), 
			VIPS_OPERATION_BOOLEAN_OR ) );
	}

	friend VImage operator|( VImage a, double b ) 
		throw( VError )
	{ 
		return( a.boolean_const( to_vector( b ), 
			VIPS_OPERATION_BOOLEAN_OR ) );
	}

	friend VImage operator|( std::vector<double> a, VImage b ) 
		throw( VError )
	{
		return( b.boolean_const( a, VIPS_OPERATION_BOOLEAN_OR ) );
	}

	friend VImage operator|( VImage a, std::vector<double> b ) 
		throw( VError )
	{ 
		return( a.boolean_const( b, VIPS_OPERATION_BOOLEAN_OR ) );
	}

	friend VImage operator^( VImage a, VImage b ) 
		throw( VError ) 
	{
		return( a.boolean( b, VIPS_OPERATION_BOOLEAN_EOR ) );
	}

	friend VImage operator^( double a, VImage b ) 
		throw( VError )
	{
		return( b.boolean_const( to_vector( a ), 
			VIPS_OPERATION_BOOLEAN_EOR ) );
	}

	friend VImage operator^( VImage a, double b ) 
		throw( VError )
	{ 
		return( a.boolean_const( to_vector( b ), 
			VIPS_OPERATION_BOOLEAN_EOR ) );
	}

	friend VImage operator^( std::vector<double> a, VImage b ) 
		throw( VError )
	{
		return( b.boolean_const( a, VIPS_OPERATION_BOOLEAN_EOR ) );
	}

	friend VImage operator^( VImage a, std::vector<double> b ) 
		throw( VError )
	{ 
		return( a.boolean_const( b, VIPS_OPERATION_BOOLEAN_EOR ) );
	}

	friend VImage operator<<( VImage a, VImage b ) 
		throw( VError ) 
	{
		return( a.boolean( b, VIPS_OPERATION_BOOLEAN_LSHIFT ) );
	}

	friend VImage operator<<( VImage a, double b ) 
		throw( VError )
	{ 
		return( a.boolean_const( to_vector( b ), 
			VIPS_OPERATION_BOOLEAN_LSHIFT ) ); 
	}

	friend VImage operator<<( VImage a, std::vector<double> b ) 
		throw( VError )
	{ 
		return( a.boolean_const( b, VIPS_OPERATION_BOOLEAN_LSHIFT ) ); 
	}

	friend VImage operator>>( VImage a, VImage b ) 
		throw( VError ) 
	{
		return( a.boolean( b, VIPS_OPERATION_BOOLEAN_RSHIFT ) );
	}

	friend VImage operator>>( VImage a, double b ) 
		throw( VError )
	{ 
		return( a.boolean_const( to_vector( b ), 
			VIPS_OPERATION_BOOLEAN_RSHIFT ) ); 
	}

	friend VImage operator>>( VImage a, std::vector<double> b ) 
		throw( VError )
	{ 
		return( a.boolean_const( b, VIPS_OPERATION_BOOLEAN_RSHIFT ) ); 
	}

	friend VImage operator-( VImage a ) 
		throw( VError )
	{ 
		return( a * -1 );
	}

};

VIPS_NAMESPACE_END

#endif /*VIPS_VIMAGE_H*/
