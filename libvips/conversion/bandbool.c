/* bandbool.c --- bool op across image bands
 *
 * 7/12/12
 * 	- from boolean.c
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>

#include <vips/vips.h>

#include "bandary.h"

typedef struct _VipsBandbool {
	VipsBandary parent_instance;

	VipsImage *in;

	VipsOperationBoolean operation;

} VipsBandbool;

typedef VipsBandaryClass VipsBandboolClass;

G_DEFINE_TYPE( VipsBandbool, vips_bandbool, VIPS_TYPE_BANDARY );

static int
vips_bandbool_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsBandary *bandary = (VipsBandary *) object;
	VipsBandbool *bandbool = (VipsBandbool *) object;

	/* << and >> don't work over bands.
	 */
	if( bandbool->operation == VIPS_OPERATION_BOOLEAN_LSHIFT ||
		bandbool->operation == VIPS_OPERATION_BOOLEAN_RSHIFT ) {
		vips_error( class->nickname, 
			_( "operator %s not supported across image bands" ), 
			vips_enum_nick( VIPS_TYPE_OPERATION_BOOLEAN, 
				bandbool->operation ) );
		return( -1 );
	}

	if( bandbool->in ) {
		if( vips_check_noncomplex( class->nickname, bandbool->in ) )
			return( -1 );

		bandary->n = 1;
		bandary->in = &bandbool->in;

		if( bandbool->in->Bands == 1 ) 
			return( vips_bandary_copy( bandary ) );
	}

	bandary->out_bands = 1;

	if( VIPS_OBJECT_CLASS( vips_bandbool_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

#define SWITCH( I, F, OP ) \
	switch( vips_image_get_format( im ) ) { \
	case VIPS_FORMAT_UCHAR:		I( unsigned char, OP ); break; \
	case VIPS_FORMAT_CHAR:		I( signed char, OP ); break; \
	case VIPS_FORMAT_USHORT: 	I( unsigned short, OP ); break; \
	case VIPS_FORMAT_SHORT: 	I( signed short, OP ); break; \
	case VIPS_FORMAT_UINT: 		I( unsigned int, OP ); break; \
	case VIPS_FORMAT_INT: 		I( signed int, OP ); break; \
	case VIPS_FORMAT_FLOAT: 	F( float, OP ); break; \
	case VIPS_FORMAT_DOUBLE: 	F( double, OP ); break;\
 	\
	default: \
		g_assert_not_reached(); \
	} 

#define LOOPB( TYPE, OP ) { \
	TYPE *p = (TYPE *) in[0]; \
	TYPE *q = (TYPE *) out; \
 	\
	for( x = 0; x < width; x++ ) { \
		TYPE acc; \
		\
		acc = p[0]; \
		for( b = 1; b < bands; b++ ) \
			acc = acc OP p[b]; \
		\
		q[x] = acc; \
		p += bands; \
	} \
}

#define FLOOPB( TYPE, OP ) { \
	TYPE *p = (TYPE *) in[0]; \
	int *q = (int *) out; \
 	\
	for( x = 0; x < width; x++ ) { \
		int acc; \
		\
		acc = (int) p[0]; \
		for( b = 1; b < bands; b++ ) \
			acc = acc OP ((int) p[b]); \
		\
		q[x] = acc; \
		p += bands; \
	} \
}

static void
vips_bandbool_buffer( VipsBandary *bandary, 
	VipsPel *out, VipsPel **in, int width )
{
	VipsBandbool *bandbool = (VipsBandbool *) bandary;
	VipsImage *im = bandary->ready[0];
	int bands = im->Bands;

	int x, b;

	switch( bandbool->operation ) {
	case VIPS_OPERATION_BOOLEAN_AND: 	
		SWITCH( LOOPB, FLOOPB, & ); 
		break;

	case VIPS_OPERATION_BOOLEAN_OR: 	
		SWITCH( LOOPB, FLOOPB, | ); 
		break;

	case VIPS_OPERATION_BOOLEAN_EOR: 	
		SWITCH( LOOPB, FLOOPB, ^ ); 
		break;

	default:
		g_assert_not_reached();
	}
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define C VIPS_FORMAT_CHAR
#define US VIPS_FORMAT_USHORT
#define S VIPS_FORMAT_SHORT
#define UI VIPS_FORMAT_UINT
#define I VIPS_FORMAT_INT
#define F VIPS_FORMAT_FLOAT
#define X VIPS_FORMAT_COMPLEX
#define D VIPS_FORMAT_DOUBLE
#define DX VIPS_FORMAT_DPCOMPLEX

/* Format conversions for boolean. 
 */
static const VipsBandFormat vips_bandbool_format_table[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, C,  US, S,  UI, I,  I,  I,  I,  I,
};

static void
vips_bandbool_class_init( VipsBandboolClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsBandaryClass *bandary_class = VIPS_BANDARY_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "bandbool";
	object_class->description = _( "boolean operation across image bands" );
	object_class->build = vips_bandbool_build;

	bandary_class->process_line = vips_bandbool_buffer;
	bandary_class->format_table = vips_bandbool_format_table;

	VIPS_ARG_IMAGE( class, "in", 0, 
		_( "Input" ), 
		_( "Input image argument" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsBandbool, in ) );

	VIPS_ARG_ENUM( class, "boolean", 200, 
		_( "Operation" ), 
		_( "boolean to perform" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsBandbool, operation ),
		VIPS_TYPE_OPERATION_BOOLEAN, 
			VIPS_OPERATION_BOOLEAN_AND ); 
}

static void
vips_bandbool_init( VipsBandbool *bandbool )
{
	bandbool->operation = VIPS_OPERATION_BOOLEAN_AND;
}

static int
vips_bandboolv( VipsImage *in, VipsImage **out, 
	VipsOperationBoolean operation, va_list ap )
{
	return( vips_call_split( "bandbool", ap, in, out, operation ) );
}

/**
 * vips_bandbool:
 * @in: left-hand input #VipsImage
 * @out: output #VipsImage
 * @boolean: boolean operation to perform
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform various boolean operations across the bands of an image. For
 * example, a three-band uchar image operated on with
 * #VIPS_OPERATION_BOOLEAN_AND will produce a one-band uchar image where each
 * pixel is the bitwise and of the band elements of the corresponding pixel in
 * the input image. 
 *
 * The output image is the same format as the input image for integer
 * types. Float types are cast to int before processing. Complex types are not
 * supported.
 *
 * The output image always has one band. 
 *
 * This operation is useful in conjuction with vips_relational(). You can use
 * it to see if all image bands match exactly. 
 *
 * See also: vips_boolean_const().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_bandbool( VipsImage *in, VipsImage **out, 
	VipsOperationBoolean boolean, ... )
{
	va_list ap;
	int result;

	va_start( ap, boolean );
	result = vips_bandboolv( in, out, boolean, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_bandand:
 * @in: left-hand input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_BOOLEAN_AND on an image. See
 * vips_bandbool().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_bandand( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_bandboolv( in, out, VIPS_OPERATION_BOOLEAN_AND, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_bandor:
 * @in: left-hand input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_BOOLEAN_OR on an image. See
 * vips_bandbool().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_bandor( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_bandboolv( in, out, VIPS_OPERATION_BOOLEAN_OR, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_bandeor:
 * @in: left-hand input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_BOOLEAN_EOR on an image. See
 * vips_bandbool().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_bandeor( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_bandboolv( in, out, VIPS_OPERATION_BOOLEAN_EOR, ap );
	va_end( ap );

	return( result );
}

