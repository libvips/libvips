/* an image plus a constant
 *
 * 11/11/11
 * 	- from arith_binary_const
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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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

#include "unaryconst.h"

G_DEFINE_ABSTRACT_TYPE( VipsUnaryConst, vips_unary_const, VIPS_TYPE_UNARY );

/* Cast a vector of double to a vector of TYPE, clipping to a range.
 */
#define CAST_CLIP( TYPE, N, X ) { \
	TYPE *tq = (TYPE *) q; \
	\
	for( i = 0; i < m; i++ ) { \
		double v = p[VIPS_MIN( n - 1, i )]; \
		\
		tq[i] = (TYPE) VIPS_CLIP( N, v, X ); \
	} \
}

/* Cast a vector of double to a vector of TYPE.
 */
#define CAST( TYPE ) { \
	TYPE *tq = (TYPE *) q; \
	\
	for( i = 0; i < m; i++ ) \
		tq[i] = (TYPE) p[VIPS_MIN( n - 1, i )]; \
}

/* Cast a vector of double to a complex vector of TYPE.
 */
#define CASTC( TYPE ) { \
	TYPE *tq = (TYPE *) q; \
	\
	for( i = 0; i < m; i++ ) { \
		tq[0] = (TYPE) p[VIPS_MIN( n - 1, i )]; \
		tq[1] = 0; \
		\
		tq += 2; \
	} \
}

/* Cast a n-band vector of double to a m-band vector in another format.
 */
static VipsPel *
make_pixel( VipsObject *obj, int m, VipsBandFmt fmt, int n, double *p )
{
	VipsPel *q;
	int i;

	if( !(q = VIPS_ARRAY( obj, 
		m * vips__image_sizeof_bandformat[fmt], VipsPel )) )
		return( NULL );

        switch( fmt ) {
        case VIPS_FORMAT_CHAR:		
		CAST_CLIP( signed char, SCHAR_MIN, SCHAR_MAX ); 
		break;

        case VIPS_FORMAT_UCHAR:  	
		CAST_CLIP( unsigned char, 0, UCHAR_MAX ); 
		break;

        case VIPS_FORMAT_SHORT:  	
		CAST_CLIP( signed short, SCHAR_MIN, SCHAR_MAX ); 
		break;

        case VIPS_FORMAT_USHORT: 	
		CAST_CLIP( unsigned short, 0, USHRT_MAX ); 
		break;

        case VIPS_FORMAT_INT:    	
		CAST_CLIP( signed int, INT_MIN, INT_MAX ); 
		break;

        case VIPS_FORMAT_UINT:   	
		CAST_CLIP( unsigned int, 0, UINT_MAX ); 
		break;

        case VIPS_FORMAT_FLOAT: 		
		CAST( float ); 
		break; 

        case VIPS_FORMAT_DOUBLE:		
		CAST( double ); 
		break;

        case VIPS_FORMAT_COMPLEX: 	
		CASTC( float ); 
		break; 

        case VIPS_FORMAT_DPCOMPLEX:	
		CASTC( double ); 
		break;

        default:
                g_assert( 0 );
        }

	return( q );
}

static int
vips_unary_const_build( VipsObject *object )
{
	VipsArithmetic *arithmetic = VIPS_ARITHMETIC( object );
	VipsUnary *unary = (VipsUnary *) object;
	VipsUnaryConst *uconst = (VipsUnaryConst *) object;

	/* If we have a three-element vector we need to bandup the image to
	 * match.
	 */
	uconst->n = 1;
	if( uconst->c )
		uconst->n = VIPS_MAX( uconst->n, uconst->c->n );
	if( unary->in )
		uconst->n = VIPS_MAX( uconst->n, unary->in->Bands );
	arithmetic->base_bands = uconst->n;

	if( unary->in && uconst->c ) {
		if( vips_check_vector( "VipsRelationalConst", 
			uconst->c->n, unary->in ) )
		return( -1 );
	}

	/* Some operations need the vector in the input type (eg.
	 * im_equal_vec() where the output type is always uchar and is useless
	 * for comparisons), some need it in the output type (eg.
	 * im_andimage_vec() where we want to get the double to an int so we
	 * can do bitwise-and without having to cast for each pixel), some
	 * need a fixed type (eg. im_powtra_vec(), where we want to keep it as
	 * double).
	 *
	 * Therefore pass in the desired vector type as a param.
	 */

	if( uconst->c ) 
		uconst->c_ready = make_pixel( (VipsObject *) uconst, 
			uconst->n, uconst->const_format,
			uconst->c->n, (double *) uconst->c->data );

	if( VIPS_OBJECT_CLASS( vips_unary_const_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_unary_const_class_init( VipsUnaryConstClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "unary_const";
	object_class->description = _( "unary operations with a constant" );
	object_class->build = vips_unary_const_build;

	VIPS_ARG_BOXED( class, "c", 200, 
		_( "c" ), 
		_( "Array of constants" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsUnaryConst, c ),
		VIPS_TYPE_ARRAY_DOUBLE );
}

static void
vips_unary_const_init( VipsUnaryConst *uconst )
{
}
