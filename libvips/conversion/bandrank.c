/* Sort a set of images, pixelwise, and pick out the index at each point.
 *
 * 19/8/03
 *	- from im_maxvalue(), via im_gbandrank()
 * 10/11/10
 * 	- gtkdoc
 * 	- cleanups
 * 	- any mix of formats and bands
 * 23/10/13
 * 	- redo as a class, from bandrank.c
 */

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

/*
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "bandary.h"

typedef struct _VipsBandrank {
	VipsBandary parent_instance;

	/* The input images.
	 */
	VipsArrayImage *in;
	int index;		/* Pick out this one */
} VipsBandrank;

typedef VipsBandaryClass VipsBandrankClass;

G_DEFINE_TYPE( VipsBandrank, vips_bandrank, VIPS_TYPE_BANDARY );

/* Special-case max and min (rather common).
 */
#define FIND_MAX( TYPE ) { \
	for( x = 0; x < sz; x++ ) { \
		TYPE top = ((TYPE *) p[0])[x]; \
 		\
		for( i = 1; i < bandary->n; i++ ) { \
			TYPE v = ((TYPE *) p[i])[x]; \
 			\
			if( v > top ) \
				top = v; \
		} \
 		\
		((TYPE *) q)[x] = top; \
	} \
}

#define FIND_MIN( TYPE ) { \
	for( x = 0; x < sz; x++ ) { \
		TYPE bot = ((TYPE *) p[0])[x]; \
 		\
		for( i = 1; i < bandary->n; i++ ) { \
			TYPE v = ((TYPE *) p[i])[x]; \
 			\
			if( v < bot ) \
				bot = v; \
		} \
 		\
		((TYPE *) q)[x] = bot; \
	} \
}

#define FIND_RANK( TYPE ) { \
	TYPE *sort = (TYPE *) sort_buffer; \
	\
	for( x = 0; x < sz; x++ ) { \
		for( i = 0; i < bandary->n; i++ ) { \
			TYPE v = ((TYPE *) p[i])[x]; \
			\
			/* Search for element >v. 
			 */\
			for( j = 0; j < i; j++ ) \
				if( sort[j] > v ) \
					break; \
			\
			/* Move remaining elements down. 
			 */ \
			for( k = i; k > j; k-- ) \
				sort[k] = sort[k - 1]; \
			\
			/* Insert this element. 
			 */ \
			sort[j] = v; \
		} \
		\
		((TYPE *) q)[x] = sort[bandrank->index]; \
	} \
} 

#define SWITCH( OPERATION ) \
	switch( in[0]->BandFmt ) { \
	case VIPS_FORMAT_UCHAR:		OPERATION( unsigned char ); break; \
	case VIPS_FORMAT_CHAR:   	OPERATION( signed char ); break; \
	case VIPS_FORMAT_USHORT: 	OPERATION( unsigned short ); break; \
	case VIPS_FORMAT_SHORT:  	OPERATION( signed short ); break; \
	case VIPS_FORMAT_UINT:   	OPERATION( unsigned int ); break; \
	case VIPS_FORMAT_INT:    	OPERATION( signed int ); break; \
	case VIPS_FORMAT_FLOAT:  	OPERATION( float ); break; \
	case VIPS_FORMAT_DOUBLE: 	OPERATION( double ); break; \
 	\
	default: \
		g_assert_not_reached(); \
	} 

/* Sort input band elements in the stack. Needs to be big enough for
 * sizeof(band-element) * number-of-images.
 */
#define SORT_BUFFER (1024)

static void
vips_bandrank_buffer( VipsBandary *bandary, VipsPel *q, VipsPel **p, int width )
{
	VipsBandrank *bandrank = (VipsBandrank *) bandary;
	VipsImage **in = bandary->ready;
	int sz = width * in[0]->Bands; 

	int i, j, k;
	int x;
	VipsPel sort_buffer[SORT_BUFFER]; 

	/* Special-case max and min.
	 */
	if( bandrank->index == 0 ) 
		SWITCH( FIND_MIN )
	else if( bandrank->index == bandary->n - 1 )
		SWITCH( FIND_MAX )
	else
		SWITCH( FIND_RANK )
}

static int
vips_bandrank_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsBandary *bandary = (VipsBandary *) object;
	VipsBandrank *bandrank = (VipsBandrank *) object;

	if( bandrank->in ) {
		int n;
		VipsImage **in = vips_array_image_get( bandrank->in, &n );
		VipsImage **band = (VipsImage **) 
			vips_object_local_array( object, n );

		int i;

		for( i = 0; i < n; i++ ) 
			if( vips_check_noncomplex( class->nickname, in[i] ) )
				return( -1 );

		if( n == 1 ) {
			bandary->in = in;
			bandary->n = 1;

			return( vips_bandary_copy( bandary ) );
		}

		/* We need to keep one band element for every input image 
		 * on the stack.
		 */
		if( sizeof( double ) * n > SORT_BUFFER ) {
			vips_error( class->nickname, 
				"%s", _( "too many input images" ) );
			return( -1 );
		}

		if( vips__bandalike_vec( class->nickname, in, band, n, 0 ) )
			return( -1 ); 

		bandary->in = band;
		bandary->n = n;
		bandary->out_bands = band[0]->Bands;

		if( bandrank->index == -1 )
			bandrank->index = bandary->n / 2; 
	}

	if( VIPS_OBJECT_CLASS( vips_bandrank_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_bandrank_class_init( VipsBandrankClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsBandaryClass *bandary_class = VIPS_BANDARY_CLASS( class );

	VIPS_DEBUG_MSG( "vips_bandrank_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "bandrank";
	vobject_class->description = _( "band-wise rank of a set of images" );
	vobject_class->build = vips_bandrank_build;

	bandary_class->process_line = vips_bandrank_buffer;

	VIPS_ARG_BOXED( class, "in", 0, 
		_( "Input" ), 
		_( "Array of input images" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsBandrank, in ),
		VIPS_TYPE_ARRAY_IMAGE );

	VIPS_ARG_INT( class, "index", 0, 
		_( "Index" ), 
		_( "Select this band element from sorted list" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsBandrank, index ),
		-1, 1000000, -1 ); 

}

static void
vips_bandrank_init( VipsBandrank *bandrank )
{
	/* -1 means median.
	 */
	bandrank->index = -1;
}

static int
vips_bandrankv( VipsImage **in, VipsImage **out, int n, va_list ap )
{
	VipsArrayImage *array; 
	int result;

	array = vips_array_image_new( in, n ); 
	result = vips_call_split( "bandrank", ap, array, out );
	vips_area_unref( VIPS_AREA( array ) );

	return( result );
}

/**
 * vips_bandrank:
 * @in: array of input images
 * @out: output image
 * @n: number of input images
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @index: pick this index from list of sorted values
 *
 * Sorts the images @in band-element-wise, then outputs an 
 * image in which each band element is selected from the sorted list by the 
 * @index parameter. For example, if @index
 * is zero, then each output band element will be the minimum of all the 
 * corresponding input band elements. 
 *
 * By default, @index is -1, meaning pick the median value. 
 *
 * It works for any uncoded, non-complex image type. Images are cast up to the
 * smallest common-format.
 *
 * Any image can have either 1 band or n bands, where n is the same for all
 * the non-1-band images. Single band images are then effectively copied to 
 * make n-band images.
 *
 * Smaller input images are expanded by adding black pixels.
 *
 * See also: vips_rank().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_bandrank( VipsImage **in, VipsImage **out, int n, ... )
{
	va_list ap;
	int result;

	va_start( ap, n );
	result = vips_bandrankv( in, out, n, ap );
	va_end( ap );

	return( result );
}

