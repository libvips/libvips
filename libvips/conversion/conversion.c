/* base class for all conversion operations
 *
 * properties:
 * 	- unary, binary or binary with one arg a constant
 * 	- cast binary args to match
 * 	- not point-to-point
 * 	- format, bands etc. can all change
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
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "conversion.h"

G_DEFINE_ABSTRACT_TYPE( VipsConversion, vips_conversion, VIPS_TYPE_OPERATION );

static int
vips_conversion_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );

#ifdef DEBUG
	printf( "vips_conversion_build: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	g_object_set( conversion, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_conversion_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_conversion_class_init( VipsConversionClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "conversion";
	vobject_class->description = _( "conversion operations" );
	vobject_class->build = vips_conversion_build;

	VIPS_ARG_IMAGE( class, "out", 1, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsConversion, out ) );
}

static void
vips_conversion_init( VipsConversion *conversion )
{
}

/* Called from iofuncs to init all operations in this dir. Use a plugin system
 * instead?
 */
void
vips_conversion_operation_init( void )
{
	extern GType vips_copy_get_type( void ); 
	extern GType vips_tile_cache_get_type( void ); 
	extern GType vips_line_cache_get_type( void ); 
	extern GType vips_sequential_get_type( void ); 
	extern GType vips_cache_get_type( void ); 
	extern GType vips_embed_get_type( void ); 
	extern GType vips_flip_get_type( void ); 
	extern GType vips_insert_get_type( void ); 
	extern GType vips_join_get_type( void ); 
	extern GType vips_extract_area_get_type( void ); 
	extern GType vips_extract_band_get_type( void ); 
	extern GType vips_replicate_get_type( void ); 
	extern GType vips_cast_get_type( void ); 
	extern GType vips_bandjoin_get_type( void ); 
	extern GType vips_black_get_type( void ); 
	extern GType vips_rot_get_type( void ); 
	extern GType vips_ifthenelse_get_type( void ); 
	extern GType vips_recomb_get_type( void ); 
	extern GType vips_bandmean_get_type( void ); 
	extern GType vips_flatten_get_type( void ); 
	extern GType vips_bandbool_get_type( void ); 

	vips_copy_get_type();
	vips_tile_cache_get_type(); 
	vips_line_cache_get_type(); 
	vips_sequential_get_type(); 
	vips_cache_get_type(); 
	vips_embed_get_type();
	vips_flip_get_type();
	vips_insert_get_type();
	vips_join_get_type();
	vips_extract_area_get_type();
	vips_extract_band_get_type();
	vips_replicate_get_type();
	vips_cast_get_type();
	vips_bandjoin_get_type();
	vips_black_get_type();
	vips_rot_get_type();
	vips_ifthenelse_get_type();
	vips_recomb_get_type(); 
	vips_bandmean_get_type(); 
	vips_flatten_get_type(); 
	vips_bandbool_get_type(); 
}

/* The common part of most binary conversion
 * operators. We:
 *
 * - check in and out
 * - cast in1 and in2 up to a common format
 * - equalise bands 
 * - make an input array
 * - return the matched images in vec[0] and vec[1]
 *
 *
 * A left-over, remove soon.
 */
IMAGE **
im__insert_base( const char *domain, 
	IMAGE *in1, IMAGE *in2, IMAGE *out ) 
{
	IMAGE *t[4];
	IMAGE **vec;

	if( im_piocheck( in1, out ) || 
		im_pincheck( in2 ) ||
		im_check_bands_1orn( domain, in1, in2 ) ||
		im_check_coding_known( domain, in1 ) ||
		im_check_coding_same( domain, in1, in2 ) )
		return( NULL );

	/* Cast our input images up to a common format and bands.
	 */
	if( im_open_local_array( out, t, 4, domain, "p" ) ||
		im__formatalike( in1, in2, t[0], t[1] ) ||
		im__bandalike( domain, t[0], t[1], t[2], t[3] ) ||
		!(vec = im_allocate_input_array( out, t[2], t[3], NULL )) )
		return( NULL );

	/* Generate the output.
	 */
	if( im_cp_descv( out, vec[0], vec[1], NULL ) ||
		im_demand_hint_array( out, IM_SMALLTILE, vec ) )
		return( NULL );

	return( vec );
}

/**
 * im_insertset:
 * @main: big image
 * @sub: small image
 * @out: output image
 * @n: number of positions
 * @x: left positions of @sub
 * @y: top positions of @sub
 *
 * Insert @sub repeatedly into @main at the positions listed in the arrays @x,
 * @y of length @n. @out is the same
 * size as @main. @sub is clipped against the edges of @main. 
 *
 * This operation is fast for large @n, but will use a memory buffer the size
 * of @out. It's useful for things like making scatter plots.
 *
 * If the number of bands differs, one of the images 
 * must have one band. In this case, an n-band image is formed from the 
 * one-band image by joining n copies of the one-band image together, and then
 * the two n-band images are operated upon.
 *
 * The two input images are cast up to the smallest common type (see table 
 * Smallest common format in 
 * <link linkend="VIPS-arithmetic">arithmetic</link>).
 *
 * See also: im_insert(), im_lrjoin().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_insertset( IMAGE *main, IMAGE *sub, IMAGE *out, int n, int *x, int *y )
{
	IMAGE **vec;
	IMAGE *t;
	int i;

	if( !(vec = im__insert_base( "im_insert", main, sub, out )) )
		return( -1 );

	/* Copy to a memory image, zap that, then copy to out.
	 */
	if( !(t = im_open_local( out, "im_insertset", "t" )) ||
		im_copy( vec[0], t ) )
		return( -1 );

	for( i = 0; i < n; i++ ) 
		if( im_insertplace( t, vec[1], x[i], y[i] ) )
			return( -1 );

	if( im_copy( t, out ) )
		return( -1 );

	return( 0 );
}
