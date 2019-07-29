/* map though an array of images
 *
 * 28/7/19
 * 	- from mapimage.c
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

typedef struct _VipsMapimage {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;
	VipsArrayImage *lut;

} VipsMapimage;

typedef VipsOperationClass VipsMapimageClass;

G_DEFINE_TYPE( VipsMapimage, vips_mapimage, VIPS_TYPE_OPERATION );

/* Our sequence value: the region this sequence is using, and local stats.
 */
typedef struct {
	VipsRegion *ir;		/* Input region */
} VipsMapimageSequence;

/* Our start function.
 */
static void *
vips_mapimage_start( VipsImage *out, void *a, void *b )
{
	VipsImage *in = (VipsImage *) a;
	VipsMapimageSequence *seq;

	if( !(seq = VIPS_NEW( out, VipsMapimageSequence )) )
		 return( NULL );

	/* Init!
	 */

	if( !(seq->ir = vips_region_new( in )) ) 
		return( NULL );

	return( seq );
}

/* Do a map.
 */
static int 
vips_mapimage_gen( VipsRegion *or, void *vseq, void *a, void *b, 
	gboolean *stop )
{
	VipsMapimageSequence *seq = (VipsMapimageSequence *) vseq;
	VipsImage *in = (VipsImage *) a;
	VipsMapimage *mapimage = (VipsMapimage *) b;
	VipsRegion *ir = seq->ir;
	VipsRect *r = &or->valid;

	return( 0 );
}

/* Destroy a sequence value.
 */
static int
vips_mapimage_stop( void *vseq, void *a, void *b )
{
	VipsMapimageSequence *seq = (VipsMapimageSequence *) vseq;
	VipsMapimage *mapimage = (VipsMapimage *) b;

	VIPS_UNREF( seq->ir );

	return( 0 );
}

static int
vips_mapimage_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsMapimage *mapimage = (VipsMapimage *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 2 );

	VipsImage *in;
	VipsImage **lut;
	int n;
	VipsImage **decode;
	VipsImage **format;
	VipsImage **band;
	VipsImage **size;
	int i;

	g_object_set( object, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_mapimage_parent_class )->build( object ) )
		return( -1 );

	in = mapimage->in;
	lut = vips_area_get_data( &mapimage->lut.area, NULL, &n, NULL, NULL );
	if( n > 256 ) {
		vips_error( class->nickname, _( "LUT too large" ) );
		return( -1 );
	}
	if( in->Bands > 1 ) {
		vips_error( class->nickname, _( "index image not 1-band" ) );
		return( -1 );
	}

	/* Cast @in to u8 to make the index image.
	 */
	if( vips_cast( in, &t[0], VIPS_FORMAT_UCHAR, NULL ) )
		return( -1 );
	in = t[0];

	decode = (VipsImage **) vips_object_local_array( object, n );
	format = (VipsImage **) vips_object_local_array( object, n );
	band = (VipsImage **) vips_object_local_array( object, n );
	size = (VipsImage **) vips_object_local_array( object, n );

	/* Decode RAD/LABQ etc.
	 */
	for( i = 0; i < arithmetic->n; i++ )
		if( vips_image_decode( lut[i], &decode[i] ) )
			return( -1 );
	lut = decode;

	/* LUT images must match in format, size and bands.
	 */
	if( vips__formatalike_vec( lut, format, n ) ||
		vips__bandalike_vec( class->nickname, format, band, n, max_bands ) ||
		vips__sizealike_vec( band, size, n ) ) 
		return( -1 );





	if( vips_check_uncoded( class->nickname, in ) ||
		vips_check_bands_1orn( class->nickname, in, lut ) ||
		vips_image_pio_input( in ) )
		return( -1 );

	if( vips_image_pipelinev( mapimage->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, in, lut, NULL ) )
		return( -1 );
	mapimage->out->BandFmt = lut->BandFmt;

	/* Output has same number of bands as LUT, unless LUT has 1 band, in
	 * which case output has same number of bands as input.
	 */
	if( lut->Bands != 1 )
		mapimage->out->Bands = lut->Bands;

	/* The Type comes from the image with many bands. A B_W index image,
	 * for example, needs to become an RGB image when it goes through a
	 * three-band LUT.
	 */
	if( lut->Bands != 1 )
		mapimage->out->Type = lut->Type;

	g_signal_connect( in, "preeval", 
		G_CALLBACK( vips_mapimage_preeval ), mapimage );
	g_signal_connect( in, "posteval", 
		G_CALLBACK( vips_mapimage_posteval ), mapimage );

	/* Make luts. We unpack the LUT image into a 2D C array to speed
	 * processing.
	 */
	if( !(t[1] = vips_image_copy_memory( lut )) )
		return( -1 );
	lut = t[1];
	mapimage->fmt = lut->BandFmt;
	mapimage->es = VIPS_IMAGE_SIZEOF_ELEMENT( lut );
	mapimage->sz = lut->Xsize * lut->Ysize;
	mapimage->clp = mapimage->sz - 1;

	/* If @bands is >= 0, we need to expand the lut to the number of bands
	 * in the input image. 
	 */
	if( mapimage->band >= 0 && 
		lut->Bands == 1 )
		mapimage->nb = in->Bands;
	else
		mapimage->nb = lut->Bands;

	/* Attach tables.
	 */
	if( !(mapimage->table = VIPS_ARRAY( mapimage, mapimage->nb, VipsPel * )) ) 
                return( -1 );
	for( i = 0; i < mapimage->nb; i++ )
		if( !(mapimage->table[i] = VIPS_ARRAY( mapimage, 
			mapimage->sz * mapimage->es, VipsPel )) )
			return( -1 );

	if( vips_image_generate( mapimage->out,
		vips_mapimage_start, vips_mapimage_gen, vips_mapimage_stop, 
		in, mapimage ) )
		return( -1 );

	return( 0 );
}

static void
vips_mapimage_class_init( VipsMapimageClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "mapimage";
	object_class->description = _( "map an image though a lut" );
	object_class->build = vips_mapimage_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMapimage, in ) );

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsMapimage, out ) );

	VIPS_ARG_BOXED( class, "lut", 3, 
		_( "LUT" ), 
		_( "Look-up table of images" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMapimage, lut ),
		VIPS_TYPE_ARRAY_IMAGE );

}

static void
vips_mapimage_init( VipsMapimage *mapimage )
{
}

static int
vips_mapimagev( VipsImage *in, VipsImage **out, VipsImage **lut, int n, 
	va_list ap )
{
	VipsArrayImage *array; 
	int result;

	array = vips_array_image_new( lut, n ); 
	result = vips_call_split( "mapimage", ap, in, out, array );
	vips_area_unref( VIPS_AREA( array ) );

	return( result );
}

/**
 * vips_mapimage: (method)
 * @in: input image
 * @out: (out): output image
 * @lut: (array length=n): LUT of input images
 * @n: number of input images
 * @...: %NULL-terminated list of optional named arguments
 *
 * Map index image @in through a LUT of images. 
 *
 * Each value in @in is used to select an image from @lut, and the
 * corresponding pixel is copied to the output.
 *
 * @in must have one band. @lut can have up to 256 elements. Values in @in
 * greater than or equal to @n use the final image in @lut. The images in @lut
 * must have either one band or the same number of bands. 
 *
 * See also: vips_maplut().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_mapimage( VipsImage *in, VipsImage **out, VipsImage **lut, int n, ... )
{
	va_list ap;
	int result;

	va_start( ap, n );
	result = vips_mapimagev( in, out, lut, n, ap );
	va_end( ap );

	return( result );
}

