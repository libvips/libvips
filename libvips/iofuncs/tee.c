/* Make a "tee" in a pipeline: pixels pass through an arbitrary C function.
 *
 * 23/8/19
 *      - from vips-tee
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
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/

#include <vips/vips.h>

typedef struct _VipsTee {
	VipsOperation parent_instance;

	VipsArrayImage *in;
	VipsImage *out;
	char *command;
	int padding;
	double x_scale;
	double y_scale;
} VipsTee;

typedef VipsOperationClass VipsTeeClass;

#define VIPS_TYPE_TEE (vips_tee_get_type())
#define VIPS_TEE( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), VIPS_TYPE_TEE, VipsTee ))
#define VIPS_TEE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), VIPS_TYPE_TEE, VipsTeeClass))
#define VIPS_IS_TEE( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_TEE ))
#define VIPS_IS_TEE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_TEE ))
#define VIPS_TEE_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), VIPS_TYPE_TEE, VipsTeeClass ))

extern "C" {
	G_DEFINE_TYPE( VipsTee, vips_tee, VIPS_TYPE_OPERATION );
}

static int 
vips_tee_get_tile_border( VipsTee *vipstee )
{
	return( vipstee->padding );
}

#define INDEX( IMG, X, Y, Z ) \
	((*(IMG))( (guint) (X), (guint) (Y), (guint) (Z), 0 ))

// copy part of a vips region into a cimg
static void
vips_to_tee( VipsRegion *in, VipsRect *area, CImg<float> *img )
{
	VipsImage *im = in->im;

	for( int y = 0; y < area->height; y++ ) {
		float *p = (float *) 
			VIPS_REGION_ADDR( in, area->left, area->top + y );

		for( int x = 0; x < area->width; x++ ) {
			for( int z = 0; z < im->Bands; z++ ) 
				INDEX( img, x, y, z ) = p[z];

			p += im->Bands;
		}
	}
}

// write a CImg to a vips region
// fill out->valid, img has pixels in img_rect
static void
vips_from_tee( tee_image<float> *img, VipsRect *img_rect, VipsRegion *out )
{
	VipsImage *im = out->im;
	VipsRect *valid = &out->valid;

	g_assert( vips_rect_includesrect( img_rect, valid ) );

	int x_off = valid->left - img_rect->left;
	int y_off = valid->top - img_rect->top;

	for( int y = 0; y < valid->height; y++ ) {
		float *p = (float *) 
			   VIPS_REGION_ADDR( out, valid->left, valid->top + y );

		for( int x = 0; x < valid->width; x++ ) {
			for( int z = 0; z < im->Bands; z++ )
				p[z] = INDEX( img, x + x_off, y + y_off, z );

			p += im->Bands;
		}
	}
}

/* One of these for each thread.
 */
struct VipsTeeSequence { 
	VipsRegion **ir;
	tee *tee_instance;
};

static int
vips_tee_stop( void *vseq, void *a, void *b )
{
	VipsTeeSequence *seq = (VipsTeeSequence *) vseq;

        if( seq->ir ) {
		int i;

		for( i = 0; seq->ir[i]; i++ )
			g_object_unref( seq->ir[i] );
		VIPS_FREE( seq->ir );
	}

	delete seq->tee_instance;

	VIPS_FREE( seq );

	return( 0 );
}

static void *
vips_tee_start( VipsImage *out, void *a, void *b )
{
	VipsImage **in = (VipsImage **) a;

	VipsTeeSequence *seq;
	int i, n;

	if( !(seq = VIPS_NEW( NULL, VipsTeeSequence )) )
		return( NULL ); 

	/* Make a region for each input image. 
	 */
	for( n = 0; in[n]; n++ )
		;

	if( !(seq->ir = VIPS_ARRAY( NULL, n + 1, VipsRegion * )) ) {
		vips_tee_stop( seq, NULL, NULL );
		return( NULL );
	}

	for( i = 0; i < n; i++ )
		if( !(seq->ir[i] = vips_region_new( in[i] )) ) {
			vips_tee_stop( seq, NULL, NULL );
			return( NULL );
		}
	seq->ir[n] = NULL;

	/* Make a tee for this thread.
	 */
	seq->tee_instance = new tee; 

	return( (void *) seq );
}

static int
vips_tee_gen( VipsRegion *oreg, void *vseq, void *a, void *b, gboolean *stop )
{
	VipsTeeSequence *seq = (VipsTeeSequence *) vseq;
	VipsTee *vipstee = (VipsTee *) b;
	int ninput = VIPS_AREA( vipstee->in )->n;
	const int tile_border = vips_tee_get_tile_border( vipstee );
	const VipsRect *r = &oreg->valid;

	VipsRect need;
	VipsRect image;

	need = *r;
	vips_rect_marginadjust( &need, tile_border );
	image.left = 0;
	image.top = 0;
	image.width = seq->ir[0]->im->Xsize;
	image.height = seq->ir[0]->im->Ysize;
	vips_rect_intersectrect( &need, &image, &need );

	for( int i = 0; seq->ir[i]; i++ ) 
		if( vips_region_prepare( seq->ir[i], &need ) ) 
			return( -1 );

	tee_list<float> images;
	tee_list<char> images_names;

	try {
		images.assign( (guint) ninput );

		for( int i = 0; seq->ir[i]; i++ ) {
			tee_image<float> &img = images._data[i];
			img.assign( need.width, need.height, 
				1, seq->ir[i]->im->Bands );
			vips_to_tee( seq->ir[0], &need, &img );
		}

		seq->tee_instance->run( vipstee->command, 
			images, images_names );
		vips_from_tee( &images._data[0], &need, oreg );
	}
	catch( tee_exception e ) { 
		images.assign( (guint) 0 );

		vips_error( "VipsTee", "%s", e.what() );

		return( -1 );
	}
	images.assign( (guint) 0 );

	return( 0 );
}

static int 
vips_tee_build( VipsObject *object )
{
	VipsObjectClass *klass = VIPS_OBJECT_GET_CLASS( object );
	VipsTee *vipstee = (VipsTee *) object;

	VipsImage **in;
	VipsImage **t;
	int ninput;

	if( VIPS_OBJECT_CLASS( vips_tee_parent_class )->build( object ) )
		return( -1 );

	in = vips_array_image_get( vipstee->in, &ninput );

	for( int i = 0; i < ninput; i++ ) 
		if( vips_image_pio_input( in[i] ) || 
			vips_check_coding_known( klass->nickname, in[i] ) )  
			return( -1 );

	/* Cast all inputs up to float. 
	 */
	t = (VipsImage **) vips_object_local_array( object, ninput );
	for( int i = 0; i < ninput; i++ )
		if( vips_cast( in[i], &t[i], VIPS_FORMAT_FLOAT, NULL ) )
			return( -1 );
	in = t;

	g_object_set( vipstee, "out", vips_image_new(), NULL ); 

	if( vips_image_pipeline_array( vipstee->out, 
		VIPS_DEMAND_STYLE_SMALLTILE, in ) )
		return( -1 );

	if( vips_image_generate( vipstee->out,
		vips_tee_start, vips_tee_gen, vips_tee_stop, 
		in, vipstee ) )
		return( -1 );

	return( 0 );
}

static void
vips_tee_class_init( VipsTeeClass *klass )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( klass );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( klass );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( klass );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "tee";
	vobject_class->description = _( "Make a 'tee' in a libvips pipeline" );
	vobject_class->build = vips_tee_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_BOXED( klass, "in", 0, 
		_( "Input" ), 
		_( "Array of input images" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsTee, in ),
		VIPS_TYPE_ARRAY_IMAGE );

	VIPS_ARG_IMAGE( klass, "out", 1,
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsTee, out ) );

	VIPS_ARG_INT( klass, "padding", 3,
		_( "padding" ), 
		_( "Tile overlap" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsTee, padding ),
		0, INT_MAX, 0);

}

static void
vips_tee_init( VipsTee *vipstee )
{
}

/**
 * vips_tee:
 * @in: (array length=n) (transfer none): array of input images
 * @out: output image
 * @n: number of input images
 * @padding: overlap tiles by this much
 * @x_scale: 
 * @y_scale: 
 * @command: command to execute
 *
 * Returns: 0 on success, -1 on failure. 
 */
int
vips_tee( VipsImage **in, VipsImage **out, int n, 
	int padding, double x_scale, double y_scale, const char *command, ... )
{
	VipsArrayImage *array; 
	va_list ap;
	int result;

	array = vips_array_image_new( in, n ); 
	va_start( ap, command );
	result = vips_call_split( "tee", ap, array, out, 
		padding, x_scale, y_scale, command );
	va_end( ap );
	vips_area_unref( VIPS_AREA( array ) );

	return( result );
}
