/* im_gaussnoise
 *
 * Copyright 1990, N. Dessipris.
 *
 * File written on 2/12/1986
 * Author : N. Dessipris
 * Updated : 6/6/1991
 * 21/7/93 JC
 *	- im_outcheck() call added
 * 1/2/95 JC
 *	- declaration for drand48() added
 *	- partialised, adapting im_gaussnoise()
 * 23/10/98 JC
 *	- drand48() chaged to random() for portability
 * 21/10/02 JC
 *	- tries rand() if random() is not available
 *	- uses RAND_MAX, d'oh
 * 29/1/10
 * 	- cleanups
 * 	- gtkdoc
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

#include <vips/vips.h>

#include "conversion.h"

typedef struct _VipsGaussnoise {
	VipsConversion parent_instance;

	int width;
	int height;
	double mean;
	double sigma;

} VipsGaussnoise;

typedef VipsConversionClass VipsGaussnoiseClass;

G_DEFINE_TYPE( VipsGaussnoise, vips_gaussnoise, VIPS_TYPE_CONVERSION );

static int
vips_gaussnoise_gen( VipsRegion *or, void *seq, void *a, void *b,
	gboolean *stop )
{
	VipsGaussnoise *gaussnoise = (VipsGaussnoise *) a;
	int sz = VIPS_REGION_N_ELEMENTS( or );

	int x, y, i;

	for( y = 0; y < or->valid.height; y++ ) {
		float *q = (float *) VIPS_REGION_ADDR( or, 
			or->valid.left, y + or->valid.top );

		for( x = 0; x < sz; x++ ) {
			double sum = 0.0;

			for( i = 0; i < 12; i++ ) 
#ifdef HAVE_RANDOM
				sum += (double) random() / RAND_MAX;
#else /*HAVE_RANDOM*/
#ifdef HAVE_RAND
				sum += (double) rand() / RAND_MAX;
#else /*HAVE_RAND*/
#error "no random number generator found"
#endif /*HAVE_RAND*/
#endif /*HAVE_RAND*/

			q[x] = (sum - 6.0) * gin->sigma + gin->mean;
		}
	}

	return( 0 );
}

static int
vips_gaussnoise_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsGaussnoise *gaussnoise = (VipsGaussnoise *) object;

	if( VIPS_OBJECT_CLASS( vips_gaussnoise_parent_class )->build( object ) )
		return( -1 );

	vips_image_init_fields( conversion->out,
		gaussnoise->width, gaussnoise->height, gaussnoise->bands, 
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE,
                gaussnoise->bands == 1 ? 
			VIPS_INTERPRETATION_B_W : VIPS_INTERPRETATION_MULTIBAND,
		1.0, 1.0 );
	vips_demand_hint( conversion->out, 
		VIPS_DEMAND_STYLE_ANY, NULL );

	if( vips_image_generate( conversion->out, 
		NULL, vips_gaussnoise_gen, NULL, gaussnoise, NULL ) )
		return( -1 );

	return( 0 );
}

static void
vips_gaussnoise_class_init( VipsGaussnoiseClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_gaussnoise_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "gaussnoise";
	vobject_class->description = _( "make a gaussnoise image" );
	vobject_class->build = vips_gaussnoise_build;

	VIPS_ARG_INT( class, "width", 4, 
		_( "Width" ), 
		_( "Image width in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsGaussnoise, width ),
		1, 1000000, 1 );

	VIPS_ARG_INT( class, "height", 5, 
		_( "Height" ), 
		_( "Image height in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsGaussnoise, height ),
		1, 1000000, 1 );

	VIPS_ARG_DOUBLE( class, "mean", 6, 
		_( "Mean" ), 
		_( "Mean of pixels in generated image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsGaussnoise, mean ),
		-10000000, 1000000, 1 );

	VIPS_ARG_DOUBLE( class, "sigma", 6, 
		_( "Sigma" ), 
		_( "Standard deviation of pixels in generated image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsGaussnoise, sigma ),
		1, 100000, 1 );

}

static void
vips_gaussnoise_init( VipsGaussnoise *gaussnoise )
{
	gaussnoise->mean = 1.0;
	gaussnoise->sigma = 1.0;
}

/**
 * vips_gaussnoise:
 * @out: output image
 * @width: output width
 * @height: output height
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @mean: mean of generated pixels
 * @sigma: standard deviation of generated pixels
 *
 * Make a one band float image of gaussian noise with the specified
 * distribution. The noise distribution is created by averaging 12 random 
 * numbers with the appropriate weights.
 *
 * See also: vips_black(), im_make_xy(), im_text().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_gaussnoise( VipsImage **out, int width, int height, ... )
{
	va_list ap;
	int result;

	va_start( ap, height );
	result = vips_call_split( "gaussnoise", ap, out, width, height );
	va_end( ap );

	return( result );
}

/* Generate function --- just fill the region with noise. "dummy" is our
 * sequence value: we don't need one.
 */
/*ARGSUSED*/
static int
gnoise_gen( REGION *or, void *seq, void *a, void *b )
{
	GnoiseInfo *gin = (GnoiseInfo *) a;
	int x, y, i;
	int sz = IM_REGION_N_ELEMENTS( or );

	for( y = 0; y < or->valid.height; y++ ) {
		float *q = (float *) 
			IM_REGION_ADDR( or, or->valid.left, y + or->valid.top );

		for( x = 0; x < sz; x++ ) {
			double sum = 0.0;

			for( i = 0; i < 12; i++ ) 
#ifdef HAVE_RANDOM
				sum += (double) random() / RAND_MAX;
#else /*HAVE_RANDOM*/
#ifdef HAVE_RAND
				sum += (double) rand() / RAND_MAX;
#else /*HAVE_RAND*/
#error "no random number generator found"
#endif /*HAVE_RAND*/
#endif /*HAVE_RAND*/

			q[x] = (sum - 6.0) * gin->sigma + gin->mean;
		}
	}

	return( 0 );
}

/**
 * im_gaussnoise:
 * @out: output image
 * @x: output width
 * @y: output height
 * @mean: average value in output
 * @sigma: standard deviation in output
 *
 * Make a one band float image of gaussian noise with the specified
 * distribution. The noise distribution is created by averaging 12 random 
 * numbers with the appropriate weights.
 *
 * See also: im_addgnoise(), im_make_xy(), im_text(), im_gaussnoise().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_gaussnoise( IMAGE *out, int x, int y, double mean, double sigma )
{	
	GnoiseInfo *gin;

	if( x <= 0 || y <= 0 ) {
		im_error( "im_gaussnoise", "%s", _( "bad parameter" ) );
		return( -1 );
	}

	if( im_poutcheck( out ) )
		return( -1 );
	im_initdesc( out, 
		x, y, 1, 
		IM_BBITS_FLOAT, IM_BANDFMT_FLOAT, IM_CODING_NONE, IM_TYPE_B_W,
		1.0, 1.0, 0, 0 );
	if( im_demand_hint( out, IM_ANY, NULL ) )
		return( -1 );
	
	/* Save parameters.
	 */
	if( !(gin = IM_NEW( out, GnoiseInfo )) )
		return( -1 );
	gin->mean = mean;
	gin->sigma = sigma;

	if( im_generate( out, NULL, gnoise_gen, NULL, gin, NULL ) )
		return( -1 );
	
	return( 0 );
}
