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
 * 29/5/13
 * 	- redo as a class
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

#include "pcreate.h"

typedef struct _VipsGaussnoise {
	VipsCreate parent_instance;

	int width;
	int height;
	double mean;
	double sigma;

} VipsGaussnoise;

typedef VipsCreateClass VipsGaussnoiseClass;

G_DEFINE_TYPE( VipsGaussnoise, vips_gaussnoise, VIPS_TYPE_CREATE );

/* Make a random number in 0 - 1. Prefer random(). 
 */
#ifdef HAVE_RANDOM
#define VIPS_RND() ((double) random() / RAND_MAX)
#else /*!HAVE_RANDOM*/
#ifdef HAVE_RAND
#define VIPS_RND() ((double) rand() / RAND_MAX)
#else /*!HAVE_RAND*/
#error "no random number generator found"
#endif /*HAVE_RAND*/
#endif /*HAVE_RANDOM*/

static int
vips_gaussnoise_gen( VipsRegion *or, void *seq, void *a, void *b,
	gboolean *stop )
{
	VipsGaussnoise *gaussnoise = (VipsGaussnoise *) a;
	int sz = VIPS_REGION_N_ELEMENTS( or );

	int y;

	for( y = 0; y < or->valid.height; y++ ) {
		float *q = (float *) VIPS_REGION_ADDR( or, 
			or->valid.left, y + or->valid.top );

		int x;

		for( x = 0; x < sz; x++ ) {
			double sum;
			int i;

			sum = 0.0;
			for( i = 0; i < 12; i++ ) 
				sum += VIPS_RND(); 

			q[x] = (sum - 6.0) * gaussnoise->sigma + 
				gaussnoise->mean;
		}
	}

	return( 0 );
}

static int
vips_gaussnoise_build( VipsObject *object )
{
	VipsCreate *create = VIPS_CREATE( object );
	VipsGaussnoise *gaussnoise = (VipsGaussnoise *) object;

	if( VIPS_OBJECT_CLASS( vips_gaussnoise_parent_class )->build( object ) )
		return( -1 );

	vips_image_init_fields( create->out,
		gaussnoise->width, gaussnoise->height, 1,
		VIPS_FORMAT_FLOAT, VIPS_CODING_NONE,
		VIPS_INTERPRETATION_B_W, 1.0, 1.0 );
	vips_image_pipelinev( create->out, 
		VIPS_DEMAND_STYLE_ANY, NULL );

	if( vips_image_generate( create->out, 
		NULL, vips_gaussnoise_gen, NULL, gaussnoise, NULL ) )
		return( -1 );

	return( 0 );
}

static void
vips_gaussnoise_class_init( VipsGaussnoiseClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = (VipsOperationClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "gaussnoise";
	vobject_class->description = _( "make a gaussnoise image" );
	vobject_class->build = vips_gaussnoise_build;

	/* We want a new set of numbers each time.
	 */
	operation_class->flags |= VIPS_OPERATION_NOCACHE;

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
		-10000000, 1000000, 128 );

	VIPS_ARG_DOUBLE( class, "sigma", 6, 
		_( "Sigma" ), 
		_( "Standard deviation of pixels in generated image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsGaussnoise, sigma ),
		0, 100000, 30 );

}

static void
vips_gaussnoise_init( VipsGaussnoise *gaussnoise )
{
	gaussnoise->mean = 128.0;
	gaussnoise->sigma = 30.0;
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
 * See also: vips_black(), vips_xyz(), vips_text().
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
