/* histogram normalisation
 *
 * Author: N. Dessipris
 * Written on: 02/08/1990
 * 24/5/95 JC
 *	- tidied up and ANSIfied
 * 20/7/95 JC
 *	- smartened up again
 *	- now works for hists >256 elements
 * 3/3/01 JC
 *	- broken into norm and norm ... helps im_histspec()
 *	- better behaviour for >8 bit hists
 * 31/10/05 JC
 * 	- was broken for vertical histograms, gah
 * 	- neater im_histnorm()
 * 23/7/07
 * 	- eek, off by 1 for more than 1 band hists
 * 12/5/08
 * 	- histnorm works for signed hists now as well
 * 24/3/10
 * 	- gtkdoc
 * 	- small cleanups
 * 12/8/13	
 * 	- redone im_histnorm() as a class, vips_hist_norm()
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

#include <vips/vips.h>

typedef struct _VipsHistNorm {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;
} VipsHistNorm;

typedef VipsOperationClass VipsHistNormClass;

G_DEFINE_TYPE( VipsHistNorm, vips_hist_norm, VIPS_TYPE_OPERATION );

static int
vips_hist_norm_build( VipsObject *object )
{
	VipsHistNorm *norm = (VipsHistNorm *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 3 );

	guint64 px;
	int bands; 
	double *a, *b;
	int y;
	VipsBandFormat fmt;

	g_object_set( norm, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_hist_norm_parent_class )->build( object ) )
		return( -1 );

	/* Need max for each channel.
	 */
	if( vips_stats( norm->in, &t[0], NULL ) )
		return( -1 ); 

	/* Scale each channel by px / channel max
	 */
	px = VIPS_IMAGE_N_PELS( norm->in );
	bands = norm->in->Bands;
	if( !(a = VIPS_ARRAY( object, bands, double )) ||
		!(b = VIPS_ARRAY( object, bands, double )) )
		return( -1 );
	for( y = 0; y < bands; y++ ) {
		a[y] = px / *VIPS_MATRIX( t[0], 1, y + 1 );
		b[y] = 0;
	}

	if( vips_linear( norm->in, &t[1], a, b, bands, NULL ) )
		return( -1 );

	/* Make output format as small as we can.
	 */
	if( px <= 256 ) 
		fmt = VIPS_FORMAT_UCHAR;
	else if( px <= 65536 ) 
		fmt = VIPS_FORMAT_USHORT;
	else 
		fmt = VIPS_FORMAT_UINT;

	if( vips_cast( t[1], &t[2], fmt, NULL ) ||
		vips_image_write( t[2], norm->out ) )
		return( -1 );

	return( 0 );
}

static void
vips_hist_norm_class_init( VipsHistNormClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "hist_norm";
	object_class->description = _( "normalise histogram" );
	object_class->build = vips_hist_norm_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsHistNorm, in ) );

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsHistNorm, out ) );
}

static void
vips_hist_norm_init( VipsHistNorm *hist_norm )
{
}

/**
 * vips_hist_norm:
 * @in: input image
 * @out: output image
 *
 * Normalise histogram ... normalise range to make it square (ie. max ==
 * number of elements). Normalise each band separately.
 *
 * See also: vips_hist_cum().
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_hist_norm( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "hist_norm", ap, in, out );
	va_end( ap );

	return( result );
}
