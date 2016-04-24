/* estimate entropy
 *
 * Author: John Cupitt
 * 11/8/15	
 * 	- from hist_ismonotonic.c
 * 6/3/16
 * 	- vips_log() call was mangled, thanks Lovell
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
#include <math.h>

#include <vips/vips.h>

typedef struct _VipsHistEntropy { 
	VipsOperation parent_instance;

	VipsImage *in;

	double out;
} VipsHistEntropy;

typedef VipsOperationClass VipsHistEntropyClass;

G_DEFINE_TYPE( VipsHistEntropy, vips_hist_entropy, 
	VIPS_TYPE_OPERATION );

static int
vips_hist_entropy_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsHistEntropy *entropy = (VipsHistEntropy *) object; 
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 4 );

	double avg; 
	double sum; 

	if( VIPS_OBJECT_CLASS( vips_hist_entropy_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_check_hist( class->nickname, entropy->in ) )
		return( -1 );

	/* Compute:
	 *   norm_hist = hist / sum( hist )
	 *   entropy = -sum( norm_hist * log2( norm_hist ) )
	 */
	if( vips_avg( entropy->in, &avg, NULL ) )
		return( -1 );
	sum = avg * VIPS_IMAGE_N_PELS( entropy->in ) * entropy->in->Bands;
	if( vips_linear1( entropy->in, &t[0], 1.0 / sum, 0, NULL ) ||
		vips_log( t[0], &t[1], NULL ) ||
		vips_linear1( t[1], &t[2], 1.0 / log( 2.0 ), 0, NULL ) ||
		vips_multiply( t[0], t[2], &t[3], NULL ) ||
		vips_avg( t[3], &avg, NULL ) )
		return( -1 );

	g_object_set( entropy, 
		"out", -avg * 
			VIPS_IMAGE_N_PELS( entropy->in ) * entropy->in->Bands,
		NULL ); 

	return( 0 );
}

static void
vips_hist_entropy_class_init( VipsHistEntropyClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "hist_entropy";
	object_class->description = _( "estimate image entropy" );
	object_class->build = vips_hist_entropy_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input histogram image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsHistEntropy, in ) );

	VIPS_ARG_DOUBLE( class, "out", 1, 
		_( "Output" ), 
		_( "Output value" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET( VipsHistEntropy, out ),
		-INFINITY, INFINITY, 0.0 );

}

static void
vips_hist_entropy_init( VipsHistEntropy *entropy )
{
}

/**
 * vips_hist_entropy:
 * @in: input histogram 
 * @out: image entropy
 * @...: %NULL-terminated list of optional named arguments
 *
 * Estimate image entropy from a histogram. Entropy is calculated as:
 *
 * |[
 * -sum( p * log2( p ) )
 * ]|
 *
 * where p is histogram-value / sum-of-histogram-values.
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_hist_entropy( VipsImage *in, double *out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "hist_entropy", ap, in, out );
	va_end( ap );

	return( result );
}
