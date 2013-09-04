/* Match two normalised, cumulative histograms.
 *
 * Copyright: 1991, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 19/07/1990
 * Modified on: 26/03/1991
 *
 * 1/3/01 JC
 * 	- bleurg! rewritten, now does 16 bits as well, bugs removed, faster,
 *     	  smaller
 * 24/3/10
 * 	- gtkdoc
 * 	- small cleanups
 * 12/8/13	
 * 	- redone im_histspec() as a class, vips_hist_match()
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
#include <assert.h>

#include <vips/vips.h>

#include "phistogram.h"

/*
#define DEBUG
 */

typedef struct _VipsHistMatch {
	VipsHistogram parent_instance;

	VipsImage *in;
	VipsImage *ref;

} VipsHistMatch;

typedef VipsHistogramClass VipsHistMatchClass;

G_DEFINE_TYPE( VipsHistMatch, vips_hist_match, VIPS_TYPE_HISTOGRAM );

static void
vips_hist_match_process( VipsHistogram *histogram, 
	VipsPel *out, VipsPel **in, int width )
{
	VipsHistMatch *match = (VipsHistMatch *) histogram; 
	const int bands = match->in->Bands;	
	const int max = width * bands;

	unsigned int *inbuf = (unsigned int *) in[0];
	unsigned int *refbuf = (unsigned int *) in[1];
	unsigned int *outbuf = (unsigned int *) out;

	int i, j;

	for( j = 0; j < bands; j++ ) {
		/* Track up refbuf[] with this.
		 */
		int ri = j;
		int limit = max - bands;

		for( i = j; i < max; i += bands ) {
			unsigned int inv = inbuf[i];

			for( ; ri < limit; ri += bands )
				if( inv <= refbuf[ri] )
					break;

			if( ri < limit ) {
				/* Simple rounding.
				 */
				double mid = refbuf[ri] + 
					refbuf[ri + bands] / 2.0;

				if( inv < mid )
					outbuf[i] = ri / bands;
				else
					outbuf[i] = ri / bands + 1;
			}
			else 
				outbuf[i] = refbuf[ri];
		}
	}
}

static int
vips_hist_match_build( VipsObject *object )
{
	VipsHistogram *histogram = VIPS_HISTOGRAM( object );
	VipsHistMatch *match = (VipsHistMatch *) object;

	histogram->n = 2;
	histogram->in = (VipsImage **) vips_object_local_array( object, 2 );
	histogram->in[0] = match->in;
	histogram->in[1] = match->ref;

	if( histogram->in[0] )
		g_object_ref( histogram->in[0] );
	if( histogram->in[1] )
		g_object_ref( histogram->in[1] );

	if( VIPS_OBJECT_CLASS( vips_hist_match_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

#define UI VIPS_FORMAT_UINT

static const VipsBandFormat vips_hist_match_format_table[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UI, UI, UI, UI, UI, UI, UI, UI, UI, UI 
};

static void
vips_hist_match_class_init( VipsHistMatchClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsHistogramClass *hclass = VIPS_HISTOGRAM_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "hist_match";
	vobject_class->description = _( "match two histograms" );
	vobject_class->build = vips_hist_match_build;

	hclass->format_table = vips_hist_match_format_table;
	hclass->process = vips_hist_match_process;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsHistMatch, in ) );

	VIPS_ARG_IMAGE( class, "ref", 2, 
		_( "Reference" ), 
		_( "Reference image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsHistMatch, ref ) );

}

static void
vips_hist_match_init( VipsHistMatch *match )
{
}

/**
 * vips_hist_match:
 * @in: input histogram
 * @ref: reference histogram 
 * @out: output histogram
 *
 * Creates a lut which, when applied to the image from which histogram @in was
 * formed, will produce an image whose PDF matches that of the image from 
 * which @ref was formed.
 *
 * See also: im_hsp(), im_histgr(), im_maplut().
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_hist_match( VipsImage *in, VipsImage *ref, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "hist_match", ap, in, ref, out );
	va_end( ap );

	return( result );
}
