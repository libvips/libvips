/* Build a tone curve. 
 *
 * Author: John Cupitt
 * Written on: 18/7/1995
 * 17/9/96 JC
 *	- restrictions on Ps, Pm, Ph relaxed
 *	- restrictions on S, M, H relaxed
 * 25/7/01 JC
 *	- patched for im_extract_band() change
 * 11/7/04
 *	- generalised to im_tone_build_range() ... so you can use it for any
 *	  image, not just LabS
 * 26/3/10
 * 	- cleanups
 * 	- gtkdoc
 * 20/9/13
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
#include <math.h>

#include <vips/vips.h>

#include "pcreate.h"

typedef struct _VipsTonelut {
	VipsCreate parent_instance;

	/* Parameters for tone curve formation.
	 */
	double Lb, Lw;
	double Ps, Pm, Ph; 
	double S, M, H;

	/* Range we process.
	 */
	int in_max;
	int out_max;

	/* Derived values.
	 */
	double Ls, Lm, Lh;
} VipsTonelut;

typedef VipsCreateClass VipsTonelutClass;

G_DEFINE_TYPE( VipsTonelut, vips_tonelut, VIPS_TYPE_CREATE );

/* Calculate shadow curve.
 */
static double
shad( VipsTonelut *lut, double x )
{
	double x1 = (x - lut->Lb) / (lut->Ls - lut->Lb);
	double x2 = (x - lut->Ls) / (lut->Lm - lut->Ls);

	double out;

	if( x < lut->Lb )
		out = 0;
	else if( x < lut->Ls )
		out = 3.0 * x1 * x1 - 2.0 * x1 * x1 * x1;
	else if( x < lut->Lm )
		out = 1.0 - 3.0 * x2 * x2 + 2.0 * x2 * x2 * x2;
	else 
		out = 0;

	return( out );
}

/* Calculate mid-tone curve.
 */
static double
mid( VipsTonelut *lut, double x )
{
	double x1 = (x - lut->Ls) / (lut->Lm - lut->Ls);
	double x2 = (x - lut->Lm) / (lut->Lh - lut->Lm);

	double out;

	if( x < lut->Ls )
		out = 0;
	else if( x < lut->Lm )
		out = 3.0 * x1 * x1 - 2.0 * x1 * x1 * x1;
	else if( x < lut->Lh )
		out = 1.0 - 3.0 * x2 * x2 + 2.0 * x2 * x2 * x2;
	else 
		out = 0;

	return( out );
}

/* Calculate highlight curve.
 */
static double
high( VipsTonelut *lut, double x )
{
	double x1 = (x - lut->Lm) / (lut->Lh - lut->Lm);
	double x2 = (x - lut->Lh) / (lut->Lw - lut->Lh);

	double out;

	if( x < lut->Lm )
		out = 0;
	else if( x < lut->Lh )
		out = 3.0 * x1 * x1 - 2.0 * x1 * x1 * x1;
	else if( x < lut->Lw )
		out = 1.0 - 3.0 * x2 * x2 + 2.0 * x2 * x2 * x2;
	else 
		out = 0;

	return( out );
}

/* Generate a point on the tone curve. Everything is 0-100.
 */
static double
tone_curve( VipsTonelut *lut, double x )
{
	double out;

	out = x + 
		lut->S * shad( lut, x ) + 
		lut->M * mid( lut, x ) + 
		lut->H * high( lut, x );
	
	return( out );
}

static int
vips_tonelut_build( VipsObject *object )
{
	VipsCreate *create = VIPS_CREATE( object );
	VipsTonelut *lut = (VipsTonelut *) object;

	int i; 
	unsigned short buf[65536];

	if( VIPS_OBJECT_CLASS( vips_tonelut_parent_class )->build( object ) )
		return( -1 );

	g_assert( lut->in_max > 0 && lut->in_max < 65536 ); 
	g_assert( lut->out_max > 0 && lut->out_max < 65536 ); 

	/* Note derived params.
	 */
	lut->Ls = lut->Lb + lut->Ps * (lut->Lw - lut->Lb);
	lut->Lm = lut->Lb + lut->Pm * (lut->Lw - lut->Lb);
	lut->Lh = lut->Lb + lut->Ph * (lut->Lw - lut->Lb);

	/* Generate curve.
	 */
	for( i = 0; i <= lut->in_max; i++ ) {
		int v = (lut->out_max / 100.0) * 
			tone_curve( lut, 100.0 * i / lut->in_max );

		if( v < 0 )
			v = 0;
		else if( v > lut->out_max )
			v = lut->out_max;

		buf[i] = v;
	}

	/* Make the output image.
	 */
        vips_image_init_fields( create->out,
                lut->in_max + 1, 1, 1, 
		VIPS_FORMAT_USHORT, VIPS_CODING_NONE, 
		VIPS_INTERPRETATION_HISTOGRAM, 1.0, 1.0 );
        if( vips_image_write_line( create->out, 0, (VipsPel *) buf ) ) 
		return( -1 );

	return( 0 );
}

static void
vips_tonelut_class_init( VipsTonelutClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "tonelut";
	vobject_class->description = _( "build a look-up table" );
	vobject_class->build = vips_tonelut_build;

	VIPS_ARG_INT( class, "in_max", 4, 
		_( "In-max" ), 
		_( "Size of LUT to build" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsTonelut, in_max ),
		1, 65535, 32767 );

	VIPS_ARG_INT( class, "out_max", 5, 
		_( "Out-max" ), 
		_( "Maximum value in output LUT" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsTonelut, out_max ),
		1, 65535, 32767 );

	VIPS_ARG_DOUBLE( class, "Lb", 6, 
		_( "Black point" ), 
		_( "Lowest value in output" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsTonelut, Lb ),
		0, 100, 0 ); 

	VIPS_ARG_DOUBLE( class, "Lw", 7, 
		_( "White point" ), 
		_( "Highest value in output" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsTonelut, Lw ),
		0, 100, 100 ); 

	VIPS_ARG_DOUBLE( class, "Ps", 8, 
		_( "Shadow point" ), 
		_( "Position of shadow" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsTonelut, Ps ),
		0, 1, 0.2 ); 

	VIPS_ARG_DOUBLE( class, "Pm", 9, 
		_( "Mid-tone point" ), 
		_( "Position of mid-tones" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsTonelut, Pm ),
		0, 1, 0.5 ); 

	VIPS_ARG_DOUBLE( class, "Ph", 10, 
		_( "Highlight point" ), 
		_( "Position of highlights" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsTonelut, Ph ),
		0, 1, 0.8 ); 

	VIPS_ARG_DOUBLE( class, "S", 11, 
		_( "Shadow adjust" ), 
		_( "Adjust shadows by this much" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsTonelut, S ),
		-30, 30, 0 ); 

	VIPS_ARG_DOUBLE( class, "M", 12, 
		_( "Mid-tone adjust" ), 
		_( "Adjust mid-tones by this much" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsTonelut, M ),
		-30, 30, 0 ); 

	VIPS_ARG_DOUBLE( class, "H", 13, 
		_( "Highlight adjust" ), 
		_( "Adjust highlights by this much" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsTonelut, H ),
		-30, 30, 0 ); 

}

static void
vips_tonelut_init( VipsTonelut *lut )
{
	lut->in_max = 32767; 
	lut->out_max = 32767; 
	lut->Lb = 0.0; 
	lut->Lw = 100.0; 
	lut->Ps = 0.2; 
	lut->Pm = 0.5; 
	lut->Ph = 0.8; 
	lut->S = 0.0; 
	lut->M = 0.0; 
	lut->H = 0.0; 
}

/**
 * vips_tonelut:
 * @out: output image 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @in_max: input range 
 * @out_max: output range
 * @Lb: black-point [0-100]
 * @Lw: white-point [0-100]
 * @Ps: shadow point (eg. 0.2)
 * @Pm: mid-tone point (eg. 0.5)
 * @Ph: highlight point (eg. 0.8)
 * @S: shadow adjustment (+/- 30)
 * @M: mid-tone adjustment (+/- 30)
 * @H: highlight adjustment (+/- 30)
 *
 * vips_tonelut() generates a tone curve for the adjustment of image 
 * levels. It is mostly designed for adjusting the L* part of a LAB image in
 * way suitable for print work, but you can use it for other things too.
 *
 * The curve is an unsigned 16-bit image with (@in_max + 1) entries, 
 * each in the range [0, @out_max].
 *
 * @Lb, @Lw are expressed as 0-100, as in LAB colour space. You 
 * specify the scaling for the input and output images with the @in_max and 
 * @out_max parameters.
 *
 * See also: vips_tone_map(), vips_tone_analyse().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_tonelut( VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "tonelut", ap, out );
	va_end( ap );

	return( result );
}

