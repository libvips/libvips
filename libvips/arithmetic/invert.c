/* photographic negative ... just an example, really
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 12/02/1990
 * Modified on :
 * 7/7/93 JC
 *      - memory leaks fixed
 *      - adapted for partial v2
 *      - ANSIfied
 * 22/2/95 JC
 *	- tidied up again
 * 2/9/09
 * 	- gtk-doc comment
 * 23/8/11
 * 	- rewrite as a class 
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
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

#include "arithmetic.h"
#include "unary.h"

/**
 * VipsInvert:
 * @in: input #VipsImage
 * @out: output #VipsImage
 *
 * this operation calculates (255 - @in).
 * The operation works on uchar images only. The input can have any 
 * number of channels.
 *
 * This is not a generally useful operation -- it is included as an example of 
 * a very simple operation.
 * See im_exptra() for an example of a VIPS function which can process
 * any input image type.
 *
 * See also: im_exptra(), im_lintra().
 *
 * Returns: 0 on success, -1 on error
 */

typedef VipsUnary VipsInvert;
typedef VipsUnaryClass VipsInvertClass;

G_DEFINE_TYPE( VipsInvert, vips_invert, VIPS_TYPE_UNARY );

static void
vips_invert_buffer( VipsArithmetic *arithmetic, PEL *out, PEL **in, int width )
{
	VipsImage *im = arithmetic->ready[0];
	PEL *p = in[0];
	int ne = width * im->Bands;

	int x;

	for( x = 0; x < ne; x++ )
		out[x] = 255 - p[x];
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define C VIPS_FORMAT_CHAR
#define US VIPS_FORMAT_USHORT
#define S VIPS_FORMAT_SHORT
#define UI VIPS_FORMAT_UINT
#define I VIPS_FORMAT_INT
#define F VIPS_FORMAT_FLOAT
#define X VIPS_FORMAT_COMPLEX
#define D VIPS_FORMAT_DOUBLE
#define DX VIPS_FORMAT_DPCOMPLEX

/* Type promotion for invertion. Sign and value preserving. Make sure these
 * match the case statement in vips_invert_buffer() above.
 */
static const VipsBandFormat bandfmt_invert[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, UC, UC, UC, UC, UC, UC, UC, UC, UC
};

static void
vips_invert_class_init( VipsInvertClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS( class );

	object_class->nickname = "invert";
	object_class->description = _( "invert an image" );

	vips_arithmetic_set_format_table( aclass, bandfmt_invert );

	aclass->process_line = vips_invert_buffer;
}

static void
vips_invert_init( VipsInvert *invert )
{
}

int
vips_invert( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "invert", ap, in, out );
	va_end( ap );

	return( result );
}
