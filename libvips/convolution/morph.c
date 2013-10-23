/* morphology
 *
 * 23/10/13	
 * 	- from vips_conv()
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

/* This is a simple wrapper over the old vips7 functions. At some point we
 * should rewrite this as a pure vips8 class and redo the vips7 functions as
 * wrappers over this.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>

#include <vips/vips.h>

#include "pconvolution.h"

typedef struct {
	VipsConvolution parent_instance;

	VipsOperationMorphology morph;

} VipsMorph;

typedef VipsConvolutionClass VipsMorphClass;

G_DEFINE_TYPE( VipsMorph, vips_morph, VIPS_TYPE_CONVOLUTION );

static int
vips_morph_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConvolution *convolution = (VipsConvolution *) object;
	VipsMorph *morph = (VipsMorph *) object;

	INTMASK *imsk;

	g_object_set( morph, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_morph_parent_class )->build( object ) )
		return( -1 );

	if( !(imsk = im_vips2imask( convolution->M, class->nickname )) || 
		!im_local_imask( convolution->out, imsk ) )
		return( -1 ); 

	switch( morph->morph ) { 
	case VIPS_OPERATION_MORPHOLOGY_DILATE:
		if( im_dilate( convolution->in, convolution->out, imsk ) )
			return( -1 ); 
		break;

	case VIPS_OPERATION_MORPHOLOGY_ERODE:
		if( im_erode( convolution->in, convolution->out, imsk ) )
			return( -1 ); 
		break;

	default:
		g_assert( 0 );
	}

	return( 0 );
}

static void
vips_morph_class_init( VipsMorphClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "morph";
	object_class->description = _( "convolution operation" );
	object_class->build = vips_morph_build;

	VIPS_ARG_ENUM( class, "morph", 103, 
		_( "Morphology" ), 
		_( "Morphological operation to perform" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsMorph, morph ), 
		VIPS_TYPE_OPERATION_MORPHOLOGY, 
			VIPS_OPERATION_MORPHOLOGY_ERODE ); 

}

static void
vips_morph_init( VipsMorph *morph )
{
	morph->morph = VIPS_OPERATION_MORPHOLOGY_ERODE;
}

/**
 * vips_morph:
 * @in: input image
 * @out: output image
 * @mask: morphology with this mask
 * @morph: operation to perform
 * @...: %NULL-terminated list of optional named arguments
 *
 * Performs a morphological operation on @in using @mask as a
 * structuring element. 
 *
 * The image should have 0 (black) for no object and 255
 * (non-zero) for an object. Note that this is the reverse of the usual
 * convention for these operations, but more convenient when combined with the
 * boolean operators. The output image is the same
 * size as the input image: edge pxels are made by expanding the input image
 * as necessary.
 *
 * Mask coefficients can be either 0 (for object) or 255 (for background) 
 * or 128 (for do not care).  The origin of the mask is at location
 * (m.xsize / 2, m.ysize / 2), integer division.  All algorithms have been 
 * based on the book "Fundamentals of Digital Image Processing" by A. Jain, 
 * pp 384-388, Prentice-Hall, 1989. 
 *
 * For #VIPS_OPERATION_MOPHOLOGY_ERODE, 
 * the whole mask must match for the output pixel to be
 * set, that is, the result is the logical AND of the selected input pixels.
 *
 * For #VIPS_OPERATION_MOPHOLOGY_DILATE, 
 * the output pixel is set if any part of the mask 
 * matches, that is, the result is the logical OR of the selected input pixels.
 *
 * See the boolean operations vips_andimage(), vips_orimage() and 
 * vips_eorimage() 
 * for analogues of the usual set difference and set union operations.
 *
 * Operations are performed using the processor's vector unit,
 * if possible. Disable this with --vips-novector or IM_NOVECTOR.
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_morph( VipsImage *in, VipsImage **out, VipsImage *mask, 
	VipsOperationMorphology morph, ... )
{
	va_list ap;
	int result;

	va_start( ap, morph );
	result = vips_call_split( "morph", ap, in, out, mask, morph );
	va_end( ap );

	return( result );
}
