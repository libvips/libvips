/* base class for all morphological operations
 *
 * properties:
 * 	- one input image
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

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
#include <vips/internal.h>

#include "pmorphology.h"

/** 
 * SECTION: morphology
 * @short_description: morphological operators, rank filters and related image 
 * analysis
 * @see_also: <link linkend="libvips-boolean">boolean</link>
 * @stability: Stable
 * @include: vips/vips.h
 *
 * The morphological functions search images
 * for particular patterns of pixels, specified with the mask argument,
 * either adding or removing pixels when they find a match. They are useful
 * for cleaning up images --- for example, you might threshold an image, and
 * then use one of the morphological functions to remove all single isolated
 * pixels from the result.
 *
 * If you combine the morphological operators with the mask rotators
 * im_rotate_imask45(), for example) and apply them repeatedly, you
 * can achieve very complicated effects: you can thin, prune, fill, open edges,
 * close gaps, and many others. For example, see `Fundamentals  of  Digital
 * Image Processing' by A.  Jain, pp 384-388, Prentice-Hall, 1989 for more 
 * ideas.
 *
 * Beware that VIPS reverses the usual image processing convention, by 
 * assuming white objects (non-zero pixels) on a black background (zero
 * pixels).
 *
 * The mask you give to the morphological functions should contain only the
 * values 0 (for background), 128 (for don't care) and 255 (for object). The
 * mask must have odd length sides --- the origin of the mask is taken to be
 * the centre value. For example, the mask:
 *
 *   3 3 
 *   128 255 128
 *   255 0   255
 *   128 255 128
 *
 * applied to an image with im_erode(), will find all black pixels
 * 4-way connected with white pixels. Essentially, im_dilate()
 * sets pixels in the output if any part of the mask matches, whereas
 * im_erode() sets pixels only if all of the mask matches.
 *
 * See im_andimage(), im_orimage() and im_eorimage()
 * for analogues of the usual set difference and set union operations.
 */

G_DEFINE_ABSTRACT_TYPE( VipsMorphology, vips_morphology, 
	VIPS_TYPE_OPERATION );

static void
vips_morphology_class_init( VipsMorphologyClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "morphology";
	vobject_class->description = _( "morphological operations" );

	/* Inputs set by subclassess.
	 */

	VIPS_ARG_IMAGE( class, "in", 0, 
		_( "Input" ), 
		_( "Input image argument" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMorphology, in ) );

}

static void
vips_morphology_init( VipsMorphology *morphology )
{
}

/* Called from iofuncs to init all operations in this dir. Use a plugin system
 * instead?
 */
void
vips_morphology_operation_init( void )
{
	extern int vips_morph_get_type( void ); 
	extern int vips_rank_get_type( void ); 
	extern int vips_countlines_get_type( void ); 

	vips_morph_get_type(); 
	vips_rank_get_type(); 
	vips_countlines_get_type(); 
}
