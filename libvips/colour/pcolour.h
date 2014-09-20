/* base class for all colour operations
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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef VIPS_PCOLOUR_H
#define VIPS_PCOLOUR_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include <vips/vips.h>

#define VIPS_TYPE_COLOUR (vips_colour_get_type())
#define VIPS_COLOUR( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_COLOUR, VipsColour ))
#define VIPS_COLOUR_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_COLOUR, VipsColourClass))
#define VIPS_IS_COLOUR( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_COLOUR ))
#define VIPS_IS_COLOUR_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_COLOUR ))
#define VIPS_COLOUR_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_COLOUR, VipsColourClass ))

struct _VipsColour;
typedef void (*VipsColourProcessFn)( struct _VipsColour *colour, 
	VipsPel *out, VipsPel **in, int width );

typedef struct _VipsColour {
	VipsOperation parent_instance;

	/* Null-terminated array of input arguments, set these from a 
	 * subclass.
	 */
	VipsImage **in;
	int n;

	/* If this is >0, only process this many bands from the input. Extra
	 * bands are removed and reattached after processing.
	 */
	int input_bands; 

	VipsImage *out;

	/* Set fields on ->out from these.
	 */
	VipsCoding coding;
	VipsInterpretation interpretation;
	VipsBandFormat format;
	int bands;

	/* Attach this profile, if set.
	 */
	char *profile_filename;
} VipsColour;

typedef struct _VipsColourClass {
	VipsOperationClass parent_class;

	/* The buffer processor.
	 */
	VipsColourProcessFn process_line;

} VipsColourClass;

GType vips_colour_get_type( void );

/* A float in, float out colourspace transformation.
 */

#define VIPS_TYPE_COLOUR_SPACE (vips_colour_space_get_type())
#define VIPS_COLOUR_SPACE( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_COLOUR_SPACE, VipsColourSpace ))
#define VIPS_COLOUR_SPACE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_COLOUR_SPACE, VipsColourSpaceClass))
#define VIPS_IS_COLOUR_SPACE( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_COLOUR_SPACE ))
#define VIPS_IS_COLOUR_SPACE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_COLOUR_SPACE ))
#define VIPS_COLOUR_SPACE_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_COLOUR_SPACE, VipsColourSpaceClass ))

typedef struct _VipsColourSpace {
	VipsColour parent_instance;

	VipsImage *in;

} VipsColourSpace;

typedef struct _VipsColourSpaceClass {
	VipsColourClass parent_class;

} VipsColourSpaceClass;

GType vips_colour_space_get_type( void );

/* Change colour encoding ... either in or out is not three-band float.
 */

#define VIPS_TYPE_COLOUR_CODE (vips_colour_code_get_type())
#define VIPS_COLOUR_CODE( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_COLOUR_CODE, VipsColourCode ))
#define VIPS_COLOUR_CODE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_COLOUR_CODE, VipsColourCodeClass))
#define VIPS_IS_COLOUR_CODE( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_COLOUR_CODE ))
#define VIPS_IS_COLOUR_CODE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_COLOUR_CODE ))
#define VIPS_COLOUR_CODE_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_COLOUR_CODE, VipsColourCodeClass ))

typedef struct _VipsColourCode {
	VipsColour parent_instance;

	VipsImage *in;

	/* Test in against these.
	 */
	VipsCoding input_coding;
	VipsBandFormat input_format;
	int input_bands;
	VipsInterpretation input_interpretation;

} VipsColourCode;

typedef struct _VipsColourCodeClass {
	VipsColourClass parent_class;

} VipsColourCodeClass;

GType vips_colour_code_get_type( void );

/* Difference between two colour images. 
 */

#define VIPS_TYPE_COLOUR_DIFFERENCE (vips_colour_difference_get_type())
#define VIPS_COLOUR_DIFFERENCE( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_COLOUR_DIFFERENCE, VipsColourDifference ))
#define VIPS_COLOUR_DIFFERENCE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_COLOUR_DIFFERENCE, VipsColourDifferenceClass))
#define VIPS_IS_COLOUR_DIFFERENCE( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_COLOUR_DIFFERENCE ))
#define VIPS_IS_COLOUR_DIFFERENCE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_COLOUR_DIFFERENCE ))
#define VIPS_COLOUR_DIFFERENCE_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_COLOUR_DIFFERENCE, VipsColourDifferenceClass ))

typedef struct _VipsColourDifference {
	VipsColour parent_instance;

	VipsImage *left;
	VipsImage *right;

	/* Both get converted to this space.
	 */
	VipsInterpretation interpretation;

} VipsColourDifference;

typedef struct _VipsColourDifferenceClass {
	VipsColourClass parent_class;

} VipsColourDifferenceClass;

GType vips_colour_difference_get_type( void );

void vips__pythagoras_line( VipsColour *colour, 
	VipsPel *out, VipsPel **in, int width );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_PCOLOUR_H*/

