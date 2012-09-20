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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/* We don't want to get confused with the colour.h in include, put an
 * extra _ in there.
 */

#ifndef VIPS__COLOUR_H
#define VIPS__COLOUR_H

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

	VipsImage *out;
} VipsColour;

typedef struct _VipsColourClass {
	VipsOperationClass parent_class;

	/* The buffer processor.
	 */
	VipsColourProcessFn process_line;

	/* What to set Type to for this subclass.
	 */
	VipsInterpretation interpretation;
} VipsColourClass;

GType vips_colour_get_type( void );

/* A three float bands in, three float bands out colourspace transformation.
 */

#define VIPS_TYPE_COLOUR_SPACE (vips_space_get_type())
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

GType vips_space_get_type( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS__COLOUR_H*/


