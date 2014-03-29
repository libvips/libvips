/* a drawink operation with an ink param
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

#ifndef VIPS_DRAWINK_H
#define VIPS_DRAWINK_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include "pdraw.h"

#define VIPS_TYPE_DRAWINK (vips_drawink_get_type())
#define VIPS_DRAWINK( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_DRAWINK, VipsDrawink ))
#define VIPS_DRAWINK_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_DRAWINK, VipsDrawinkClass))
#define VIPS_IS_DRAWINK( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_DRAWINK ))
#define VIPS_IS_DRAWINK_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_DRAWINK ))
#define VIPS_DRAWINK_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_DRAWINK, VipsDrawinkClass ))

typedef struct _VipsDrawink {
	VipsDraw parent_instance;

	VipsArrayDouble *ink;

	/* Ink cast to pixel type.
	 */
	VipsPel *pixel_ink;
} VipsDrawink;

typedef struct _VipsDrawinkClass {
	VipsDrawClass parent_class;

} VipsDrawinkClass;

GType vips_drawink_get_type( void );

typedef int (*VipsDrawPoint)( VipsDrawink *drawink, int x, int y ); 
typedef int (*VipsDrawScanline)( VipsDrawink *drawink, int y, int x1, int x2 );

static inline int
vips__drawink_pel( VipsDrawink *drawink, VipsPel *q )
{
	VipsDraw *draw = (VipsDraw *) drawink;

 	int j;

	/* Faster than memcopy() for n < about 20.
	 */
	for( j = 0; j < draw->psize; j++ ) 
		q[j] = drawink->pixel_ink[j];

	return( 0 ); 
}

/* Paint, with clip.
 */
static inline int 
vips__drawink_pel_clip( VipsDrawink *drawink, int x, int y )
{
	VipsDraw *draw = (VipsDraw *) drawink;

	if( x < 0 || 
		x >= draw->image->Xsize )
		return( 0 );
	if( y < 0 || 
		y >= draw->image->Ysize )
		return( 0 );

	vips__drawink_pel( drawink, VIPS_IMAGE_ADDR( draw->image, x, y ) );

	return( 0 ); 
}

/* Is p painted?
 */
static inline gboolean
vips__drawink_painted( VipsDrawink *drawink, VipsPel *p )
{
	VipsDraw *draw = (VipsDraw *) drawink;

 	int j;

	for( j = 0; j < draw->psize; j++ ) 
		if( p[j] != drawink->pixel_ink[j] ) 
			break;

	return( j == draw->psize );
}

int vips__drawink_scanline( VipsDrawink *drawink, int y, int x1, int x2 );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_DRAWINK_H*/
