/* draw_line draw class
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

#ifndef VIPS_DRAW_LINE_H
#define VIPS_DRAW_LINE_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define VIPS_TYPE_DRAW_LINE (vips_draw_line_get_type())
#define VIPS_DRAW_LINE( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_DRAW_LINE, VipsDrawLine ))
#define VIPS_DRAW_LINE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_DRAW_LINE, VipsDrawLineClass))
#define VIPS_IS_DRAW_LINE( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_DRAW_LINE ))
#define VIPS_IS_DRAW_LINE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_DRAW_LINE ))
#define VIPS_DRAW_LINE_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_DRAW_LINE, VipsDrawLineClass ))

typedef struct _VipsDrawLine {
	VipsDraw parent_object;

	int x1;
	int y1;
	int x2;
	int y2;

	int dx;
	int dy;

} VipsDrawLine;

typedef struct _VipsDrawLineClass {
	VipsDrawClass parent_class;

	int (*plot_point)( VipsDrawLine *, int x, int y ); 
} VipsDrawLineClass; 

typedef int (*VipsDrawLinePlotPoint)( VipsDrawLine *draw_line, int x, int y ); 

GType vips_draw_line_get_type( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_PDRAW_H*/

