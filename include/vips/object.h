/* abstract base class for all vips objects
 */

/*

    Copyright (C) 1991-2003 The National Gallery

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

#ifndef VIPS_OBJECT_H
#define VIPS_OBJECT_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define VIPS_TYPE_OBJECT (vips_object_get_type())
#define VIPS_OBJECT( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), VIPS_TYPE_OBJECT, VipsObject ))
#define VIPS_OBJECT_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), VIPS_TYPE_OBJECT, VipsObjectClass))
#define VIPS_IS_OBJECT( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_OBJECT ))
#define VIPS_IS_OBJECT_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_OBJECT ))
#define VIPS_OBJECT_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), VIPS_TYPE_OBJECT, VipsObjectClass ))

typedef struct _VipsObject {
	GObject parent_object;

	/* Optional instance name.
	 */
	char *name;
} VipsObject;

typedef struct _VipsObjectClass {
	GObjectClass parent_class;

	/* Something about the object has changed. Should use glib's properties
	 * but fix this later.
	 */
	void (*changed)( VipsObject * );

	/* Try to print something about the class, handy for help displays.
	 */
	void (*print_class)( struct _VipsObjectClass *, im_buf_t * );

	/* Try to print something about the object, handy for debugging.
	 */
	void (*print)( VipsObject *, im_buf_t * );

	/* Class nickname, eg. "VipsInterpolateBicubic" has "bicubic" as a
	 * nickname. Not internationalised. 
	 */
	const char *nickname;

	/* Class description. Used for help messages, so internationalised.
	 */
	const char *description;
} VipsObjectClass;

void *vips_object_changed( VipsObject *object );
void vips_object_print_class( VipsObjectClass *klass );
void vips_object_print( VipsObject *object );

GType vips_object_get_type( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_OBJECT_H*/


