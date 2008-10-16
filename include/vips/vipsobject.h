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

#define TYPE_VOBJECT (vobject_get_type())
#define VOBJECT( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), TYPE_VOBJECT, VObject ))
#define VOBJECT_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), TYPE_VOBJECT, VObjectClass))
#define IS_VOBJECT( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), TYPE_VOBJECT ))
#define IS_VOBJECT_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), TYPE_VOBJECT ))
#define VOBJECT_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), TYPE_VOBJECT, VObjectClass ))

/* Handy vobject_destroy() shortcut.
 */
#define IDESTROY( O ) { \
	if( O ) { \
		(void) vobject_destroy( VOBJECT( O ) ); \
		( O ) = NULL; \
	} \
}

typedef struct _VObject {
	GObject parent_object;

	/* True when created ... the 1 reference that gobject makes is
	 * 'floating' and not owned by anyone. Do _sink() after every _ref()
	 * to transfer ownership to the parent container. Upshot: no need to
	 * _unref() after _add() in _new().
	 */
	gboolean floating;

	/* Stop destroy loops with this.
	 */
	gboolean in_destruction;
} VObject;

typedef struct _VObjectClass {
	GObjectClass parent_class;

	/* End object's lifetime, just like gtk_object_destroy.
	 */
	void (*destroy)( VObject * );

	/* Something about the object has changed. Should use glib's properties
	 * but fix this later.
	 */
	void (*changed)( VObject * );
} VObjectClass;

void *vobject_destroy( VObject *vobject );
void *vobject_changed( VObject *vobject );
void vobject_sink( VObject *vobject );

GType vobject_get_type( void );

