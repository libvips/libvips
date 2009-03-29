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

typedef struct _VipsObject VipsObject;
typedef struct _VipsObjectClass VipsObjectClass;

/* Track extra stuff for arguments to objects
 */

/* Flags we associate with each argument.
 */
typedef enum _VipsArgumentFlags {
	VIPS_ARGUMENT_NONE = 0,

	/* Must be set in the constructor.
	 */
	VIPS_ARGUMENT_REQUIRED = 1,

	/* Can only be set in the constructor.
	 */
	VIPS_ARGUMENT_CONSTRUCT = 2,

	/* Can only be set once.
	 */
	VIPS_ARGUMENT_SET_ONCE = 4,

	/* Have input & output flags. Both set is an error; neither set is OK.
	 */

	/* Is an input argument (one we depend on) ... if it's a gobject, we 
	 * should ref it. In our _dispose(), we should unref it.
	 */
	VIPS_ARGUMENT_INPUT = 8,

	/* Is an output argument (one that depends on us) ... if it's a
	 * gobject, we should ref ourselves. We watch "destroy" on the
	 * argument: if it goes, we unref ourselves. If we dispose, we
	 * disconnect the signal.
	 */
	VIPS_ARGUMENT_OUTPUT = 16
} VipsArgumentFlags;

/* Useful flag combinations. User-visible ones are:

VIPS_ARGUMENT_REQURED_INPUT 	Eg. the "left" argument for an add operation

VIPS_ARGUMENT_OPTIONAL_INPUT 	Eg. the "caption" for an object

VIPS_ARGUMENT_REQURED_OUTPUT 	Eg. the "result" of an add operation

VIPS_ARGUMENT_OPTIONAL_OUTPUT 	Eg. the "width" of an image

   Other combinations are used internally, eg. supplying the cast-table for an 
   arithmetic operation

 */

#define VIPS_ARGUMENT_REQUIRED_INPUT \
	(VIPS_ARGUMENT_INPUT | VIPS_ARGUMENT_REQUIRED | \
	 VIPS_ARGUMENT_CONSTRUCT | VIPS_ARGUMENT_SET_ONCE)

#define VIPS_ARGUMENT_OPTIONAL_INPUT \
	(VIPS_ARGUMENT_INPUT | \
	 VIPS_ARGUMENT_CONSTRUCT | VIPS_ARGUMENT_SET_ONCE)

#define VIPS_ARGUMENT_REQUIRED_OUTPUT \
	(VIPS_ARGUMENT_OUTPUT | VIPS_ARGUMENT_REQUIRED | \
	 VIPS_ARGUMENT_SET_ONCE)

#define VIPS_ARGUMENT_OPTIONAL_OUTPUT \
	(VIPS_ARGUMENT_OUTPUT | \
	 VIPS_ARGUMENT_SET_ONCE)

/* Keep one of these for every argument.
 */
typedef struct _VipsArgument {
	GParamSpec *pspec;	/* pspec for this argument */

	/* More stuff, see below */
} VipsArgument;

/* Keep one of these in the class struct for every argument.
 */
typedef struct _VipsArgumentClass {
	VipsArgument parent;

	/* The class of the object we are an arg for.
	 */
	VipsObjectClass *object_class;

	VipsArgumentFlags flags;
	guint offset;		/* G_STRUCT_OFFSET of member in object */
} VipsArgumentClass;

/* Keep one of these in the object struct for every argument instance.
 */
typedef struct _VipsArgumentInstance {
	VipsArgument parent;

	/* The object we are attached to.
	 */
	VipsObject *object;

	/* Has been set.
	 */
	gboolean assigned;

	/* If this is an output argument, keep the id of our "destroy" handler
	 * here.
	 */
	gulong destroy_id;	
} VipsArgumentInstance;

/* Need to look up our VipsArgument structs from a pspec. Just hash the
 * pointer (ie. we assume pspecs are never shared, is this correct?)
 */
typedef GHashTable VipsArgumentTable;

VipsArgumentInstance *vips__argument_get_instance( VipsArgumentClass *,
	VipsObject *);
VipsArgument *vips__argument_table_lookup( VipsArgumentTable *, 
	GParamSpec *);
typedef void *(*VipsArgumentMapFn)( VipsObject *, GParamSpec *,
	VipsArgumentClass *, VipsArgumentInstance *, void *a, void *b );
void *vips_argument_map( VipsObject *object, 
	VipsArgumentMapFn fn, void *a, void *b );

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

struct _VipsObject {
	GObject parent_object;

	gboolean constructed;		/* Construct done and checked */

	/* Table of argument instances for this class and any derived classes.
	 */
	VipsArgumentTable *argument_table;

	/* Class properties (see below), duplicated in the instance so we can
	 * get at them easily via the property system.
	 */
	char *nickname;
	char *description;
};

struct _VipsObjectClass {
	GObjectClass parent_class;

	/* Build the object ... all argument properties have been set,
	 * now build the thing.
	 */
	int (*build)( VipsObject *object );

	/* Try to print something about the class, handy for help displays.
	 */
	void (*print_class)( struct _VipsObjectClass *, VipsBuf * );

	/* Try to print something about the object, handy for debugging.
	 */
	void (*print)( VipsObject *, VipsBuf * );

	/* Class nickname, eg. "VipsInterpolateBicubic" has "bicubic" as a
	 * nickname. Not internationalised. 
	 */
	const char *nickname;

	/* Class description. Used for help messages, so internationalised.
	 */
	const char *description;

	/* Table of arguments for this class and any derived classes. Order
	 * is important, so keep a traverse list too. We can't rely on the
	 * ordering given by g_object_class_list_properties() since it comes
	 * from a hash :-(
	 */
	VipsArgumentTable *argument_table;
	GSList *argument_table_traverse;
};

void vips_object_set_property( GObject *gobject, 
	guint property_id, const GValue *value, GParamSpec *pspec );
void vips_object_get_property( GObject *gobject, 
	guint property_id, GValue *value, GParamSpec *pspec );

int vips_object_build( VipsObject *object );
void vips_object_print_class( VipsObjectClass *klass );
void vips_object_print( VipsObject *object );

GType vips_object_get_type( void );

void vips_object_class_install_argument( VipsObjectClass *,
	GParamSpec *pspec, VipsArgumentFlags flags, guint offset );

typedef void *(*VipsObjectSetArguments)( VipsObject *, void *, void * );
VipsObject *vips_object_new( GType type, 
	VipsObjectSetArguments set, void *a, void *b );

VipsObject *vips_object_new_from_string( const char *base, const char *str );
void vips_object_to_string( VipsObject *object, VipsBuf *buf );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_OBJECT_H*/


