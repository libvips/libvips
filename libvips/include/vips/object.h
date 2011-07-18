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

/* Handy!
 */
#define VIPS_UNREF( X ) VIPS_FREEF( g_object_unref, (X) )

typedef struct _VipsObject VipsObject;
typedef struct _VipsObjectClass VipsObjectClass;

/* Track extra stuff for arguments to objects
 */

/* Flags we associate with each argument.
 */
typedef enum {
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

VIPS_ARGUMENT_REQUIRED_INPUT 	Eg. the "left" argument for an add operation

VIPS_ARGUMENT_OPTIONAL_INPUT 	Eg. the "caption" for an object

VIPS_ARGUMENT_OUTPUT 	        Eg. the "result" of an add operation

   Other combinations are used internally, eg. supplying the cast-table for an 
   arithmetic operation

 */

#define VIPS_ARGUMENT_REQUIRED_INPUT \
	(VIPS_ARGUMENT_INPUT | \
	 VIPS_ARGUMENT_REQUIRED | \
	 VIPS_ARGUMENT_CONSTRUCT | \
	 VIPS_ARGUMENT_SET_ONCE)

#define VIPS_ARGUMENT_OPTIONAL_INPUT \
	(VIPS_ARGUMENT_INPUT | \
	 VIPS_ARGUMENT_CONSTRUCT | \
	 VIPS_ARGUMENT_SET_ONCE)

#define VIPS_ARGUMENT_REQUIRED_OUTPUT \
	(VIPS_ARGUMENT_OUTPUT | \
	 VIPS_ARGUMENT_REQUIRED | \
	 VIPS_ARGUMENT_CONSTRUCT | \
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

	/* If this is an output argument, keep the id of our "close" handler
	 * here.
	 */
	gulong close_id;	
} VipsArgumentInstance;

/* Need to look up our VipsArgument structs from a pspec. Just hash the
 * pointer (ie. we assume pspecs are never shared, is this correct?)
 */
typedef GHashTable VipsArgumentTable;

VipsArgumentInstance *vips__argument_get_instance( VipsArgumentClass *,
	VipsObject *);
VipsArgument *vips__argument_table_lookup( VipsArgumentTable *, 
	GParamSpec *);
void vips__object_set_member( VipsObject *object, GParamSpec *pspec,
	GObject **member, GObject *argument );
typedef void *(*VipsArgumentMapFn)( VipsObject *, GParamSpec *,
	VipsArgumentClass *, VipsArgumentInstance *, void *a, void *b );
void *vips_argument_map( VipsObject *object, 
	VipsArgumentMapFn fn, void *a, void *b );
void vips_argument_dispose_all( VipsObject *object );

/* We have to loop over an objects args in several places, and we can't always
 * use vips_argument_map(), the preferred looper. Have the loop code as a
 * macro as well for these odd cases.
 */
#define VIPS_ARGUMENT_FOR_ALL( OBJECT, PSPEC, ARG_CLASS, ARG_INSTANCE ) { \
	VipsObjectClass *object_class = VIPS_OBJECT_GET_CLASS( OBJECT ); \
	GSList *p; \
 	\
	for( p = object_class->argument_table_traverse; p; p = p->next ) { \
		VipsArgumentClass *ARG_CLASS = \
			(VipsArgumentClass *) p->data; \
		VipsArgument *argument = (VipsArgument *) argument_class; \
		GParamSpec *PSPEC = argument->pspec; \
		VipsArgumentInstance *ARG_INSTANCE = \
			vips__argument_get_instance( argument_class, \
			VIPS_OBJECT( OBJECT ) ); \
		\
		/* We have many props on the arg table ... filter out the \
		 * ones for this class. \
		 */ \
		if( g_object_class_find_property( \
			G_OBJECT_CLASS( object_class ), \
			g_param_spec_get_name( PSPEC ) ) == PSPEC ) {

#define VIPS_ARGUMENT_FOR_ALL_END } } }

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

	/* The pre/post/close callbacks are all fire-once. 
	 */
	gboolean preclose;
	gboolean close;
	gboolean postclose;
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

	/* Sanity-check the object. Print messages and stuff. 
	 * Handy for debugging.
	 */
	void (*sanity)( VipsObject *, VipsBuf * );

	/* Rewind. Save and restore any stuff that needs to survive a
	 * dispose().
	 */
	void (*rewind)( VipsObject * );

	/* Just before close, everything is still alive.
	 */
	void (*preclose)( VipsObject * );

	/* Close, time to free stuff.
	 */
	void (*close)( VipsObject * );

	/* Post-close, everything is dead, except the VipsObject pointer.
	 * Useful for eg. deleting the file associated with a temp image.
	 */
	void (*postclose)( VipsObject * );

	/* The CLI interface. Implement these four to get CLI input and output
	 * for your object.
	 */

	/* Given a command-line arg (eg. a filename), make an instance of the
	 * object. Just do the g_object_new(), don't call _build().
	 *
	 * Don't call this directly, see vips_object_new_from_string().
	 */
	VipsObject *(*new_from_string)( const char *string );

	/* The inverse of ^^. Given an object, output what ->new_from_string()
	 * would have been given to make that object. 
	 */
	void (*to_string)( VipsObject *, VipsBuf * ); 

	/* Does this output arg need an arg from the command line? Image
	 * output, for example, needs a filename to write to.
	 */
	gboolean output_needs_arg;

	/* Write the object to the string. Return 0 for success, or -1 on
	 * error, setting vips_error(). string is NULL if output_needs_arg()
	 * was FALSE.
	 */
	int (*output_to_arg)( VipsObject *object, const char *string );

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

gboolean vips_pspec_value_is_null( GParamSpec *pspec, const GValue *value );
void vips_object_set_property( GObject *gobject, 
	guint property_id, const GValue *value, GParamSpec *pspec );
void vips_object_get_property( GObject *gobject, 
	guint property_id, GValue *value, GParamSpec *pspec );

void vips_object_preclose( VipsObject *object );
int vips_object_build( VipsObject *object );
void vips_object_print_class( VipsObjectClass *klass );
void vips_object_print( VipsObject *object );
void vips_object_print_name( VipsObject *object );
gboolean vips_object_sanity( VipsObject *object );

GType vips_object_get_type( void );

void vips_object_class_install_argument( VipsObjectClass *,
	GParamSpec *pspec, VipsArgumentFlags flags, guint offset );
int vips_object_set_argument_from_string( VipsObject *object, 
	const char *name, const char *value );
gboolean vips_object_get_argument_needs_string( VipsObject *object, 
	const char *name );
int vips_object_get_argument_to_string( VipsObject *object, 
	const char *name, const char *arg );
int vips_object_set_required( VipsObject *object, const char *value );

typedef void *(*VipsObjectSetArguments)( VipsObject *, void *, void * );
VipsObject *vips_object_new( GType type, 
	VipsObjectSetArguments set, void *a, void *b );

VipsObject *vips_object_new_from_string( VipsObjectClass *object_class, 
	const char *p );
void vips_object_to_string( VipsObject *object, VipsBuf *buf );

void *vips_object_map( VipsSListMap2Fn fn, void *a, void *b );

typedef void *(*VipsTypeMap)( GType, void * );
typedef void *(*VipsTypeMap2)( GType, void *, void * );
typedef void *(*VipsClassMap)( VipsObjectClass *, void * );
void *vips_type_map( GType base, VipsTypeMap2 fn, void *a, void *b );
void *vips_type_map_all( GType base, VipsTypeMap fn, void *a );
void *vips_class_map_all( GType base, VipsClassMap fn, void *a );
int vips_class_depth( VipsObjectClass *klass );
VipsObjectClass *vips_class_find( const char *basename, const char *nickname );
GType vips_type_find( const char *basename, const char *nickname );

void vips_object_local_cb( VipsObject *vobject, GObject *gobject );
#define vips_object_local( V, G ) \
	(g_signal_connect( V, "close", \
		G_CALLBACK( vips_object_local_cb ), G ), 0)

void vips_object_print_all( void );
void vips_object_sanity_all( void );

void vips_object_rewind( VipsObject *object );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_OBJECT_H*/


