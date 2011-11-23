/* Base type for supported image files. Subclass this to add a new
 * file.
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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef IM_FILE_H
#define IM_FILE_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define VIPS_TYPE_FILE (vips_file_get_type())
#define VIPS_FILE( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_FILE, VipsFile ))
#define VIPS_FILE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_FILE, VipsFileClass))
#define VIPS_IS_FILE( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_FILE ))
#define VIPS_IS_FILE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_FILE ))
#define VIPS_FILE_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_FILE, VipsFileClass ))

typedef struct _VipsFile {
	VipsOperation parent_object;
	/*< public >*/

	/* Filename for load or save.
	 */
	char *filename; 

} VipsFile;

typedef struct _VipsFileClass {
	VipsOperationClass parent_class;

	/*< public >*/
	/* Is a file in this file.
	 */
	gboolean (*is_a)( const char * );

	/* Null-terminated list of allowed suffixes, eg. ".tif", ".tiff".
	 */
	const char **suffs;

	/* Loop over files in this order, default 0. We need this because
	 * some files can be read by several loaders (eg. tiff can be read
	 * by the libMagick loader as well as by the tiff loader), and we want
	 * to make sure the better loader comes first.
	 */
	int priority;

} VipsFileClass;

GType vips_file_get_type( void );

/* Map over and find files. This uses type introspection to loop over
 * subclasses of VipsFile.
 */
void *vips_file_map( VipsSListMap2Fn fn, void *a, void *b );

#define VIPS_TYPE_FILE_LOAD (vips_file_load_get_type())
#define VIPS_FILE_LOAD( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_FILE_LOAD, VipsFileLoad ))
#define VIPS_FILE_LOAD_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_FILE_LOAD, VipsFileLoadClass))
#define VIPS_IS_FILE_LOAD( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_FILE_LOAD ))
#define VIPS_IS_FILE_LOAD_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_FILE_LOAD ))
#define VIPS_FILE_LOAD_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_FILE_LOAD, VipsFileLoadClass ))

/* Image file properties. 
 */
typedef enum {
	VIPS_FILE_NONE = 0,		/* No flags set */
	VIPS_FILE_PARTIAL = 1,	/* Lazy read OK (eg. tiled tiff) */
	VIPS_FILE_BIGENDIAN = 2	/* Most-significant byte first */
} VipsFileFlags;

typedef struct _VipsFileLoad {
	VipsFile parent_object;
	/*< public >*/

	/* Flags read from the file.
	 */
	VipsFileFlags flags;

	/* The image we've loaded.
	 */
	VipsImage *out;

} VipsFileLoad;

typedef struct _VipsFileLoadClass {
	VipsFileClass parent_class;

	/*< public >*/

	/* Get the flags for this file in this file.
	 */
	VipsFileFlags (*get_flags)( VipsFileLoad * );

} VipsFileLoadClass;

GType vips_file_load_get_type( void );

VipsFileLoad *vips_file_load_new_from_file( const char *filename );

VipsFileLoad *vips_file_for_file( const char *filename );

#define VIPS_TYPE_FILE_SAVE (vips_file_save_get_type())
#define VIPS_FILE_SAVE( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_FILE_SAVE, VipsFileSave ))
#define VIPS_FILE_SAVE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_FILE_SAVE, VipsFileSaveClass))
#define VIPS_IS_FILE_SAVE( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_FILE_SAVE ))
#define VIPS_IS_FILE_SAVE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_FILE_SAVE ))
#define VIPS_FILE_SAVE_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_FILE_SAVE, VipsFileSaveClass ))

typedef struct _VipsFileSave {
	VipsFile parent_object;
	/*< public >*/

	/* The image we are to save.
	 */
	VipsImage *in;

} VipsFileSave;

typedef struct _VipsFileSaveClass {
	VipsFileClass parent_class;

	/*< public >*/

} VipsFileSaveClass;

GType vips_file_save_get_type( void );

VipsFileSave *vips_file_save_new_from_filename( const char *filename )

/* Read/write an image convenience functions.
 */
int vips_file_read( const char *filename, VipsImage *out );
int vips_file_write( VipsImage *in, const char *filename );







#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_FILE_H*/
