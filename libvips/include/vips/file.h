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

#ifndef VIPS_FILE_H
#define VIPS_FILE_H

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

	/* Loop over files in this order, default 0. We need this because
	 * some files can be read by several loaders (eg. tiff can be read
	 * by the libMagick loader as well as by the tiff loader), and we want
	 * to make sure the better loader comes first.
	 */
	int priority;

	/* Null-terminated list of recommended suffixes, eg. ".tif", ".tiff".
	 * This can be used by both load and save, so it's in the base class.
	 */
	const char **suffs;

} VipsFileClass;

GType vips_file_get_type( void );

/* Map over and find files. This uses type introspection to loop over
 * subclasses of VipsFile.
 */
void *vips_file_map( const char *base, VipsSListMap2Fn fn, void *a, void *b );

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
	VIPS_FILE_NONE = 0,	/* No flags set */
	VIPS_FILE_PARTIAL = 1,	/* Lazy read OK (eg. tiled tiff) */
	VIPS_FILE_BIGENDIAN = 2	/* Most-significant byte first */
} VipsFileFlags;

typedef struct _VipsFileLoad {
	VipsFile parent_object;
	/*< public >*/

	/* Open to disc (default is to open to memory).
	 */
	gboolean disc;

	/* Flags read from the file.
	 */
	VipsFileFlags flags;

	/* The image we generate.
	 */
	VipsImage *out;

	/* The behind-the-scenes real image we decompress to. This can be a
	 * disc file or a memory buffer.
	 */
	VipsImage *real;

} VipsFileLoad;

typedef struct _VipsFileLoadClass {
	VipsFileClass parent_class;

	/*< public >*/

	/* Is a file in this format.
	 */
	gboolean (*is_a)( const char * );

	/* Get the flags for this file.
	 */
	int (*get_flags)( VipsFileLoad * );

	/* Set the header fields in @out from @filename. If you can read the 
	 * whole image as well with no performance cost (as with vipsload),
	 * leave ->load() NULL and only @header will be used.
	 */
	int (*header)( VipsFileLoad * );

	/* Read the whole image into @real. It gets copied to @out later.
	 */
	int (*load)( VipsFileLoad * );

} VipsFileLoadClass;

GType vips_file_load_get_type( void );

const char *vips_file_find_load( const char *filename );

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

/** 
 * VipsSaveable:
 * @VIPS_SAVEABLE_RGB: 1 or 3 bands (eg. PPM) 
 * @VIPS_SAVEABLE_RGBA: 1, 2, 3 or 4 bands (eg. PNG)
 * @VIPS_SAVEABLE_RGB_CMYK: 1, 3 or 4 bands (eg. JPEG)
 * @VIPS_SAVEABLE_ANY: any number of bands (eg. TIFF)
 *
 * See also: #VipsFileSave.
 */
typedef enum {
	VIPS_SAVEABLE_RGB,
	VIPS_SAVEABLE_RGBA,
	VIPS_SAVEABLE_RGB_CMYK,
	VIPS_SAVEABLE_ANY,
	VIPS_SAVEABLE_LAST
} VipsSaveable;

typedef struct _VipsFileSave {
	VipsFile parent_object;
	/*< public >*/

	/* The image we are to save.
	 */
	VipsImage *in;

	/* The image converted to a saveable format (eg. 8-bit RGB).
	 */
	VipsImage *ready;

} VipsFileSave;

typedef struct _VipsFileSaveClass {
	VipsFileClass parent_class;

	/*< public >*/

	/* How this format treats bands.
	 */
	VipsSaveable saveable;

	/* How this format treats band formats.
	 */
	VipsBandFormat *format_table;
} VipsFileSaveClass;

GType vips_file_save_get_type( void );

const char *vips_file_find_save( const char *filename );

/* Read/write an image convenience functions.
 */
int vips_file_read( const char *filename, VipsImage **out, ... );
int vips_file_write( VipsImage *in, const char *filename, ... );

void vips_file_operation_init( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_FILE_H*/
