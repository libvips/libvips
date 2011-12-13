/* Base type for supported image foreigns. Subclass this to add a new
 * foreign.
 */

/*

    This foreign is part of VIPS.
    
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

    These foreigns are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef VIPS_FOREIGN_H
#define VIPS_FOREIGN_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define VIPS_TYPE_FOREIGN (vips_foreign_get_type())
#define VIPS_FOREIGN( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_FOREIGN, VipsForeign ))
#define VIPS_FOREIGN_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_FOREIGN, VipsForeignClass))
#define VIPS_IS_FOREIGN( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_FOREIGN ))
#define VIPS_IS_FOREIGN_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_FOREIGN ))
#define VIPS_FOREIGN_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_FOREIGN, VipsForeignClass ))

typedef struct _VipsForeign {
	VipsOperation parent_object;
	/*< public >*/

} VipsForeign;

typedef struct _VipsForeignClass {
	VipsOperationClass parent_class;

	/*< public >*/

	/* Loop over formats in this order, default 0. We need this because
	 * some formats can be read by several loaders (eg. tiff can be read
	 * by the libMagick loader as well as by the tiff loader), and we want
	 * to make sure the better loader comes first.
	 */
	int priority;

	/* Null-terminated list of recommended suffixes, eg. ".tif", ".tiff".
	 * This can be used by both load and save, so it's in the base class.
	 */
	const char **suffs;

} VipsForeignClass;

GType vips_foreign_get_type( void );

/* Map over and find formats. This uses type introspection to loop over
 * subclasses of VipsForeign.
 */
void *vips_foreign_map( const char *base, 
	VipsSListMap2Fn fn, void *a, void *b );

/* Image file load properties. 
 */
typedef enum {
	VIPS_FOREIGN_NONE = 0,		/* No flags set */
	VIPS_FOREIGN_PARTIAL = 1,	/* Lazy read OK (eg. tiled tiff) */
	VIPS_FOREIGN_BIGENDIAN = 2,	/* Most-significant byte first */
	VIPS_FOREIGN_ALL = 3		/* All flags set */
} VipsForeignFlags;

#define VIPS_TYPE_FOREIGN_LOAD (vips_foreign_load_get_type())
#define VIPS_FOREIGN_LOAD( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_FOREIGN_LOAD, VipsForeignLoad ))
#define VIPS_FOREIGN_LOAD_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_FOREIGN_LOAD, VipsForeignLoadClass))
#define VIPS_IS_FOREIGN_LOAD( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_FOREIGN_LOAD ))
#define VIPS_IS_FOREIGN_LOAD_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_FOREIGN_LOAD ))
#define VIPS_FOREIGN_LOAD_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_FOREIGN_LOAD, VipsForeignLoadClass ))

typedef struct _VipsForeignLoad {
	VipsForeign parent_object;
	/*< public >*/

	/* Open to disc (default is to open to memory).
	 */
	gboolean disc;

	/* Flags read from the foreign.
	 */
	VipsForeignFlags flags;

	/* The image we generate.
	 */
	VipsImage *out;

	/* The behind-the-scenes real image we decompress to. This can be a
	 * disc foreign or a memory buffer.
	 */
	VipsImage *real;

} VipsForeignLoad;

typedef struct _VipsForeignLoadClass {
	VipsForeignClass parent_class;

	/*< public >*/

	/* Is a file in this format.
	 */
	gboolean (*is_a)( const char * );

	/* Get the flags for this file.
	 */
	VipsForeignFlags (*get_flags)( VipsForeignLoad * );

	/* Set the header fields in @out from @filename. If you can read the 
	 * whole image as well with no performance cost (as with vipsload),
	 * leave ->load() NULL and only @header will be used.
	 *
	 * ->header() needs to set the dhint on the image .. otherwise you get 
	 * the default SMALLTILE.
	 */
	int (*header)( VipsForeignLoad * );

	/* Read the whole image into @real. It gets copied to @out later.
	 */
	int (*load)( VipsForeignLoad * );

} VipsForeignLoadClass;

GType vips_foreign_load_get_type( void );

const char *vips_foreign_find_load( const char *foreignname );

#define VIPS_TYPE_FOREIGN_SAVE (vips_foreign_save_get_type())
#define VIPS_FOREIGN_SAVE( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_FOREIGN_SAVE, VipsForeignSave ))
#define VIPS_FOREIGN_SAVE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_FOREIGN_SAVE, VipsForeignSaveClass))
#define VIPS_IS_FOREIGN_SAVE( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_FOREIGN_SAVE ))
#define VIPS_IS_FOREIGN_SAVE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_FOREIGN_SAVE ))
#define VIPS_FOREIGN_SAVE_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_FOREIGN_SAVE, VipsForeignSaveClass ))

/** 
 * VipsSaveable:
 * @VIPS_SAVEABLE_RGB: 1 or 3 bands (eg. PPM) 
 * @VIPS_SAVEABLE_RGBA: 1, 2, 3 or 4 bands (eg. PNG)
 * @VIPS_SAVEABLE_RGB_CMYK: 1, 3 or 4 bands (eg. JPEG)
 * @VIPS_SAVEABLE_ANY: any number of bands (eg. TIFF)
 *
 * See also: #VipsForeignSave.
 */
typedef enum {
	VIPS_SAVEABLE_RGB,
	VIPS_SAVEABLE_RGBA,
	VIPS_SAVEABLE_RGB_CMYK,
	VIPS_SAVEABLE_ANY,
	VIPS_SAVEABLE_LAST
} VipsSaveable;

typedef struct _VipsForeignSave {
	VipsForeign parent_object;
	/*< public >*/

	/* The image we are to save.
	 */
	VipsImage *in;

	/* The image converted to a saveable format (eg. 8-bit RGB).
	 */
	VipsImage *ready;

} VipsForeignSave;

typedef struct _VipsForeignSaveClass {
	VipsForeignClass parent_class;

	/*< public >*/

	/* How this format treats bands.
	 */
	VipsSaveable saveable;

	/* How this format treats band formats.
	 */
	VipsBandFormat *format_table;
} VipsForeignSaveClass;

GType vips_foreign_save_get_type( void );

const char *vips_foreign_find_save( const char *filename );

/* Read/write an image convenience functions.
 */
int vips_foreign_read( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_foreign_write( VipsImage *in, const char *filename, ... )
	__attribute__((sentinel));

int vips_foreign_read_options( const char *filename, VipsImage **out );
int vips_foreign_write_options( VipsImage *in, const char *filename );

void vips_foreign_operation_init( void );

int vips_openslideload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));

int vips_jpegload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_jpegload_buffer( void *buf, size_t len, VipsImage **out, ... )
	__attribute__((sentinel));

int vips_jpegsave( VipsImage *in, const char *filename, ... )
	__attribute__((sentinel));
int vips_jpegsave_buffer( VipsImage *in, void **buf, size_t *len, ... )
	__attribute__((sentinel));
int vips_jpegsave_mime( VipsImage *in, ... )
	__attribute__((sentinel));

/**
 * VipsForeignTiffCompression:
 * @VIPS_FOREIGN_TIFF_COMPRESSION_NONE: no compression
 * @VIPS_FOREIGN_TIFF_COMPRESSION_JPEG: jpeg compression
 * @VIPS_FOREIGN_TIFF_COMPRESSION_DEFLATE: deflate (zip) compression
 * @VIPS_FOREIGN_TIFF_COMPRESSION_PACKBITS: packbits compression
 * @VIPS_FOREIGN_TIFF_COMPRESSION_CCITTFAX4: fax4 compression
 * @VIPS_FOREIGN_TIFF_COMPRESSION_LZW: LZW compression
 *
 * The compression types supported by the tiff writer.
 *
 * Use @Q to set the jpeg compression level, default 75.
 *
 * Use @prediction to set the lzw or deflate prediction, default none.
 */
typedef enum {
	VIPS_FOREIGN_TIFF_COMPRESSION_NONE,
	VIPS_FOREIGN_TIFF_COMPRESSION_JPEG,
	VIPS_FOREIGN_TIFF_COMPRESSION_DEFLATE,
	VIPS_FOREIGN_TIFF_COMPRESSION_PACKBITS,
	VIPS_FOREIGN_TIFF_COMPRESSION_CCITTFAX4,
	VIPS_FOREIGN_TIFF_COMPRESSION_LZW,
	VIPS_FOREIGN_TIFF_COMPRESSION_LAST
} VipsForeignTiffCompression;

/**
 * VipsForeignTiffPredictor:
 * @VIPS_FOREIGN_TIFF_PREDICTOR_NONE: no prediction
 * @VIPS_FOREIGN_TIFF_PREDICTOR_HORIZONTAL: horizontal differenceing
 * @VIPS_FOREIGN_TIFF_PREDICTOR_FLOAT: float predictor
 *
 * The predictor can help deflate and lzw compression. The values are fixed by
 * the tiff library.
 */
typedef enum {
	VIPS_FOREIGN_TIFF_PREDICTOR_NONE = 1,
	VIPS_FOREIGN_TIFF_PREDICTOR_HORIZONTAL = 2,
	VIPS_FOREIGN_TIFF_PREDICTOR_FLOAT = 3,
	VIPS_FOREIGN_TIFF_PREDICTOR_LAST
} VipsForeignTiffPredictor;

/**
 * VipsForeignTiffResunit:
 * @VIPS_FOREIGN_TIFF_RESUNIT_CM: use centimeters
 * @VIPS_FOREIGN_TIFF_RESUNIT_INCH: use inches
 *
 * Use inches or centimeters as the resolution unit for a tiff file.
 */
typedef enum {
	VIPS_FOREIGN_TIFF_RESUNIT_CM,
	VIPS_FOREIGN_TIFF_RESUNIT_INCH,
	VIPS_FOREIGN_TIFF_RESUNIT_LAST
} VipsForeignTiffResunit;

int vips_tiffload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_tiffsave( VipsImage *in, const char *filename, ... )
	__attribute__((sentinel));

int vips_openexrload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_FOREIGN_H*/
