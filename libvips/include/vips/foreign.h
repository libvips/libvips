/* Base type for supported image formats. Subclass this to add a new
 * format.
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

#ifndef VIPS_FOREIGN_H
#define VIPS_FOREIGN_H

#include <glib.h>
#include <glib-object.h>
#include <vips/object.h>
#include <vips/operation.h>

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

/* Don't put spaces around void here, it breaks gtk-doc.
 */
VIPS_API
GType vips_foreign_get_type(void);

/* Map over and find formats. This uses type introspection to loop over
 * subclasses of VipsForeign.
 */
VIPS_API
void *vips_foreign_map( const char *base, 
	VipsSListMap2Fn fn, void *a, void *b );

/* Image file load properties. 
 *
 * Keep in sync with the deprecated VipsFormatFlags, we need to be able to
 * cast between them.
 */
typedef enum /*< flags >*/ {
	VIPS_FOREIGN_NONE = 0,		/* No flags set */
	VIPS_FOREIGN_PARTIAL = 1,	/* Lazy read OK (eg. tiled tiff) */
	VIPS_FOREIGN_BIGENDIAN = 2,	/* Most-significant byte first */
	VIPS_FOREIGN_SEQUENTIAL = 4,	/* Top-to-bottom lazy read OK */
	VIPS_FOREIGN_ALL = 7		/* All flags set */
} VipsForeignFlags;

/** 
 * VipsFailOn:
 * @VIPS_FAIL_ON_NONE: never stop 
 * @VIPS_FAIL_ON_TRUNCATED: stop on image truncated, nothing else
 * @VIPS_FAIL_ON_ERROR: stop on serious error or truncation
 * @VIPS_FAIL_ON_WARNING: stop on anything, even warnings
 *
 * How sensitive loaders are to errors, from never stop (very insensitive), to 
 * stop on the smallest warning (very sensitive). 
 * 
 * Each one implies the ones before it, so #VIPS_FAIL_ON_ERROR implies
 * #VIPS_FAIL_ON_TRUNCATED.
 */
typedef enum {
	VIPS_FAIL_ON_NONE,
	VIPS_FAIL_ON_TRUNCATED,
	VIPS_FAIL_ON_ERROR,
	VIPS_FAIL_ON_WARNING,
	VIPS_FAIL_ON_LAST
} VipsFailOn;

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
	/*< private >*/

	/* Set TRUE to force open via memory. 
	 */
	gboolean memory;

	/* Type of access upstream wants and the loader must supply. 
	 */
	VipsAccess access;

	/* Flags for this load operation.
	 */
	VipsForeignFlags flags;

	/* Behaviour on error.
	 */
	VipsFailOn fail_on;

	/* Deprecated and unused. Just here for compat.
	 */
	gboolean fail;
	gboolean sequential;

	/*< public >*/

	/* The image we generate. This must be set by ->header().
	 */
	VipsImage *out;

	/* The behind-the-scenes real image we decompress to. This can be a
	 * disc file or a memory buffer. This must be set by ->load().
	 */
	VipsImage *real;

	/* Set this to tag the operation as nocache.
	 */
	gboolean nocache;

	/* Deprecated: the memory option used to be called disc and default
	 * TRUE.
	 */
	gboolean disc;

	/* Set if a start function fails. We want to prevent the other starts
	 * from also triggering the load.
	 */
	gboolean error;
} VipsForeignLoad;

typedef struct _VipsForeignLoadClass {
	VipsForeignClass parent_class;
	/*< public >*/

	/* Is a file in this format. 
	 *
	 * This function should return %TRUE if the file contains an image of 
	 * this type. If you don't define this function, #VipsForeignLoad
	 * will use @suffs instead.
	 */
	gboolean (*is_a)( const char *filename );

	/* Is a buffer in this format. 
	 *
	 * This function should return %TRUE if the buffer contains an image of 
	 * this type. 
	 */
	gboolean (*is_a_buffer)( const void *data, size_t size );

	/* Is a stream in this format. 
	 *
	 * This function should return %TRUE if the stream contains an image of 
	 * this type. 
	 */
	gboolean (*is_a_source)( VipsSource *source );

	/* Get the flags from a filename. 
	 *
	 * This function should examine the file and return a set
	 * of flags. If you don't define it, vips will default to 0 (no flags 
	 * set).  
	 *
	 * This method is necessary for vips7 compatibility. Don't define
	 * it if you don't need vips7.
	 */
	VipsForeignFlags (*get_flags_filename)( const char *filename );

	/* Get the flags for this load operation. Images can be loaded from 
	 * (for example) memory areas rather than files, so you can't just use
	 * @get_flags_filename().
	 */
	VipsForeignFlags (*get_flags)( VipsForeignLoad *load );

	/* Do the minimum read we can. 
	 *
	 * Set the header fields in @out from @filename. If you can read the 
	 * whole image as well with no performance cost (as with vipsload),
	 * or if your loader does not support reading only the header, read
	 * the entire image in this method and leave @load() NULL.
	 *
	 * @header() needs to set the dhint on the image .. otherwise you get 
	 * the default SMALLTILE.
	 *
	 * Return 0 for success, -1 for error, setting vips_error().
	 */
	int (*header)( VipsForeignLoad *load );

	/* Read the whole image into @real. The pixels will get copied to @out 
	 * later.
	 *
	 * You can omit this method if you define a @header() method which 
	 * loads the whole file. 
	 *
	 * Return 0 for success, -1 for error, setting
	 * vips_error().
	 */
	int (*load)( VipsForeignLoad *load );
} VipsForeignLoadClass;

/* Don't put spaces around void here, it breaks gtk-doc.
 */
VIPS_API
GType vips_foreign_load_get_type(void);

VIPS_API
const char *vips_foreign_find_load( const char *filename );
VIPS_API
const char *vips_foreign_find_load_buffer( const void *data, size_t size );
VIPS_API
const char *vips_foreign_find_load_source( VipsSource *source );

VIPS_API
VipsForeignFlags vips_foreign_flags( const char *loader, const char *filename );
VIPS_API
gboolean vips_foreign_is_a( const char *loader, const char *filename );
VIPS_API
gboolean vips_foreign_is_a_buffer( const char *loader, 
	const void *data, size_t size );
VIPS_API
gboolean vips_foreign_is_a_source( const char *loader, 
	VipsSource *source );

VIPS_API
void vips_foreign_load_invalidate( VipsImage *image );

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
 * @VIPS_SAVEABLE_MONO: 1 band (eg. CSV)
 * @VIPS_SAVEABLE_RGB: 1 or 3 bands (eg. PPM) 
 * @VIPS_SAVEABLE_RGBA: 1, 2, 3 or 4 bands (eg. PNG)
 * @VIPS_SAVEABLE_RGBA_ONLY: 3 or 4 bands (eg. WEBP)
 * @VIPS_SAVEABLE_RGB_CMYK: 1, 3 or 4 bands (eg. JPEG)
 * @VIPS_SAVEABLE_ANY: any number of bands (eg. TIFF)
 *
 * See also: #VipsForeignSave.
 */
typedef enum {
	VIPS_SAVEABLE_MONO,
	VIPS_SAVEABLE_RGB,
	VIPS_SAVEABLE_RGBA,
	VIPS_SAVEABLE_RGBA_ONLY,
	VIPS_SAVEABLE_RGB_CMYK,
	VIPS_SAVEABLE_ANY,
	VIPS_SAVEABLE_LAST
} VipsSaveable;

typedef struct _VipsForeignSave {
	VipsForeign parent_object;

	/* Don't attach metadata.
	 */
	gboolean strip;

	/* If flattening out alpha, the background colour to use. Default to
	 * 0 (black).
	 */
	VipsArrayDouble *background;

	/* Set to non-zero to set the page size for multi-page save.
	 */
	int page_height;

	/*< public >*/

	/* The image we are to save, as supplied by our caller. 
	 */
	VipsImage *in;

	/* @in converted to a saveable format (eg. 8-bit RGB) according to the
	 * instructions you give in the class fields below.
	 *
	 * This is the image you should actually write to the output.
	 */
	VipsImage *ready;

} VipsForeignSave;

typedef struct _VipsForeignSaveClass {
	VipsForeignClass parent_class;

	/*< public >*/

	/* How this format treats bands.
	 *
	 * @saveable describes the bands that your saver can handle. For 
	 * example, PPM images can have 1 or 3 bands (mono or RGB), so it 
	 * uses #VIPS_SAVEABLE_RGB.
	 */
	VipsSaveable saveable;

	/* How this format treats band formats.
	 *
	 * @format_table describes the band formats that your saver can 
	 * handle. For each of the 10 #VipsBandFormat values, the array 
	 * should give the format your saver will accept. 
	 */
	VipsBandFormat *format_table;

	/* The set of coding types this format can save. For example, jpeg can
	 * only save NONE, so has NONE TRUE and RAD and LABQ FALSE.
	 *
	 * Default NONE TRUE, RAD and LABQ FALSE.
	 */
	gboolean coding[VIPS_CODING_LAST];
} VipsForeignSaveClass;

/* Don't put spaces around void here, it breaks gtk-doc.
 */
VIPS_API
GType vips_foreign_save_get_type(void);

VIPS_API
const char *vips_foreign_find_save( const char *filename );
VIPS_API
gchar **vips_foreign_get_suffixes( void );
VIPS_API
const char *vips_foreign_find_save_buffer( const char *suffix );
VIPS_API
const char *vips_foreign_find_save_target( const char *suffix );

VIPS_API
int vips_vipsload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_vipsload_source( VipsSource *source, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_vipssave( VipsImage *in, const char *filename, ... )
	__attribute__((sentinel));
VIPS_API
int vips_vipssave_target( VipsImage *in, VipsTarget *target, ... )
	__attribute__((sentinel));

VIPS_API
int vips_openslideload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_openslideload_source( VipsSource *source, VipsImage **out, ... )
	__attribute__((sentinel));

/**
 * VipsForeignSubsample:
 * @VIPS_FOREIGN_SUBSAMPLE_AUTO: prevent subsampling when quality >= 90
 * @VIPS_FOREIGN_SUBSAMPLE_ON: always perform subsampling
 * @VIPS_FOREIGN_SUBSAMPLE_OFF: never perform subsampling
 *
 * Set subsampling mode.
 */
typedef enum {
	VIPS_FOREIGN_SUBSAMPLE_AUTO,
	VIPS_FOREIGN_SUBSAMPLE_ON,
	VIPS_FOREIGN_SUBSAMPLE_OFF,
	VIPS_FOREIGN_SUBSAMPLE_LAST
} VipsForeignSubsample;

/**
 * VipsForeignJpegSubsample:
 * @VIPS_FOREIGN_JPEG_SUBSAMPLE_AUTO: default preset
 * @VIPS_FOREIGN_JPEG_SUBSAMPLE_ON: always perform subsampling
 * @VIPS_FOREIGN_JPEG_SUBSAMPLE_OFF: never perform subsampling
 *
 * Set jpeg subsampling mode.
 *
 * DEPRECATED: use #VipsForeignSubsample
 */
typedef enum {
	VIPS_FOREIGN_JPEG_SUBSAMPLE_AUTO,
	VIPS_FOREIGN_JPEG_SUBSAMPLE_ON,
	VIPS_FOREIGN_JPEG_SUBSAMPLE_OFF,
	VIPS_FOREIGN_JPEG_SUBSAMPLE_LAST
} VipsForeignJpegSubsample;

VIPS_API
int vips_jpegload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_jpegload_buffer( void *buf, size_t len, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_jpegload_source( VipsSource *source, VipsImage **out, ... )
	__attribute__((sentinel));

VIPS_API
int vips_jpegsave_target( VipsImage *in, VipsTarget *target, ... )
	__attribute__((sentinel));
VIPS_API
int vips_jpegsave( VipsImage *in, const char *filename, ... )
	__attribute__((sentinel));
VIPS_API
int vips_jpegsave_buffer( VipsImage *in, void **buf, size_t *len, ... )
	__attribute__((sentinel));
VIPS_API
int vips_jpegsave_mime( VipsImage *in, ... )
	__attribute__((sentinel));

/**
 * VipsForeignWebpPreset:
 * @VIPS_FOREIGN_WEBP_PRESET_DEFAULT: default preset
 * @VIPS_FOREIGN_WEBP_PRESET_PICTURE: digital picture, like portrait, inner shot
 * @VIPS_FOREIGN_WEBP_PRESET_PHOTO: outdoor photograph, with natural lighting
 * @VIPS_FOREIGN_WEBP_PRESET_DRAWING: hand or line drawing, with high-contrast details
 * @VIPS_FOREIGN_WEBP_PRESET_ICON: small-sized colorful images
 * @VIPS_FOREIGN_WEBP_PRESET_TEXT: text-like
 *
 * Tune lossy encoder settings for different image types.
 */
typedef enum {
	VIPS_FOREIGN_WEBP_PRESET_DEFAULT,
	VIPS_FOREIGN_WEBP_PRESET_PICTURE,
	VIPS_FOREIGN_WEBP_PRESET_PHOTO,
	VIPS_FOREIGN_WEBP_PRESET_DRAWING,
	VIPS_FOREIGN_WEBP_PRESET_ICON,
	VIPS_FOREIGN_WEBP_PRESET_TEXT,
	VIPS_FOREIGN_WEBP_PRESET_LAST
} VipsForeignWebpPreset;

VIPS_API
int vips_webpload_source( VipsSource *source, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_webpload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_webpload_buffer( void *buf, size_t len, VipsImage **out, ... )
	__attribute__((sentinel));

VIPS_API
int vips_webpsave_target( VipsImage *in, VipsTarget *target, ... )
	__attribute__((sentinel));
VIPS_API
int vips_webpsave( VipsImage *in, const char *filename, ... )
	__attribute__((sentinel));
VIPS_API
int vips_webpsave_buffer( VipsImage *in, void **buf, size_t *len, ... )
	__attribute__((sentinel));
VIPS_API
int vips_webpsave_mime( VipsImage *in, ... )
	__attribute__((sentinel));

/**
 * VipsForeignTiffCompression:
 * @VIPS_FOREIGN_TIFF_COMPRESSION_NONE: no compression
 * @VIPS_FOREIGN_TIFF_COMPRESSION_JPEG: jpeg compression
 * @VIPS_FOREIGN_TIFF_COMPRESSION_DEFLATE: deflate (zip) compression
 * @VIPS_FOREIGN_TIFF_COMPRESSION_PACKBITS: packbits compression
 * @VIPS_FOREIGN_TIFF_COMPRESSION_CCITTFAX4: fax4 compression
 * @VIPS_FOREIGN_TIFF_COMPRESSION_LZW: LZW compression
 * @VIPS_FOREIGN_TIFF_COMPRESSION_WEBP: WEBP compression
 * @VIPS_FOREIGN_TIFF_COMPRESSION_ZSTD: ZSTD compression
 * @VIPS_FOREIGN_TIFF_COMPRESSION_JP2K: JP2K compression
 *
 * The compression types supported by the tiff writer.
 *
 * Use @Q to set the jpeg compression level, default 75.
 *
 * Use @predictor to set the lzw or deflate prediction, default horizontal.
 *
 * Use @lossless to set WEBP lossless compression.
 *
 * Use @level to set webp and zstd compression level.
 */
typedef enum {
	VIPS_FOREIGN_TIFF_COMPRESSION_NONE,
	VIPS_FOREIGN_TIFF_COMPRESSION_JPEG,
	VIPS_FOREIGN_TIFF_COMPRESSION_DEFLATE,
	VIPS_FOREIGN_TIFF_COMPRESSION_PACKBITS,
	VIPS_FOREIGN_TIFF_COMPRESSION_CCITTFAX4,
	VIPS_FOREIGN_TIFF_COMPRESSION_LZW,
	VIPS_FOREIGN_TIFF_COMPRESSION_WEBP,
	VIPS_FOREIGN_TIFF_COMPRESSION_ZSTD,
	VIPS_FOREIGN_TIFF_COMPRESSION_JP2K,
	VIPS_FOREIGN_TIFF_COMPRESSION_LAST
} VipsForeignTiffCompression;

/**
 * VipsForeignTiffPredictor:
 * @VIPS_FOREIGN_TIFF_PREDICTOR_NONE: no prediction
 * @VIPS_FOREIGN_TIFF_PREDICTOR_HORIZONTAL: horizontal differencing
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

VIPS_API
int vips_tiffload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_tiffload_buffer( void *buf, size_t len, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_tiffload_source( VipsSource *source, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_tiffsave( VipsImage *in, const char *filename, ... )
	__attribute__((sentinel));
VIPS_API
int vips_tiffsave_buffer( VipsImage *in, void **buf, size_t *len, ... )
	__attribute__((sentinel));
VIPS_API
int vips_tiffsave_target( VipsImage *in, VipsTarget *target, ... )
	__attribute__((sentinel));

VIPS_API
int vips_openexrload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));

VIPS_API
int vips_fitsload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_fitssave( VipsImage *in, const char *filename, ... )
	__attribute__((sentinel));

VIPS_API
int vips_analyzeload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));

VIPS_API
int vips_rawload( const char *filename, VipsImage **out, 
	int width, int height, int bands, ... )
	__attribute__((sentinel));
VIPS_API
int vips_rawsave( VipsImage *in, const char *filename, ... )
	__attribute__((sentinel));
VIPS_API
int vips_rawsave_fd( VipsImage *in, int fd, ... )
	__attribute__((sentinel));

VIPS_API
int vips_csvload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_csvload_source( VipsSource *source, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_csvsave( VipsImage *in, const char *filename, ... )
	__attribute__((sentinel));
VIPS_API
int vips_csvsave_target( VipsImage *in, VipsTarget *target, ... )
	__attribute__((sentinel));

VIPS_API
int vips_matrixload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_matrixload_source( VipsSource *source, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_matrixsave( VipsImage *in, const char *filename, ... )
	__attribute__((sentinel));
VIPS_API
int vips_matrixsave_target( VipsImage *in, VipsTarget *target, ... )
	__attribute__((sentinel));
VIPS_API
int vips_matrixprint( VipsImage *in, ... )
	__attribute__((sentinel));

VIPS_API
int vips_magickload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_magickload_buffer( void *buf, size_t len, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_magicksave( VipsImage *in, const char *filename, ... )
	__attribute__((sentinel));
VIPS_API
int vips_magicksave_buffer( VipsImage *in, void **buf, size_t *len, ... )
	__attribute__((sentinel));

/**
 * VipsForeignPngFilter:
 * @VIPS_FOREIGN_PNG_FILTER_NONE: no filtering
 * @VIPS_FOREIGN_PNG_FILTER_SUB: difference to the left
 * @VIPS_FOREIGN_PNG_FILTER_UP: difference up
 * @VIPS_FOREIGN_PNG_FILTER_AVG: average of left and up
 * @VIPS_FOREIGN_PNG_FILTER_PAETH: pick best neighbor predictor automatically
 * @VIPS_FOREIGN_PNG_FILTER_ALL: adaptive
 *
 * http://www.w3.org/TR/PNG-Filters.html
 * The values mirror those of png.h in libpng.
 */
typedef enum /*< flags >*/ {
	VIPS_FOREIGN_PNG_FILTER_NONE = 0x08,
	VIPS_FOREIGN_PNG_FILTER_SUB = 0x10,
	VIPS_FOREIGN_PNG_FILTER_UP = 0x20,
	VIPS_FOREIGN_PNG_FILTER_AVG = 0x40,
	VIPS_FOREIGN_PNG_FILTER_PAETH = 0x80,
	VIPS_FOREIGN_PNG_FILTER_ALL = 0xF8
} VipsForeignPngFilter;

VIPS_API
int vips_pngload_source( VipsSource *source, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_pngload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_pngload_buffer( void *buf, size_t len, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_pngsave_target( VipsImage *in, VipsTarget *target, ... )
	__attribute__((sentinel));
VIPS_API
int vips_pngsave( VipsImage *in, const char *filename, ... )
	__attribute__((sentinel));
VIPS_API
int vips_pngsave_buffer( VipsImage *in, void **buf, size_t *len, ... )
	__attribute__((sentinel));

/**
 * VipsForeignPpmFormat:
 * @VIPS_FOREIGN_PPM_FORMAT_PBM: portable bitmap
 * @VIPS_FOREIGN_PPM_FORMAT_PGM: portable greymap
 * @VIPS_FOREIGN_PPM_FORMAT_PPM: portable pixmap
 * @VIPS_FOREIGN_PPM_FORMAT_PFM: portable float map
 *
 * The netpbm file format to save as.
 *
 * #VIPS_FOREIGN_PPM_FORMAT_PBM images are single bit.
 *
 * #VIPS_FOREIGN_PPM_FORMAT_PGM images are 8, 16, or 32-bits, one band.
 *
 * #VIPS_FOREIGN_PPM_FORMAT_PPM images are 8, 16, or 32-bits, three bands.
 *
 * #VIPS_FOREIGN_PPM_FORMAT_PFM images are 32-bit float pixels.
 */
typedef enum {
	VIPS_FOREIGN_PPM_FORMAT_PBM,
	VIPS_FOREIGN_PPM_FORMAT_PGM,
	VIPS_FOREIGN_PPM_FORMAT_PPM,
	VIPS_FOREIGN_PPM_FORMAT_PFM,
	VIPS_FOREIGN_PPM_FORMAT_LAST
} VipsForeignPpmFormat;

VIPS_API
int vips_ppmload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_ppmload_source( VipsSource *source, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_ppmsave( VipsImage *in, const char *filename, ... )
	__attribute__((sentinel));
VIPS_API
int vips_ppmsave_target( VipsImage *in, VipsTarget *target, ... )
	__attribute__((sentinel));

VIPS_API
int vips_matload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));

VIPS_API
int vips_radload_source( VipsSource *source, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_radload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_radload_buffer( void *buf, size_t len, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_radsave( VipsImage *in, const char *filename, ... )
	__attribute__((sentinel));
VIPS_API
int vips_radsave_buffer( VipsImage *in, void **buf, size_t *len, ... )
	__attribute__((sentinel));
VIPS_API
int vips_radsave_target( VipsImage *in, VipsTarget *target, ... )
	__attribute__((sentinel));

VIPS_API
int vips_pdfload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_pdfload_buffer( void *buf, size_t len, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_pdfload_source( VipsSource *source, VipsImage **out, ... )
	__attribute__((sentinel));

VIPS_API
int vips_svgload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_svgload_buffer( void *buf, size_t len, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_svgload_string( const char *str, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_svgload_source( VipsSource *source, VipsImage **out, ... )
	__attribute__((sentinel));

VIPS_API
int vips_gifload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_gifload_buffer( void *buf, size_t len, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_gifload_source( VipsSource *source, VipsImage **out, ... )
	__attribute__((sentinel));

VIPS_API
int vips_gifsave( VipsImage *in, const char *filename, ... )
	__attribute__((sentinel));
VIPS_API
int vips_gifsave_buffer( VipsImage *in, void **buf, size_t *len, ... )
	__attribute__((sentinel));
VIPS_API
int vips_gifsave_target( VipsImage *in, VipsTarget *target, ... )
	__attribute__((sentinel));

VIPS_API
int vips_heifload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_heifload_buffer( void *buf, size_t len, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_heifload_source( VipsSource *source, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_heifsave( VipsImage *in, const char *filename, ... )
	__attribute__((sentinel));
VIPS_API
int vips_heifsave_buffer( VipsImage *in, void **buf, size_t *len, ... )
	__attribute__((sentinel));
VIPS_API
int vips_heifsave_target( VipsImage *in, VipsTarget *target, ... )
	__attribute__((sentinel));

VIPS_API
int vips_niftiload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_niftiload_source( VipsSource *source, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_niftisave( VipsImage *in, const char *filename, ... )
	__attribute__((sentinel));

VIPS_API
int vips_jp2kload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_jp2kload_buffer( void *buf, size_t len, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_jp2kload_source( VipsSource *source, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_jp2ksave( VipsImage *in, const char *filename, ... )
	__attribute__((sentinel));
VIPS_API
int vips_jp2ksave_buffer( VipsImage *in, void **buf, size_t *len, ... )
	__attribute__((sentinel));
VIPS_API
int vips_jp2ksave_target( VipsImage *in, VipsTarget *target, ... )
	__attribute__((sentinel));

VIPS_API
int vips_jxlload_source( VipsSource *source, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_jxlload_buffer( void *buf, size_t len, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_jxlload( const char *filename, VipsImage **out, ... )
	__attribute__((sentinel));
VIPS_API
int vips_jxlsave( VipsImage *in, const char *filename, ... )
	__attribute__((sentinel));
VIPS_API
int vips_jxlsave_buffer( VipsImage *in, void **buf, size_t *len, ... )
	__attribute__((sentinel));
VIPS_API
int vips_jxlsave_target( VipsImage *in, VipsTarget *target, ... )
	__attribute__((sentinel));

/**
 * VipsForeignDzLayout:
 * @VIPS_FOREIGN_DZ_LAYOUT_DZ: use DeepZoom directory layout
 * @VIPS_FOREIGN_DZ_LAYOUT_ZOOMIFY: use Zoomify directory layout
 * @VIPS_FOREIGN_DZ_LAYOUT_GOOGLE: use Google maps directory layout
 * @VIPS_FOREIGN_DZ_LAYOUT_IIIF: use IIIF v2 directory layout
 * @VIPS_FOREIGN_DZ_LAYOUT_IIIF3: use IIIF v3 directory layout
 *
 * What directory layout and metadata standard to use. 
 */
typedef enum {
	VIPS_FOREIGN_DZ_LAYOUT_DZ,
	VIPS_FOREIGN_DZ_LAYOUT_ZOOMIFY,
	VIPS_FOREIGN_DZ_LAYOUT_GOOGLE,
	VIPS_FOREIGN_DZ_LAYOUT_IIIF,
	VIPS_FOREIGN_DZ_LAYOUT_IIIF3,
	VIPS_FOREIGN_DZ_LAYOUT_LAST
} VipsForeignDzLayout;

/**
 * VipsForeignDzDepth:
 * @VIPS_FOREIGN_DZ_DEPTH_ONEPIXEL: create layers down to 1x1 pixel
 * @VIPS_FOREIGN_DZ_DEPTH_ONETILE: create layers down to 1x1 tile
 * @VIPS_FOREIGN_DZ_DEPTH_ONE: only create a single layer
 *
 * How many pyramid layers to create.
 */
typedef enum {
	VIPS_FOREIGN_DZ_DEPTH_ONEPIXEL,
	VIPS_FOREIGN_DZ_DEPTH_ONETILE,
	VIPS_FOREIGN_DZ_DEPTH_ONE,
	VIPS_FOREIGN_DZ_DEPTH_LAST
} VipsForeignDzDepth;

/**
 * VipsForeignDzContainer:
 * @VIPS_FOREIGN_DZ_CONTAINER_FS: write tiles to the filesystem
 * @VIPS_FOREIGN_DZ_CONTAINER_ZIP: write tiles to a zip file
 * @VIPS_FOREIGN_DZ_CONTAINER_SZI: write to a szi file
 *
 * How many pyramid layers to create.
 */
typedef enum {
	VIPS_FOREIGN_DZ_CONTAINER_FS,
	VIPS_FOREIGN_DZ_CONTAINER_ZIP,
	VIPS_FOREIGN_DZ_CONTAINER_SZI,
	VIPS_FOREIGN_DZ_CONTAINER_LAST
} VipsForeignDzContainer;

VIPS_API
int vips_dzsave( VipsImage *in, const char *name, ... )
	__attribute__((sentinel));
VIPS_API
int vips_dzsave_buffer( VipsImage *in, void **buf, size_t *len, ... )
	__attribute__((sentinel));
VIPS_API
int vips_dzsave_target( VipsImage *in, VipsTarget *target, ... )
	__attribute__((sentinel));

/**
 * VipsForeignHeifCompression:
 * @VIPS_FOREIGN_HEIF_COMPRESSION_HEVC: x265
 * @VIPS_FOREIGN_HEIF_COMPRESSION_AVC: x264
 * @VIPS_FOREIGN_HEIF_COMPRESSION_JPEG: jpeg
 * @VIPS_FOREIGN_HEIF_COMPRESSION_AV1: aom
 *
 * The compression format to use inside a HEIF container. 
 *
 * This is assumed to use the same numbering as %heif_compression_format.
 */
typedef enum {
	VIPS_FOREIGN_HEIF_COMPRESSION_HEVC = 1,
	VIPS_FOREIGN_HEIF_COMPRESSION_AVC = 2,
	VIPS_FOREIGN_HEIF_COMPRESSION_JPEG = 3,
	VIPS_FOREIGN_HEIF_COMPRESSION_AV1 = 4,
	VIPS_FOREIGN_HEIF_COMPRESSION_LAST
} VipsForeignHeifCompression;

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_FOREIGN_H*/
