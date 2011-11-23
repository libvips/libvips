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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef IM_FORMAT_H
#define IM_FORMAT_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define VIPS_TYPE_FORMAT (vips_format_get_type())
#define VIPS_FORMAT( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_FORMAT, VipsFormat ))
#define VIPS_FORMAT_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_FORMAT, VipsFormatClass))
#define VIPS_IS_FORMAT( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_FORMAT ))
#define VIPS_IS_FORMAT_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_FORMAT ))
#define VIPS_FORMAT_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_FORMAT, VipsFormatClass ))

typedef struct _VipsFormat {
	VipsObject parent_object;
	/*< public >*/

	/* Filename for load or save.
	 */
	char *filename; 

} VipsFormat;

typedef struct _VipsFormatClass {
	VipsObjectClass parent_class;

	/*< public >*/
	/* Is a file in this format.
	 */
	gboolean (*is_a)( const char * );

	/* Null-terminated list of allowed suffixes, eg. ".tif", ".tiff".
	 */
	const char **suffs;

	/* Loop over formats in this order, default 0. We need this because
	 * some formats can be read by several loaders (eg. tiff can be read
	 * by the libMagick loader as well as by the tiff loader), and we want
	 * to make sure the better loader comes first.
	 */
	int priority;

} VipsFormatClass;

GType vips_format_get_type( void );

/* Map over and find formats. This uses type introspection to loop over
 * subclasses of VipsFormat.
 */
void *vips_format_map( VipsSListMap2Fn fn, void *a, void *b );

#define VIPS_TYPE_FORMAT_LOAD (vips_format_load_get_type())
#define VIPS_FORMAT_LOAD( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_FORMAT_LOAD, VipsFormatLoad ))
#define VIPS_FORMAT_LOAD_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_FORMAT_LOAD, VipsFormatLoadClass))
#define VIPS_IS_FORMAT_LOAD( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_FORMAT_LOAD ))
#define VIPS_IS_FORMAT_LOAD_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_FORMAT_LOAD ))
#define VIPS_FORMAT_LOAD_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_FORMAT_LOAD, VipsFormatLoadClass ))

/* Image file properties. 
 */
typedef enum {
	VIPS_FORMAT_NONE = 0,		/* No flags set */
	VIPS_FORMAT_PARTIAL = 1,	/* Lazy read OK (eg. tiled tiff) */
	VIPS_FORMAT_BIGENDIAN = 2	/* Most-significant byte first */
} VipsFormatFlags;

typedef struct _VipsFormatLoad {
	VipsFormat parent_object;
	/*< public >*/

	/* Flags read from the file.
	 */
	VipsFormatFlags flags;

	/* The image we've loaded.
	 */
	VipsImage *out;

} VipsFormatLoad;

typedef struct _VipsFormatLoadClass {
	VipsFormatClass parent_class;

	/*< public >*/

	/* Get the flags for this file in this format.
	 */
	VipsFormatFlags (*get_flags)( VipsFormatLoad * );

	/* Load just the header.
	 */
	int (*header)( VipsFormatLoad * );

	/* Load the whole image.
	 */
	int (*load)( VipsFormatLoad * );

} VipsFormatLoadClass;

GType vips_format_load_get_type( void );

VipsFormatFlags vips_format_get_flags( VipsFormatClass *format, 
	const char *filename );

VipsFormatLoad *vips_format_for_file( const char *filename );

#define VIPS_TYPE_FORMAT_SAVE (vips_format_save_get_type())
#define VIPS_FORMAT_SAVE( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_FORMAT_SAVE, VipsFormatSave ))
#define VIPS_FORMAT_SAVE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_FORMAT_SAVE, VipsFormatSaveClass))
#define VIPS_IS_FORMAT_SAVE( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_FORMAT_SAVE ))
#define VIPS_IS_FORMAT_SAVE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_FORMAT_SAVE ))
#define VIPS_FORMAT_SAVE_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_FORMAT_SAVE, VipsFormatSaveClass ))

typedef struct _VipsFormatSave {
	VipsFormat parent_object;
	/*< public >*/

} VipsFormatSave;

typedef struct _VipsFormatSaveClass {
	VipsFormatClass parent_class;

	/*< public >*/

	/* Write the VipsImage to the file in this format.
	 */
	int (*save)( VipsImage * );

} VipsFormatSaveClass;

GType vips_format_save_get_type( void );

VipsFormatSave *vips_format_for_name( const char *filename );

/* Read/write an image convenience functions.
 */
int vips_format_read( const char *filename, VipsImage *out );
int vips_format_write( VipsImage *in, const char *filename );







/* Low-level read/write operations.
 */
int im_jpeg2vips( const char *filename, VipsImage *out );
int im_bufjpeg2vips( void *buf, size_t len, 
	VipsImage *out, gboolean header_only );
int im_vips2jpeg( VipsImage *in, const char *filename );
int im_vips2mimejpeg( VipsImage *in, int qfac );
int im_vips2bufjpeg( VipsImage *in, VipsImage *out, 
	int qfac, char **obuf, int *olen );

int im_tiff2vips( const char *filename, VipsImage *out );
int im_vips2tiff( VipsImage *in, const char *filename );
int im_tile_cache( VipsImage *in, VipsImage *out, 
	int tile_width, int tile_height, int max_tiles );

int im_magick2vips( const char *filename, VipsImage *out );

int im_exr2vips( const char *filename, VipsImage *out );

int im_ppm2vips( const char *filename, VipsImage *out );
int im_vips2ppm( VipsImage *in, const char *filename );

int im_analyze2vips( const char *filename, VipsImage *out );

int im_csv2vips( const char *filename, VipsImage *out );
int im_vips2csv( VipsImage *in, const char *filename );

int im_png2vips( const char *filename, VipsImage *out );
int im_vips2png( VipsImage *in, const char *filename );
int im_vips2bufpng( VipsImage *in, VipsImage *out,
	int compression, int interlace, char **obuf, size_t *olen  );

int im_raw2vips( const char *filename, VipsImage *out,
	int width, int height, int bpp, int offset );
int im_vips2raw( VipsImage *in, int fd );

int im_mat2vips( const char *filename, VipsImage *out );

int im_rad2vips( const char *filename, VipsImage *out );
int im_vips2rad( VipsImage *in, const char *filename );

int im_fits2vips( const char *filename, VipsImage *out );
int im_vips2fits( VipsImage *in, const char *filename );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_FORMAT_H*/
