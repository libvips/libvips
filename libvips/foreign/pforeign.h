/* Private decls shared by all foreign.
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef VIPS_PFOREIGN_H
#define VIPS_PFOREIGN_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* Slow and horrid version if there's no recent glib.
 */
#ifndef HAVE_CHECKED_MUL
#define g_uint_checked_mul( dest, a, b ) ( \
	((guint64) a * b) > UINT_MAX ? \
		(*dest = UINT_MAX, FALSE) : \
		(*dest = a * b, TRUE) \
)
#endif /*HAVE_CHECKED_MUL*/

void vips__tiff_init( void );

int vips__tiff_write( VipsImage *in, const char *filename, 
	VipsForeignTiffCompression compression, int Q, 
	VipsForeignTiffPredictor predictor,
	const char *profile,
	gboolean tile, int tile_width, int tile_height,
	gboolean pyramid,
	int bitdepth,
	gboolean miniswhite,
	VipsForeignTiffResunit resunit, double xres, double yres,
	gboolean bigtiff,
	gboolean rgbjpeg,
	gboolean properties,
	gboolean strip,
	VipsRegionShrink region_shrink,
	int level, 
	gboolean lossless,
	VipsForeignDzDepth depth,
	gboolean subifd, 
	gboolean premultiply );

int vips__tiff_write_buf( VipsImage *in, 
	void **obuf, size_t *olen, 
	VipsForeignTiffCompression compression, int Q, 
	VipsForeignTiffPredictor predictor,
	const char *profile,
	gboolean tile, int tile_width, int tile_height,
	gboolean pyramid,
	int bitdepth,
	gboolean miniswhite,
	VipsForeignTiffResunit resunit, double xres, double yres,
	gboolean bigtiff,
	gboolean rgbjpeg,
	gboolean properties, gboolean strip,
	VipsRegionShrink region_shrink,
	int level, 
	gboolean lossless,
	VipsForeignDzDepth depth,
	gboolean subifd,
	gboolean premultiply );

gboolean vips__istiff_source( VipsSource *source );
gboolean vips__istifftiled_source( VipsSource *source );
int vips__tiff_read_header_source( VipsSource *source, VipsImage *out, 
	int page, int n, gboolean autorotate, int subifd );
int vips__tiff_read_source( VipsSource *source, VipsImage *out,
	int page, int n, gboolean autorotate, int subifd );

extern const char *vips__foreign_tiff_suffs[];

int vips__isanalyze( const char *filename );
int vips__analyze_read_header( const char *filename, VipsImage *out );
int vips__analyze_read( const char *filename, VipsImage *out );

extern const char *vips__foreign_csv_suffs[];

int vips__csv_read( const char *filename, VipsImage *out,
	int skip, int lines, const char *whitespace, const char *separator, 
	gboolean fail );
int vips__csv_read_header( const char *filename, VipsImage *out,
	int skip, int lines, const char *whitespace, const char *separator, 
	gboolean fail );

int vips__csv_write( VipsImage *in, const char *filename, 
	const char *separator );

int vips__matrix_read_header( const char *filename,
	int *width, int *height, double *scale, double *offset );
int vips__matrix_ismatrix( const char *filename );
VipsImage *vips__matrix_read_file( FILE *fp );
VipsImage *vips__matrix_read( const char *filename );
int vips__matrix_write( VipsImage *in, const char *filename );
int vips__matrix_write_file( VipsImage *in, FILE *fp );

extern const char *vips__foreign_matrix_suffs[];

int vips__openexr_isexr( const char *filename );
gboolean vips__openexr_istiled( const char *filename );
int vips__openexr_read_header( const char *filename, VipsImage *out );
int vips__openexr_read( const char *filename, VipsImage *out );

extern const char *vips__fits_suffs[];

int vips__fits_isfits( const char *filename );
int vips__fits_read_header( const char *filename, VipsImage *out );
int vips__fits_read( const char *filename, VipsImage *out );

int vips__fits_write( VipsImage *in, const char *filename );

int vips__magick_read( const char *filename, 
	VipsImage *out, const char *density, int page, int n );
int vips__magick_read_header( const char *filename, 
	VipsImage *out, const char *density, int page, int n );

int vips__magick_read_buffer( const void *buf, const size_t len,
	VipsImage *out, const char *density, int page, int n );
int vips__magick_read_buffer_header( const void *buf, const size_t len,
	VipsImage *out, const char *density, int page, int n );

extern const char *vips__mat_suffs[];

int vips__mat_load( const char *filename, VipsImage *out );
int vips__mat_header( const char *filename, VipsImage *out );
int vips__mat_ismat( const char *filename );

extern const char *vips__ppm_suffs[];

int vips__ppm_save_target( VipsImage *in, VipsTarget *target,
	gboolean ascii, gboolean squash );
int vips__rad_israd( VipsSource *source );
int vips__rad_header( VipsSource *source, VipsImage *out );
int vips__rad_load( VipsSource *source, VipsImage *out );

int vips__rad_save( VipsImage *in, VipsTarget *target );

extern const char *vips__rad_suffs[];

extern const char *vips__jpeg_suffs[];

int vips__jpeg_write_target( VipsImage *in, VipsTarget *target,
	int Q, const char *profile, 
	gboolean optimize_coding, gboolean progressive, gboolean strip,
	gboolean trellis_quant, gboolean overshoot_deringing,
	gboolean optimize_scans, int quant_table,
	VipsForeignSubsample subsample_mode );

int vips__jpeg_read_source( VipsSource *source, VipsImage *out,
	gboolean header_only, int shrink, int fail, gboolean autorotate );
int vips__isjpeg_source( VipsSource *source );

int vips__png_ispng_source( VipsSource *source );
int vips__png_header_source( VipsSource *source, VipsImage *out );
int vips__png_read_source( VipsSource *source, VipsImage *out, 
	gboolean fail );
gboolean vips__png_isinterlaced_source( VipsSource *source );
extern const char *vips__png_suffs[];

int vips__png_write_target( VipsImage *in, VipsTarget *target,
	int compress, int interlace, const char *profile,
	VipsForeignPngFilter filter, gboolean strip,
	gboolean palette, int Q, double dither,
	int bitdepth );

/* Map WEBP metadata names to vips names.
 */
typedef struct _VipsWebPNames {
	const char *vips;
	const char *webp;
	int flags;
} VipsWebPNames;

extern const VipsWebPNames vips__webp_names[];
extern const int vips__n_webp_names;
extern const char *vips__webp_suffs[];

int vips__iswebp_source( VipsSource *source );

int vips__webp_read_header_source( VipsSource *source, VipsImage *out,
	int page, int n, double scale ); 
int vips__webp_read_source( VipsSource *source, VipsImage *out, 
	int page, int n, double scale ); 

int vips__webp_write_target( VipsImage *image, VipsTarget *target,
	int Q, gboolean lossless, VipsForeignWebpPreset preset,
	gboolean smart_subsample, gboolean near_lossless,
	int alpha_q, int reduction_effort,
	gboolean min_size, int kmin, int kmax,
	gboolean strip, const char *profile );

int vips__quantise_image( VipsImage *in, 
	VipsImage **index_out, VipsImage **palette_out,
	int colours, int Q, double dither );

extern const char *vips_foreign_nifti_suffs[];

VipsBandFormat vips__foreign_nifti_datatype2BandFmt( int datatype );
int vips__foreign_nifti_BandFmt2datatype( VipsBandFormat fmt );

typedef void *(*VipsNiftiMapFn)( const char *name, GValue *value, glong offset, 
	void *a, void *b );
void *vips__foreign_nifti_map( VipsNiftiMapFn fn, void *a, void *b );

extern const char *vips__heif_suffs[];

extern const char *vips__jp2k_suffs[];
int vips__foreign_load_jp2k_decompress( VipsImage *out,
	int width, int height, gboolean ycc_to_rgb,
	void *from, size_t from_length,
	void *to, size_t to_length );
int vips__foreign_load_jp2k_compress( VipsRegion *region,
	VipsRect *tile, VipsTarget *target,
	int tile_width, int tile_height,
	gboolean save_as_ycc, gboolean subsample, gboolean lossless, int Q );

extern const char *vips__jxl_suffs[];

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_PFOREIGN_H*/


