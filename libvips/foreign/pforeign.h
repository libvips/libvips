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

#ifndef VIPS_PARITHMETIC_H
#define VIPS_PARITHMETIC_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

void vips__tiff_init( void );

int vips__tiff_write( VipsImage *in, const char *filename, 
	VipsForeignTiffCompression compression, int Q, 
		VipsForeignTiffPredictor predictor,
	char *profile,
	gboolean tile, int tile_width, int tile_height,
	gboolean pyramid,
	gboolean squash,
	gboolean miniswhite,
	VipsForeignTiffResunit resunit, double xres, double yres,
	gboolean bigtiff,
	gboolean rgbjpeg,
	gboolean properties,
	gboolean strip );

int vips__tiff_write_buf( VipsImage *in, 
	void **obuf, size_t *olen, 
	VipsForeignTiffCompression compression, int Q, 
	VipsForeignTiffPredictor predictor,
	char *profile,
	gboolean tile, int tile_width, int tile_height,
	gboolean pyramid,
	gboolean squash,
	gboolean miniswhite,
	VipsForeignTiffResunit resunit, double xres, double yres,
	gboolean bigtiff,
	gboolean rgbjpeg,
	gboolean properties, gboolean strip );

int vips__tiff_read_header( const char *filename, VipsImage *out, 
	int page, gboolean autorotate );
int vips__tiff_read( const char *filename, VipsImage *out, 
	int page, gboolean autorotate, gboolean readbehind );
gboolean vips__istifftiled( const char *filename );
gboolean vips__istiff_buffer( const void *buf, size_t len );
gboolean vips__istiff( const char *filename );

int vips__tiff_read_header_buffer( const void *buf, size_t len, VipsImage *out, 
	int page, gboolean autorotate );
int vips__tiff_read_buffer( const void *buf, size_t len, VipsImage *out, 
	int page, gboolean autorotate, gboolean readbehind );

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
	VipsImage *out, gboolean all_frames, const char *density, int page );
int vips__magick_read_header( const char *filename, 
	VipsImage *out, gboolean all_frames, const char *density, int page );

int vips__magick_read_buffer( const void *buf, const size_t len,
	VipsImage *out, gboolean all_frames, const char *density, int page );
int vips__magick_read_buffer_header( const void *buf, const size_t len,
	VipsImage *out, gboolean all_frames, const char *density, int page );

extern const char *vips__mat_suffs[];

int vips__mat_load( const char *filename, VipsImage *out );
int vips__mat_header( const char *filename, VipsImage *out );
int vips__mat_ismat( const char *filename );

int vips__ppm_header( const char *name, VipsImage *out );
int vips__ppm_load( const char *name, VipsImage *out );
int vips__ppm_isppm( const char *filename );
VipsForeignFlags vips__ppm_flags( const char *filename );
extern const char *vips__ppm_suffs[];

int vips__ppm_save( VipsImage *in, const char *filename, 
	gboolean ascii, gboolean squash ); 

int vips__rad_israd( const char *filename );
int vips__rad_header( const char *filename, VipsImage *out );
int vips__rad_load( const char *filename, VipsImage *out, gboolean readbehind );

int vips__rad_save( VipsImage *in, const char *filename );
int vips__rad_save_buf( VipsImage *in, void **obuf, size_t *olen );

extern const char *vips__rad_suffs[];

extern const char *vips__jpeg_suffs[];

int vips__jpeg_write_file( VipsImage *in, 
	const char *filename, int Q, const char *profile, 
	gboolean optimize_coding, gboolean progressive, gboolean strip,
	gboolean no_subsample, gboolean trellis_quant,
	gboolean overshoot_deringing, gboolean optimize_scans, int quant_table );
int vips__jpeg_write_buffer( VipsImage *in, 
	void **obuf, size_t *olen, int Q, const char *profile, 
	gboolean optimize_coding, gboolean progressive, gboolean strip,
	gboolean no_subsample, gboolean trellis_quant,
	gboolean overshoot_deringing, gboolean optimize_scans, int quant_table );

int vips__isjpeg_buffer( const void *buf, size_t len );
int vips__isjpeg( const char *filename );
int vips__jpeg_read_file( const char *name, VipsImage *out, 
	gboolean header_only, int shrink, gboolean fail, gboolean readbehind,
	gboolean autorotate );
int vips__jpeg_read_buffer( const void *buf, size_t len, VipsImage *out, 
	gboolean header_only, int shrink, int fail, gboolean readbehind,
	gboolean autorotate );

int vips__png_header( const char *name, VipsImage *out );
int vips__png_read( const char *name, VipsImage *out, gboolean readbehind );
gboolean vips__png_ispng_buffer( const void *buf, size_t len );
int vips__png_ispng( const char *filename );
gboolean vips__png_isinterlaced( const char *filename );
extern const char *vips__png_suffs[];
int vips__png_read_buffer( const void *buffer, size_t length, 
	VipsImage *out, gboolean readbehind  );
int vips__png_header_buffer( const void *buffer, size_t length, 
	VipsImage *out );

int vips__png_write( VipsImage *in, const char *filename, 
	int compress, int interlace, const char *profile,
	VipsForeignPngFilter filter, gboolean strip );
int vips__png_write_buf( VipsImage *in, 
	void **obuf, size_t *olen, int compression, int interlace, 
	const char *profile, VipsForeignPngFilter filter, gboolean strip );

extern const char *vips__webp_suffs[];

int vips__iswebp_buffer( const void *buf, size_t len );
int vips__iswebp( const char *filename );

int vips__webp_read_file_header( const char *name, VipsImage *out, int shrink );
int vips__webp_read_file( const char *name, VipsImage *out, int shrink ); 

int vips__webp_read_buffer_header( const void *buf, size_t len, 
	VipsImage *out, int shrink ); 
int vips__webp_read_buffer( const void *buf, size_t len, 
	VipsImage *out, int shrink ); 

int vips__webp_write_file( VipsImage *out, const char *filename, 
	int Q, gboolean lossless, VipsForeignWebpPreset preset,
	gboolean smart_subsample, gboolean near_lossless,
	int alpha_q );
int vips__webp_write_buffer( VipsImage *out, void **buf, size_t *len, 
	int Q, gboolean lossless, VipsForeignWebpPreset preset,
	gboolean smart_subsample, gboolean near_lossless,
	int alpha_q );

int vips__openslide_isslide( const char *filename );
int vips__openslide_read_header( const char *filename, VipsImage *out, 
	int level, gboolean autocrop, char *associated, gboolean fail );
int vips__openslide_read( const char *filename, VipsImage *out, 
	int level, gboolean autocrop, gboolean fail );
int vips__openslide_read_associated( const char *filename, VipsImage *out, 
	const char *associated, gboolean fail );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_PARITHMETIC_H*/


