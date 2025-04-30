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

/* We've seen real images with 28 chunks, so set 50.
 */
#define MAX_PNG_TEXT_CHUNKS 50

int vips__foreign_update_metadata(VipsImage *in,
	VipsForeignKeep keep);

void vips__tiff_init(void);

int vips__tiff_write_target(VipsImage *in, VipsTarget *target,
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
	VipsRegionShrink region_shrink,
	int level,
	gboolean lossless,
	VipsForeignDzDepth depth,
	gboolean subifd,
	gboolean premultiply,
	int page_height);

gboolean vips__istiff_source(VipsSource *source);
gboolean vips__istifftiled_source(VipsSource *source);
int vips__tiff_read_header_source(VipsSource *source, VipsImage *out,
	int page, int n, gboolean autorotate, int subifd, VipsFailOn fail_on,
	gboolean unlimited);
int vips__tiff_read_source(VipsSource *source, VipsImage *out,
	int page, int n, gboolean autorotate, int subifd, VipsFailOn fail_on,
	gboolean unlimited);

extern const char *vips__foreign_tiff_suffs[];

int vips__isanalyze(const char *filename);
int vips__analyze_read_header(const char *filename, VipsImage *out);
int vips__analyze_read(const char *filename, VipsImage *out);

extern const char *vips__foreign_csv_suffs[];

extern const char *vips__foreign_matrix_suffs[];

int vips__openexr_isexr(const char *filename);
gboolean vips__openexr_istiled(const char *filename);
int vips__openexr_read_header(const char *filename, VipsImage *out);
int vips__openexr_read(const char *filename, VipsImage *out);

extern const char *vips__fits_suffs[];

int vips__fits_isfits(const char *filename);
int vips__fits_read_header(const char *filename, VipsImage *out);
int vips__fits_read(const char *filename, VipsImage *out);

int vips__fits_write(VipsImage *in, const char *filename);

extern const char *vips__mat_suffs[];

int vips__mat_load(const char *filename, VipsImage *out);
int vips__mat_header(const char *filename, VipsImage *out);
int vips__mat_ismat(const char *filename);

extern const char *vips__ppm_suffs[];
extern const char *vips__save_pbm_suffs[];
extern const char *vips__save_pgm_suffs[];
extern const char *vips__save_ppm_suffs[];
extern const char *vips__save_pfm_suffs[];
extern const char *vips__save_pnm_suffs[];

int vips__rad_israd(VipsSource *source);
int vips__rad_header(VipsSource *source, VipsImage *out);
int vips__rad_load(VipsSource *source, VipsImage *out);

int vips__rad_save(VipsImage *in, VipsTarget *target);

extern const char *vips__rad_suffs[];

extern const char *vips__jpeg_suffs[];

int vips__jpeg_write_target(VipsImage *in, VipsTarget *target,
	int Q, const char *profile,
	gboolean optimize_coding, gboolean progressive,
	gboolean trellis_quant,
	gboolean overshoot_deringing, gboolean optimize_scans,
	int quant_table, VipsForeignSubsample subsample_mode,
	int restart_interval);

int vips__jpeg_region_write_target(VipsRegion *region, VipsRect *rect,
	VipsTarget *target,
	int Q, const char *profile,
	gboolean optimize_coding, gboolean progressive,
	VipsForeignKeep keep, gboolean trellis_quant,
	gboolean overshoot_deringing, gboolean optimize_scans,
	int quant_table, VipsForeignSubsample subsample_mode,
	int restart_interval);

int vips__jpeg_read_source(VipsSource *source, VipsImage *out,
	gboolean header_only, int shrink, VipsFailOn fail_on,
	gboolean autorotate, gboolean unlimited);
int vips__isjpeg_source(VipsSource *source);

int vips__png_ispng_source(VipsSource *source);
int vips__png_header_source(VipsSource *source, VipsImage *out,
	gboolean unlimited);
int vips__png_read_source(VipsSource *source, VipsImage *out,
	VipsFailOn fail_on, gboolean unlimited);
gboolean vips__png_isinterlaced_source(VipsSource *source);
extern const char *vips__png_suffs[];

int vips__png_write_target(VipsImage *in, VipsTarget *target,
	int compress, int interlace, const char *profile,
	VipsForeignPngFilter filter,
	gboolean palette, int Q, double dither,
	int bitdepth, int effort);

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

int vips__iswebp_source(VipsSource *source);

int vips__webp_read_header_source(VipsSource *source, VipsImage *out,
	int page, int n, double scale);
int vips__webp_read_source(VipsSource *source, VipsImage *out,
	int page, int n, double scale);

extern const char *vips_foreign_nifti_suffs[];

VipsBandFormat vips__foreign_nifti_datatype2BandFmt(int datatype);
int vips__foreign_nifti_BandFmt2datatype(VipsBandFormat fmt);

typedef void *(*VipsNiftiMapFn)(const char *name, GValue *value, glong offset,
	void *a, void *b);
void *vips__foreign_nifti_map(VipsNiftiMapFn fn, void *a, void *b);

extern const char *vips__heic_suffs[];
extern const char *vips__avif_suffs[];
extern const char *vips__heif_suffs[];
struct heif_image;
struct heif_error;
void vips__heif_init(void);
int vips__heif_chroma(int bits_per_pixel, gboolean has_alpha);
void vips__heif_image_print(struct heif_image *img);
void vips__heif_error(struct heif_error *error);

extern const char *vips__jp2k_suffs[];
int vips__foreign_load_jp2k_decompress(VipsImage *out,
	int width, int height, gboolean ycc_to_rgb,
	void *from, size_t from_length,
	void *to, size_t to_length);
int vips__foreign_save_jp2k_compress(VipsRegion *region,
	VipsRect *tile, VipsTarget *target,
	int tile_width, int tile_height,
	gboolean save_as_ycc, gboolean subsample, gboolean lossless, int Q);

extern const char *vips__jxl_suffs[];

struct _VipsArchive;
typedef struct _VipsArchive VipsArchive;
void vips__archive_free(VipsArchive *archive);
VipsArchive *vips__archive_new_to_dir(const char *base_dirname);
VipsArchive *vips__archive_new_to_target(VipsTarget *target,
	const char *base_dirname, int compression);
int vips__archive_mkdir(VipsArchive *archive, const char *dirname);
int vips__archive_mkfile(VipsArchive *archive,
	const char *filename, void *buf, size_t len);

extern const char *vips__pdf_suffs[];
gboolean vips__pdf_is_a_buffer(const void *buf, size_t len);
gboolean vips__pdf_is_a_file(const char *filename);
gboolean vips__pdf_is_a_source(VipsSource *source);

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_PFOREIGN_H*/
