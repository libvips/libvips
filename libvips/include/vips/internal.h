/* Declarations only used internally to vips. See private.h for declarations
 * which are not public, but which have to be publically visible.
 *
 * 11/9/06
 *	- cut from proto.h
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

#ifndef VIPS_INTERNAL_H
#define VIPS_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* What we store in the Meta hash table. We can't just use GHashTable's 
 * key/value pairs, since we need to iterate over meta in Meta_traverse order.
 *
 * We don't refcount at this level ... large meta values are refcounted by
 * their GValue implementation, see eg. MetaArea.
 */
typedef struct _VipsMeta {
	VipsImage *im;

	char *field;			/* strdup() of field name */
	GValue value;			/* copy of value */
} VipsMeta;

void vips__meta_init_types( void );
void vips__meta_destroy( VipsImage *im );
int vips__meta_cp( VipsImage *, const VipsImage * );

/* Default tile geometry.
 */
extern int vips__tile_width;
extern int vips__tile_height;
extern int vips__fatstrip_height;
extern int vips__thinstrip_height;

/* Default n threads.
 */
extern int vips__concurrency;

/* abort() on any error.
 */
extern int vips__fatal;

/* Give progress feedback.
 */
extern int vips__progress;

/* A string giving the image size (in bytes of uncompressed image) above which 
 * we decompress to disc on open. 
 */
extern char *vips__disc_threshold;

/* Cache size settings.
 */
extern char *vips__cache_max;
extern char *vips__cache_max_mem;
extern char *vips__cache_max_files;
extern gboolean vips__cache_dump;
extern gboolean vips__cache_trace;

void vips__cache_init( void );

void vips__type_leak( void );

typedef int (*im__fftproc_fn)( VipsImage *, VipsImage *, VipsImage * );

/* iofuncs
 */
int vips__open_image_read( const char *filename );
int vips__open_image_write( const char *filename, gboolean temp );
int vips_image_open_input( VipsImage *image );
int vips_image_open_output( VipsImage *image );

void vips__link_break_all( VipsImage *im );
void *vips__link_map( VipsImage *image, gboolean upstream, 
	VipsSListMap2Fn fn, void *a, void *b );

char *vips__b64_encode( const unsigned char *data, size_t data_length );
unsigned char *vips__b64_decode( const char *buffer, size_t *data_length );

void *vips__mmap( int fd, int writeable, size_t length, gint64 offset );
int vips__munmap( void *start, size_t length );
int vips_mapfile( VipsImage * );
int vips_mapfilerw( VipsImage * );
int vips_remapfilerw( VipsImage * );

void vips__buffer_init( void );

void vips__copy_4byte( int swap, unsigned char *to, unsigned char *from );
void vips__copy_2byte( gboolean swap, unsigned char *to, unsigned char *from );

guint32 vips__file_magic( const char *filename );
int vips__has_extension_block( VipsImage *im );
void *vips__read_extension_block( VipsImage *im, int *size );
int vips__write_extension_block( VipsImage *im, void *buf, int size );
int vips__writehist( VipsImage *image );
int vips__read_header_bytes( VipsImage *im, unsigned char *from );
int vips__write_header_bytes( VipsImage *im, unsigned char *to );

extern GMutex *vips__global_lock;

int vips__formatalike_vec( VipsImage **in, VipsImage **out, int n );
int vips__sizealike_vec( VipsImage **in, VipsImage **out, int n );
int vips__bandup( const char *domain, VipsImage *in, VipsImage **out, int n );
int vips__bandalike_vec( const char *domain, 
	VipsImage **in, VipsImage **out, int n, int base_bands );

int vips__formatalike( VipsImage *in1, VipsImage *in2, 
	VipsImage **out1, VipsImage **out2 );
int vips__sizealike( VipsImage *in1, VipsImage *in2, 
	VipsImage **out1, VipsImage **out2 );
int vips__bandalike( const char *domain, 
	VipsImage *in1, VipsImage *in2, VipsImage **out1, VipsImage **out2 );


void im__format_init( void );

void im__tiff_register( void );
void im__jpeg_register( void );
void im__png_register( void );
void im__csv_register( void );
void im__ppm_register( void );
void im__analyze_register( void );
void im__exr_register( void );
void im__magick_register( void );

int im__bandup( const char *domain, VipsImage *in, VipsImage *out, int n );
int im__bandalike_vec( const char *domain, VipsImage **in, VipsImage **out, int n );
int im__bandalike( const char *domain, 
	VipsImage *in1, VipsImage *in2, VipsImage *out1, VipsImage *out2 );
int im__formatalike_vec( VipsImage **in, VipsImage **out, int n );
int im__formatalike( VipsImage *in1, VipsImage *in2, VipsImage *out1, VipsImage *out2 );
int im__sizealike_vec( VipsImage **in, VipsImage **out, int n );
int im__sizealike( VipsImage *in1, VipsImage *in2, 
	VipsImage *out1, VipsImage *out2 );

int im__arith_binary( const char *domain, 
	VipsImage *in1, VipsImage *in2, VipsImage *out, 
	int format_table[10], 
	im_wrapmany_fn fn, void *b );
int im__arith_binary_const( const char *domain,
	VipsImage *in, VipsImage *out, 
	int n, double *c, VipsBandFormat vfmt,
	int format_table[10], 
	im_wrapone_fn fn1, im_wrapone_fn fnn );
int im__value( VipsImage *im, double *value );
typedef int (*im__wrapscan_fn)( void *p, int n, void *seq, void *a, void *b );
int im__wrapscan( VipsImage *in, 
	VipsStartFn start, im__wrapscan_fn scan, VipsStopFn stop,
	void *a, void *b );
int im__colour_difference( const char *domain,
	VipsImage *in1, VipsImage *in2, VipsImage *out, 
	im_wrapmany_fn buffer_fn, void *a, void *b );
int im__colour_unary( const char *domain,
	VipsImage *in, VipsImage *out, VipsInterpretation interpretation,
	im_wrapone_fn buffer_fn, void *a, void *b );
VipsImage **im__insert_base( const char *domain, 
	VipsImage *in1, VipsImage *in2, VipsImage *out );

int im__fftproc( VipsImage *dummy, 
	VipsImage *in, VipsImage *out, im__fftproc_fn fn );

int im__find_lroverlap( VipsImage *ref_in, VipsImage *sec_in, VipsImage *out,
        int bandno_in,
        int xref, int yref, int xsec, int ysec,
        int halfcorrelation, int halfarea,
        int *dx0, int *dy0,
        double *scale1, double *angle1, double *dx1, double *dy1 );
int im__find_tboverlap( VipsImage *ref_in, VipsImage *sec_in, VipsImage *out,
        int bandno_in,
        int xref, int yref, int xsec, int ysec,
        int halfcorrelation, int halfarea,
        int *dx0, int *dy0,
        double *scale1, double *angle1, double *dx1, double *dy1 );
int im__find_best_contrast( VipsImage *image,
	int xpos, int ypos, int xsize, int ysize,
	int xarray[], int yarray[], int cont[],
	int nbest, int hcorsize );
int im__balance( VipsImage *ref, VipsImage *sec, VipsImage *out,
	VipsImage **ref_out, VipsImage **sec_out, int dx, int dy, int balancetype );

void imb_LCh2Lab( float *, float *, int );

/* A colour temperature.
 */
typedef struct {
	double X0, Y0, Z0;
} im_colour_temperature;

void imb_XYZ2Lab( float *, float *, int, im_colour_temperature * );
void imb_LabS2Lab( signed short *, float *, int );
void imb_Lab2LabS( float *, signed short *, int n );

void vips__Lab2LabQ_vec( VipsPel *out, float *in, int width );
void vips__LabQ2Lab_vec( float *out, VipsPel *in, int width );

void im_copy_dmask_matrix( DOUBLEMASK *mask, double **matrix );
void im_copy_matrix_dmask( double **matrix, DOUBLEMASK *mask );

int *im_ivector();
float *im_fvector();
double *im_dvector();
void im_free_ivector();
void im_free_fvector();
void im_free_dvector();

int **im_imat_alloc();
float **im_fmat_alloc();
double **im_dmat_alloc();
void im_free_imat();
void im_free_fmat();
void im_free_dmat();

int im_invmat( double **, int );

int *im_offsets45( int size );
int *im_offsets90( int size );

int im_conv_f_raw( VipsImage *in, VipsImage *out, DOUBLEMASK *mask );
int im_convsep_f_raw( VipsImage *in, VipsImage *out, DOUBLEMASK *mask );

int im__fmaskcir( VipsImage *out, VipsMaskType flag, va_list ap );

/* inplace
 */

VipsPel *vips__vector_to_ink( const char *domain, 
	VipsImage *im, double *vec, int n );
VipsPel *im__vector_to_ink( const char *domain, 
	VipsImage *im, int n, double *vec );
VipsImage *im__inplace_base( const char *domain, 
	VipsImage *main, VipsImage *sub, VipsImage *out );

/* Register base vips interpolators, called during startup.
 */
void vips__interpolate_init( void );

/* Register wrappers for all the vips7 operations.
 */
void vips__init_wrap7_classes( void );

/* Start up various packages.
 */
void vips_arithmetic_operation_init( void );
void vips_conversion_operation_init( void );
void vips_resample_operation_init( void );
void vips_foreign_operation_init( void );
void vips_colour_operation_init( void );

guint64 vips__parse_size( const char *size_string );

IMAGE *vips__deprecated_open_read( const char *filename, gboolean sequential );
IMAGE *vips__deprecated_open_write( const char *filename );

int vips__input_interpolate_init( im_object *obj, char *str );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_INTERNAL_H*/
