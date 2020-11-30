/* Local definitions used by the mosaicing program 
 * If VIPS_MAXPOINTS change please ensure that it is still a multiple of
 * AREAS or else AREAS must change as well.  Initial setup is for
 * VIPS_MAXPOINTS = 60, AREAS = 3.
 * 
 * Copyright: 1990, 1991 N. Dessipris
 * Author: Nicos Dessipris
 * Written on: 07/11/1989
 * Modified on : 29/11/1989
 */

/*

    Copyright (C) 1991-2003 The National Gallery

    This program is free software; you can redistribute it and/or modify
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

/* TODO(kleisauke): This import is needed for vips__affinei */
#include <vips/transform.h>

/* Number of entries in blend table. As a power of two as well, for >>ing.
 */
#define BLEND_SHIFT (10)
#define BLEND_SIZE (1<<BLEND_SHIFT)

/* How much we scale the int version up by.
 */
#define BLEND_SCALE (4096)

struct _MergeInfo;
struct _Overlapping;

typedef int (*VipsBlendFn)( VipsRegion *or, 
	struct _MergeInfo *inf, struct _Overlapping *ovlap, VipsRect *oreg );

/* Keep state for each call in one of these.
 */
typedef struct _Overlapping {
	VipsImage *ref;			/* Arguments */
	VipsImage *sec;
	VipsImage *out;
	int dx, dy;
	int mwidth;

	/* Ref and sec images, overlap, output area. We normalise these, so
	 * that the output image is always positioned at (0,0) - ie. all these
	 * coordinates are in output image space.
	 */
	VipsRect rarea;
	VipsRect sarea;
	VipsRect overlap;
	VipsRect oarea;
	int blsize;			/* Max blend length */
	int flsize;			/* first/last cache size */

	/* Sections of ref and sec which we use in output, excluding 
	 * overlap area.
	 */
	VipsRect rpart;
	VipsRect spart;

	/* Overlap start/end cache 
	 */
	GMutex *fl_lock;		/* Need to lock on build */
	int *first, *last;

	/* Blend function.
	 */
	VipsBlendFn blend;
} Overlapping;

/* Keep per-thread state here.
 */
typedef struct _MergeInfo {
	VipsRegion *rir;			/* Two input regions */
	VipsRegion *sir;

	float *from1;			/* VIPS_CODING_LABQ buffers */
	float *from2;
	float *merge;
} MergeInfo;

/* Functions shared between lr and tb.
 */
extern double *vips__coef1;
extern double *vips__coef2;
extern int *vips__icoef1;
extern int *vips__icoef2;
int vips__make_blend_luts( void );

void vips__add_mosaic_name( VipsImage *image );
const char *vips__get_mosaic_name( VipsImage *image );

int vips__affinei( VipsImage *in, VipsImage *out, VipsTransformation *trn );

int vips__attach_input( VipsRegion *or, VipsRegion *ir, VipsRect *area );
int vips__copy_input( VipsRegion *or, VipsRegion *ir, VipsRect *area, VipsRect *reg );
Overlapping *vips__build_mergestate( const char *domain,
	VipsImage *ref, VipsImage *sec, VipsImage *out, int dx, int dy, int mwidth );
void *vips__start_merge( VipsImage *out, void *, void * );
int vips__merge_gen( VipsRegion *or, void *seq, void *a, void *,
	gboolean *stop );
int vips__stop_merge( void *seq, void *, void * );

int vips__lrmerge( VipsImage *ref, VipsImage *sec, VipsImage *out, 
	int dx, int dy, int mwidth );
int vips__tbmerge( VipsImage *ref, VipsImage *sec, VipsImage *out, 
	int dx, int dy, int mwidth );

int vips__lrmerge1( VipsImage *ref, VipsImage *sec, VipsImage *out,
	double a, double b, double dx, double dy, 
	int mwidth );
int vips__tbmerge1( VipsImage *ref, VipsImage *sec, VipsImage *out,
	double a, double b, double dx, double dy, 
	int mwidth );

#define VIPS_MAXPOINTS (60)	/* VIPS_MAXPOINTS % AREAS must be zero */
#define AREAS (3)	

typedef struct {
	char *reference;	/* filename of reference */
	char *secondary;	/* filename of secondary */
	int deltax;		/* initial estimate of displacement */
	int deltay;		/* initial estimate of displacement */
	int nopoints;   	/* must be multiple of AREAS and <= VIPS_MAXPOINTS */
	int halfcorsize;	/* recommended 5 */
	int halfareasize;	/* recommended 8 */

	/* x, y_reference and contrast found by vips_calcon() 
	 */
	int x_reference[VIPS_MAXPOINTS], y_reference[VIPS_MAXPOINTS]; 
	int contrast[VIPS_MAXPOINTS];

	/* x, y_secondary and correlation set by vips_chkpair() 
	 */
	int x_secondary[VIPS_MAXPOINTS], y_secondary[VIPS_MAXPOINTS];

	/* returns the corrected best correlation
	 * as detected in 2*halfareasize+1
	 * centered at point (x2, y2) and using
	 * correlation area 2*halfareasize+1 
	 */
	double correlation[VIPS_MAXPOINTS];

	/* Coefficients calculated by vips_clinear() 
	 */
	double l_scale, l_angle, l_deltax, l_deltay;

	/* used by vips_clinear() 
	 */
	double dx[VIPS_MAXPOINTS], dy[VIPS_MAXPOINTS];
	double deviation[VIPS_MAXPOINTS];
} TiePoints;

int vips__chkpair( VipsImage *, VipsImage *, TiePoints *point );
int vips__initialize( TiePoints *points );
int vips__improve( TiePoints *inpoints, TiePoints *outpoints );
int vips__avgdxdy( TiePoints *points, int *dx, int *dy );
int vips__lrcalcon( VipsImage *ref, TiePoints *points );
int vips__tbcalcon( VipsImage *ref, TiePoints *points );
int vips__coeff( int xr1, int yr1, int xs1, int ys1, 
	int xr2, int yr2, int xs2, int ys2, 
	double *a, double *b, double *dx, double *dy );
int vips__clinear( TiePoints *points );
int vips__find_lroverlap( VipsImage *ref_in, VipsImage *sec_in, VipsImage *out,
	int bandno_in, 
	int xref, int yref, int xsec, int ysec, 
	int halfcorrelation, int halfarea,
	int *dx0, int *dy0,
	double *scale1, double *angle1, double *dx1, double *dy1 );
int vips__find_tboverlap( VipsImage *ref_in, VipsImage *sec_in, VipsImage *out,
	int bandno_in, 
	int xref, int yref, int xsec, int ysec, 
	int halfcorrelation, int halfarea,
	int *dx0, int *dy0,
	double *scale1, double *angle1, double *dx1, double *dy1 );
int vips__find_best_contrast( VipsImage *image,
	int xpos, int ypos, int xsize, int ysize,
	int xarray[], int yarray[], int cont[],
	int nbest, int hcorsize );
