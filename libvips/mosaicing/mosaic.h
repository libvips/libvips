/* Local definitions used by the mosaicing program 
 * If IM_MAXPOINTS change please ensure that it is still a multiple of
 * AREAS or else AREAS must change as well.  Initial setup is for
 * IM_MAXPOINTS = 60, AREAS = 3.
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

/* Number of entries in blend table. As a power of two as well, for >>ing.
 */
#define BLEND_SHIFT (10)
#define BLEND_SIZE (1<<BLEND_SHIFT)

/* How much we scale the int version up by.
 */
#define BLEND_SCALE (4096)

/* Keep state for each call in one of these.
 */
typedef struct _Overlapping {
	IMAGE *ref;			/* Arguments */
	IMAGE *sec;
	IMAGE *out;
	int dx, dy;
	int mwidth;

	/* Ref and sec images, overlap, output area. We normalise these, so
	 * that the output image is always positioned at (0,0) - ie. all these
	 * coordinates are in output image space.
	 */
	Rect rarea;
	Rect sarea;
	Rect overlap;
	Rect oarea;
	int blsize;			/* Max blend length */
	int flsize;			/* first/last cache size */

	/* Sections of ref and sec which we use in output, excluding 
	 * overlap area.
	 */
	Rect rpart;
	Rect spart;

	/* Overlap start/end cache 
	 */
	GMutex *fl_lock;		/* Need to lock on build */
	int *first, *last;

	/* Blend function.
	 */
	int (*blend)();
} Overlapping;

/* Keep per-thread state here.
 */
typedef struct _MergeInfo {
	REGION *rir;			/* Two input regions */
	REGION *sir;

	float *from1;			/* IM_CODING_LABQ buffers */
	float *from2;
	float *merge;
} MergeInfo;

/* Functions shared between lr and tb.
 */
extern double *im__coef1;
extern double *im__coef2;
extern int *im__icoef1;
extern int *im__icoef2;
int im__make_blend_luts();

int im__attach_input( REGION *or, REGION *ir, Rect *area );
int im__copy_input( REGION *or, REGION *ir, Rect *area, Rect *reg );
Overlapping *im__build_mergestate( const char *domain,
	IMAGE *ref, IMAGE *sec, IMAGE *out, int dx, int dy, int mwidth );
void *im__start_merge( IMAGE *out, void *, void * );
int im__merge_gen( REGION *or, void *seq, void *a, void * );
int im__stop_merge( void *seq, void *, void * );
int im__lrmerge( IMAGE *ref, IMAGE *sec, IMAGE *out, 
	int dx, int dy, int mwidth );
int im__tbmerge( IMAGE *ref, IMAGE *sec, IMAGE *out, 
	int dx, int dy, int mwidth );
int im__lrmerge1( IMAGE *ref, IMAGE *sec, IMAGE *out,
	double a, double b, double dx, double dy, 
	int mwidth );
int im__tbmerge1( IMAGE *ref, IMAGE *sec, IMAGE *out,
	double a, double b, double dx, double dy, 
	int mwidth );


#define IM_MAXPOINTS (60)	/* IM_MAXPOINTS % AREAS must be zero */
#define AREAS (3)	

typedef struct {
        char *reference;	/* filename of reference */
        char *secondary;	/* filename of secondary */
        int deltax;		/* initial estimate of displacement */
        int deltay;		/* initial estimate of displacement */
        int nopoints;   	/* must be multiple of AREAS and <= IM_MAXPOINTS */
        int halfcorsize;	/* recommended 5 */
        int halfareasize;	/* recommended 8 */

	/* x, y_reference and contrast found by im_calcon() 
	 */
        int x_reference[IM_MAXPOINTS], y_reference[IM_MAXPOINTS]; 
        int contrast[IM_MAXPOINTS];

	/* x, y_secondary and correlation set by im_chkpair() 
	 */
        int x_secondary[IM_MAXPOINTS], y_secondary[IM_MAXPOINTS];

	/* returns the corrected best correlation
	 * as detected in 2*halfareasize+1
	 * centered at point (x2, y2) and using
	 * correlation area 2*halfareasize+1 
	 */
        double correlation[IM_MAXPOINTS];

	/* Coefficients calculated by im_clinear() 
	 */
	double l_scale, l_angle, l_deltax, l_deltay;

	/* used by im_clinear() 
	 */
        double dx[IM_MAXPOINTS], dy[IM_MAXPOINTS];
        double deviation[IM_MAXPOINTS];
} TIE_POINTS;

int im__chkpair( IMAGE *, IMAGE *, TIE_POINTS *point );
int im__initialize( TIE_POINTS *points );
int im__improve( TIE_POINTS *inpoints, TIE_POINTS *outpoints );
int im__avgdxdy( TIE_POINTS *points, int *dx, int *dy );
int im__lrcalcon( IMAGE *ref, TIE_POINTS *points );
int im__tbcalcon( IMAGE *ref, TIE_POINTS *points );
int im__coeff( int xr1, int yr1, int xs1, int ys1, 
	int xr2, int yr2, int xs2, int ys2, 
	double *a, double *b, double *dx, double *dy );
int im__clinear( TIE_POINTS *points );
int im__find_lroverlap( IMAGE *ref_in, IMAGE *sec_in, IMAGE *out,
	int bandno_in, 
	int xref, int yref, int xsec, int ysec, 
	int halfcorrelation, int halfarea,
	int *dx0, int *dy0,
	double *scale1, double *angle1, double *dx1, double *dy1 );
int im__find_tboverlap( IMAGE *ref_in, IMAGE *sec_in, IMAGE *out,
	int bandno_in, 
	int xref, int yref, int xsec, int ysec, 
	int halfcorrelation, int halfarea,
	int *dx0, int *dy0,
	double *scale1, double *angle1, double *dx1, double *dy1 );
