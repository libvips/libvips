/* Read Radiance (.hdr) files 
 *
 * 3/3/09
 * 	- write packed data, a separate im_rad2float() operation can unpack
 * 23/3/09
 * 	- add radiance write
 * 20/12/11
 * 	- reworked as some fns ready for new-style classes
 * 13/12/12
 * 	- tag RGB rad images as scRGB
 * 4/11/13
 * 	- support sequential read
 * 5/11/13
 * 	- rewritten scanline encode and decode, now much faster
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

/*

	Remaining issues:

+ it ignores some header fields, like VIEW and DATE

+ it will not rotate/flip as the FORMAT string asks

 */

/*

    Sections of this reader from Greg Ward and Radiance with kind 
    permission. The Radience copyright notice appears below.

 */

/* ====================================================================
 * The Radiance Software License, Version 1.0
 *
 * Copyright (c) 1990 - 2009 The Regents of the University of California,
 * through Lawrence Berkeley National Laboratory.   All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *           if any, must include the following acknowledgment:
 *             "This product includes Radiance software
 *                 (http://radsite.lbl.gov/)
 *                 developed by the Lawrence Berkeley National Laboratory
 *               (http://www.lbl.gov/)."
 *       Alternately, this acknowledgment may appear in the software itself,
 *       if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Radiance," "Lawrence Berkeley National Laboratory"
 *       and "The Regents of the University of California" must
 *       not be used to endorse or promote products derived from this
 *       software without prior written permission. For written
 *       permission, please contact radiance@radsite.lbl.gov.
 *
 * 5. Products derived from this software may not be called "Radiance",
 *       nor may "Radiance" appear in their name, without prior written
 *       permission of Lawrence Berkeley National Laboratory.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.   IN NO EVENT SHALL Lawrence Berkeley National Laboratory OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of Lawrence Berkeley National Laboratory.   For more
 * information on Lawrence Berkeley National Laboratory, please see
 * <http://www.lbl.gov/>.
 */

/*
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "radiance.h"

/* Begin copy-paste from Radiance sources.
 */

			/* flags for scanline ordering */
#define  XDECR			1
#define  YDECR			2
#define  YMAJOR			4

			/* standard scanline ordering */
#define  PIXSTANDARD		(YMAJOR|YDECR)
#define  PIXSTDFMT		"-Y %d +X %d\n"

			/* structure for image dimensions */
typedef struct {
	int	rt;		/* orientation (from flags above) */
	int	xr, yr;		/* x and y resolution */
} RESOLU;

			/* macros to get scanline length and number */
#define  scanlen(rs)		((rs)->rt & YMAJOR ? (rs)->xr : (rs)->yr)
#define  numscans(rs)		((rs)->rt & YMAJOR ? (rs)->yr : (rs)->xr)

			/* resolution string buffer and its size */
#define  RESOLU_BUFLEN		32

			/* macros for reading/writing resolution struct */
#define  fputsresolu(rs,fp)	fputs(resolu2str(resolu_buf,rs),fp)
#define  fgetsresolu(rs,fp)	str2resolu(rs, \
					fgets(resolu_buf,RESOLU_BUFLEN,fp))

			/* reading/writing of standard ordering */
#define  fprtresolu(sl,ns,fp)	fprintf(fp,PIXSTDFMT,ns,sl)
#define  fscnresolu(sl,ns,fp)	(fscanf(fp,PIXSTDFMT,ns,sl)==2)

					/* defined in resolu.c */
typedef int gethfunc(char *s, void *p); /* callback to process header lines */


#define  RED		0
#define  GRN		1
#define  BLU		2
#define  CIEX		0	/* or, if input is XYZ... */
#define  CIEY		1
#define  CIEZ		2
#define  EXP		3	/* exponent same for either format */
#define  COLXS		128	/* excess used for exponent */
#define  WHT		3	/* used for RGBPRIMS type */

#undef  BYTE
#define  BYTE 	unsigned char	/* 8-bit unsigned integer */

typedef BYTE  COLR[4];		/* red, green, blue (or X,Y,Z), exponent */

typedef float COLORV;
typedef COLORV  COLOR[3];	/* red, green, blue (or X,Y,Z) */

typedef float  RGBPRIMS[4][2];	/* (x,y) chromaticities for RGBW */
typedef float  (*RGBPRIMP)[2];	/* pointer to RGBPRIMS array */

typedef float  COLORMAT[3][3];	/* color coordinate conversion matrix */

#define  copycolr(c1,c2)	(c1[0]=c2[0],c1[1]=c2[1], \
				c1[2]=c2[2],c1[3]=c2[3])

#define  colval(col,pri)	((col)[pri])

#define  setcolor(col,r,g,b)	((col)[RED]=(r),(col)[GRN]=(g),(col)[BLU]=(b))

#define  copycolor(c1,c2)	((c1)[0]=(c2)[0],(c1)[1]=(c2)[1],(c1)[2]=(c2)[2])

#define  scalecolor(col,sf)	((col)[0]*=(sf),(col)[1]*=(sf),(col)[2]*=(sf))

#define  addcolor(c1,c2)	((c1)[0]+=(c2)[0],(c1)[1]+=(c2)[1],(c1)[2]+=(c2)[2])

#define  multcolor(c1,c2)	((c1)[0]*=(c2)[0],(c1)[1]*=(c2)[1],(c1)[2]*=(c2)[2])

#ifdef  NTSC
#define  CIE_x_r		0.670		/* standard NTSC primaries */
#define  CIE_y_r		0.330
#define  CIE_x_g		0.210
#define  CIE_y_g		0.710
#define  CIE_x_b		0.140
#define  CIE_y_b		0.080
#define  CIE_x_w		0.3333		/* use true white */
#define  CIE_y_w		0.3333
#else
#define  CIE_x_r		0.640		/* nominal CRT primaries */
#define  CIE_y_r		0.330
#define  CIE_x_g		0.290
#define  CIE_y_g		0.600
#define  CIE_x_b		0.150
#define  CIE_y_b		0.060
#define  CIE_x_w		0.3333		/* use true white */
#define  CIE_y_w		0.3333
#endif

#define  STDPRIMS	{{CIE_x_r,CIE_y_r},{CIE_x_g,CIE_y_g}, \
				{CIE_x_b,CIE_y_b},{CIE_x_w,CIE_y_w}}

#define CIE_D		(	CIE_x_r*(CIE_y_g - CIE_y_b) + \
				CIE_x_g*(CIE_y_b - CIE_y_r) + \
				CIE_x_b*(CIE_y_r - CIE_y_g)	)
#define CIE_C_rD	( (1./CIE_y_w) * \
				( CIE_x_w*(CIE_y_g - CIE_y_b) - \
				  CIE_y_w*(CIE_x_g - CIE_x_b) + \
				  CIE_x_g*CIE_y_b - CIE_x_b*CIE_y_g	) )
#define CIE_C_gD	( (1./CIE_y_w) * \
				( CIE_x_w*(CIE_y_b - CIE_y_r) - \
				  CIE_y_w*(CIE_x_b - CIE_x_r) - \
				  CIE_x_r*CIE_y_b + CIE_x_b*CIE_y_r	) )
#define CIE_C_bD	( (1./CIE_y_w) * \
				( CIE_x_w*(CIE_y_r - CIE_y_g) - \
				  CIE_y_w*(CIE_x_r - CIE_x_g) + \
				  CIE_x_r*CIE_y_g - CIE_x_g*CIE_y_r	) )

#define CIE_rf		(CIE_y_r*CIE_C_rD/CIE_D)
#define CIE_gf		(CIE_y_g*CIE_C_gD/CIE_D)
#define CIE_bf		(CIE_y_b*CIE_C_bD/CIE_D)

/* As of 9-94, CIE_rf=.265074126, CIE_gf=.670114631 and CIE_bf=.064811243 */

/***** The following definitions are valid for RGB colors only... *****/

#define  bright(col)	(CIE_rf*(col)[RED]+CIE_gf*(col)[GRN]+CIE_bf*(col)[BLU])
#define  normbright(c)	( ( (long)(CIE_rf*256.+.5)*(c)[RED] + \
			    (long)(CIE_gf*256.+.5)*(c)[GRN] + \
			    (long)(CIE_bf*256.+.5)*(c)[BLU] ) >> 8 )

				/* luminous efficacies over visible spectrum */
#define  MAXEFFICACY		683.		/* defined maximum at 550 nm */
#define  WHTEFFICACY		179.		/* uniform white light */
#define  D65EFFICACY		203.		/* standard illuminant D65 */
#define  INCEFFICACY		160.		/* illuminant A (incand.) */
#define  SUNEFFICACY		208.		/* illuminant B (solar dir.) */
#define  SKYEFFICACY		D65EFFICACY	/* skylight (should be 110) */
#define  DAYEFFICACY		D65EFFICACY	/* combined sky and solar */

#define  luminance(col)		(WHTEFFICACY * bright(col))

/***** ...end of stuff specific to RGB colors *****/

#define  intens(col)		( (col)[0] > (col)[1] \
				? (col)[0] > (col)[2] ? (col)[0] : (col)[2] \
				: (col)[1] > (col)[2] ? (col)[1] : (col)[2] )

#define  colrval(c,p)		( (c)[EXP] ? \
				ldexp((c)[p]+.5,(int)(c)[EXP]-(COLXS+8)) : \
				0. )

#define  WHTCOLOR		{1.0,1.0,1.0}
#define  BLKCOLOR		{0.0,0.0,0.0}
#define  WHTCOLR		{128,128,128,COLXS+1}
#define  BLKCOLR		{0,0,0,0}

				/* picture format identifier */
#define  COLRFMT		"32-bit_rle_rgbe"
#define  CIEFMT			"32-bit_rle_xyze"
#define  PICFMT			"32-bit_rle_???e"	/* matches either */
#define  LPICFMT		15			/* max format id len */

				/* macros for exposures */
#define  EXPOSSTR		"EXPOSURE="
#define  LEXPOSSTR		9
#define  isexpos(hl)		(!strncmp(hl,EXPOSSTR,LEXPOSSTR))
#define  exposval(hl)		atof((hl)+LEXPOSSTR)
#define  fputexpos(ex,fp)	fprintf(fp,"%s%e\n",EXPOSSTR,ex)

				/* macros for pixel aspect ratios */
#define  ASPECTSTR		"PIXASPECT="
#define  LASPECTSTR		10
#define  isaspect(hl)		(!strncmp(hl,ASPECTSTR,LASPECTSTR))
#define  aspectval(hl)		atof((hl)+LASPECTSTR)
#define  fputaspect(pa,fp)	fprintf(fp,"%s%f\n",ASPECTSTR,pa)

				/* macros for primary specifications */
#define  PRIMARYSTR		"PRIMARIES="
#define  LPRIMARYSTR		10
#define  isprims(hl)		(!strncmp(hl,PRIMARYSTR,LPRIMARYSTR))
#define  primsval(p,hl)		sscanf(hl+LPRIMARYSTR, \
					"%f %f %f %f %f %f %f %f", \
					&(p)[RED][CIEX],&(p)[RED][CIEY], \
					&(p)[GRN][CIEX],&(p)[GRN][CIEY], \
					&(p)[BLU][CIEX],&(p)[BLU][CIEY], \
					&(p)[WHT][CIEX],&(p)[WHT][CIEY])
#define  fputprims(p,fp)	fprintf(fp, \
				"%s %.4f %.4f %.4f %.4f %.4f %.4f %.4f %.4f\n",\
					PRIMARYSTR, \
					(p)[RED][CIEX],(p)[RED][CIEY], \
					(p)[GRN][CIEX],(p)[GRN][CIEY], \
					(p)[BLU][CIEX],(p)[BLU][CIEY], \
					(p)[WHT][CIEX],(p)[WHT][CIEY])

				/* macros for color correction */
#define  COLCORSTR		"COLORCORR="
#define  LCOLCORSTR		10
#define  iscolcor(hl)		(!strncmp(hl,COLCORSTR,LCOLCORSTR))
#define  colcorval(cc,hl)	sscanf(hl+LCOLCORSTR,"%f %f %f", \
					&(cc)[RED],&(cc)[GRN],&(cc)[BLU])
#define  fputcolcor(cc,fp)	fprintf(fp,"%s %f %f %f\n",COLCORSTR, \
					(cc)[RED],(cc)[GRN],(cc)[BLU])

#define  CGAMUT_LOWER		01
#define  CGAMUT_UPPER		02
#define  CGAMUT			(CGAMUT_LOWER|CGAMUT_UPPER)

#define  rgb_cie(xyz,rgb)	colortrans(xyz,rgb2xyzmat,rgb)

#define  cpcolormat(md,ms)	memcpy((void *)md,(void *)ms,sizeof(COLORMAT))




#define	 MAXLINE	512

char  HDRSTR[] = "#?";		/* information header magic number */

char  FMTSTR[] = "FORMAT=";	/* format identifier */

char  TMSTR[] = "CAPDATE=";	/* capture date identifier */

static gethfunc mycheck;



static int
formatval(			/* get format value (return true if format) */
	register char  *r,
	register char  *s
)
{
	register char  *cp = FMTSTR;

	while (*cp) if (*cp++ != *s++) return(0);
	while (isspace(*s)) s++;
	if (!*s) return(0);
	if (r == NULL) return(1);
	do
		*r++ = *s++;
	while(*s && !isspace(*s));
	*r = '\0';
	return(1);
}


static int
isformat(			/* is line a format line? */
	char  *s
)
{
	return(formatval(NULL, s));
}



static int
getheader(		/* get header from file */
	FILE  *fp,
	gethfunc *f,
	void  *p
)
{
	char  buf[MAXLINE];
	int n;

	/* give up if there are more than 1,000 lines of header, prevents 
	 * us scanning entire files when testing for israd */
	for (n = 0; n < 1000; n++) {
		buf[MAXLINE-2] = '\n';
		if (fgets(buf, MAXLINE, fp) == NULL)
			return(-1);
		if (buf[0] == '\n')
			return(0);
#ifdef MSDOS
		if (buf[0] == '\r' && buf[1] == '\n')
			return(0);
#endif
		if (buf[MAXLINE-2] != '\n') {
			ungetc(buf[MAXLINE-2], fp);	/* prevent false end */
			buf[MAXLINE-2] = '\0';
		}
		if (f != NULL && (*f)(buf, p) < 0)
			return(-1);
	}

	return(0);
}


struct check {
	FILE	*fp;
	char	fs[64];
};


static int
mycheck(			/* check a header line for format info. */
	char  *s,
	void  *cp
)
{
	if (!formatval(((struct check*)cp)->fs, s)
			&& ((struct check*)cp)->fp != NULL) {
		fputs(s, ((struct check*)cp)->fp);
	}
	return(0);
}


static int
globmatch(			/* check for match of s against pattern p */
	register char	*p,
	register char	*s
)
{
	int	setmatch;

	do {
		switch (*p) {
		case '?':			/* match any character */
			if (!*s++)
				return(0);
			break;
		case '*':			/* match any string */
			while (p[1] == '*') p++;
			do
				if ( (p[1]=='?' || p[1]==*s) &&
						globmatch(p+1,s) )
					return(1);
			while (*s++);
			return(0);
		case '[':			/* character set */
			setmatch = *s == *++p;
			if (!*p)
				return(0);
			while (*++p != ']') {
				if (!*p)
					return(0);
				if (*p == '-') {
					setmatch += p[-1] <= *s && *s <= p[1];
					if (!*++p)
						break;
				} else
					setmatch += *p == *s;
			}
			if (!setmatch)
				return(0);
			s++;
			break;
		case '\\':			/* literal next */
			p++;
		/* fall through */
		default:			/* normal character */
			if (*p != *s)
				return(0);
			s++;
			break;
		}
	} while (*p++);
	return(1);
}


/*
 * Checkheader(fin,fmt,fout) returns a value of 1 if the input format
 * matches the specification in fmt, 0 if no input format was found,
 * and -1 if the input format does not match or there is an
 * error reading the header.  If fmt is empty, then -1 is returned
 * if any input format is found (or there is an error), and 0 otherwise.
 * If fmt contains any '*' or '?' characters, then checkheader
 * does wildcard expansion and copies a matching result into fmt.
 * Be sure that fmt is big enough to hold the match in such cases,
 * and that it is not a static, read-only string!
 * The input header (minus any format lines) is copied to fout
 * if fout is not NULL.
 */

static int
checkheader(
	FILE  *fin,
	char  *fmt,
	FILE  *fout
)
{
	struct check	cdat;
	register char	*cp;

	cdat.fp = fout;
	cdat.fs[0] = '\0';
	if (getheader(fin, mycheck, &cdat) < 0)
		return(-1);
	if (!cdat.fs[0])
		return(0);
	for (cp = fmt; *cp; cp++)		/* check for globbing */
		if ((*cp == '?') | (*cp == '*')) {
			if (globmatch(fmt, cdat.fs)) {
				strcpy(fmt, cdat.fs);
				return(1);
			} else
				return(-1);
		}
	return(strcmp(fmt, cdat.fs) ? -1 : 1);	/* literal match */
}


static char  resolu_buf[RESOLU_BUFLEN];	/* resolution line buffer */


static int
str2resolu(rp, buf)		/* convert resolution line to struct */
register RESOLU  *rp;
char  *buf;
{
	register char  *xndx, *yndx;
	register char  *cp;

	if (buf == NULL)
		return(0);
	xndx = yndx = NULL;
	for (cp = buf; *cp; cp++)
		if (*cp == 'X')
			xndx = cp;
		else if (*cp == 'Y')
			yndx = cp;
	if (xndx == NULL || yndx == NULL)
		return(0);
	rp->rt = 0;
	if (xndx > yndx) rp->rt |= YMAJOR;
	if (xndx[-1] == '-') rp->rt |= XDECR;
	if (yndx[-1] == '-') rp->rt |= YDECR;
	if ((rp->xr = atoi(xndx+1)) <= 0)
		return(0);
	if ((rp->yr = atoi(yndx+1)) <= 0)
		return(0);
	return(1);
}


#ifdef getc_unlocked		/* avoid horrendous overhead of flockfile */
#undef getc
#undef putc
#define getc    getc_unlocked
#define putc    putc_unlocked
#endif

#define  MINELEN	8	/* minimum scanline length for encoding */
#define  MAXELEN	0x7fff	/* maximum scanline length for encoding */
#define  MINRUN		4	/* minimum run length */

static void
fputformat(		/* put out a format value */
	char  *s,
	FILE  *fp
)
{
	fputs(FMTSTR, fp);
	fputs(s, fp);
	putc('\n', fp);
}

char *
resolu2str(buf, rp)		/* convert resolution struct to line */
char  *buf;
register RESOLU  *rp;
{
	if (rp->rt&YMAJOR)
		sprintf(buf, "%cY %d %cX %d\n",
				rp->rt&YDECR ? '-' : '+', rp->yr,
				rp->rt&XDECR ? '-' : '+', rp->xr);
	else
		sprintf(buf, "%cX %d %cY %d\n",
				rp->rt&XDECR ? '-' : '+', rp->xr,
				rp->rt&YDECR ? '-' : '+', rp->yr);
	return(buf);
}

/* End copy-paste from Radiance sources.
 */

#define BUFFER_SIZE (4096)
#define BUFFER_MARGIN (256)

static unsigned char buffer[BUFFER_SIZE + BUFFER_MARGIN];
static int buffer_length = 0;
static int buffer_position = 0;
static FILE *buffer_fp = NULL;

static void
buffer_init( FILE *fp )
{
	buffer_length = 0;
	buffer_position = 0;
	buffer_fp = fp;
}

static int
buffer_need( int require )
{
	int remaining;

	g_assert( require < BUFFER_MARGIN ); 

	remaining = buffer_length - buffer_position;
	if( remaining < require ) {
		size_t len;

		memcpy( buffer, buffer + buffer_position, remaining ); 
		buffer_position = 0;
		buffer_length = remaining;

		len = fread( buffer + buffer_length, 1, BUFFER_SIZE, 
			buffer_fp );
		buffer_length += len;
		remaining = buffer_length - buffer_position;

		if( remaining < require ) {
			vips_error( "rad2vips", "%s", _( "end of file" ) ); 
			return( -1 );
		}
	}

	return( 0 );
}

#define BUFFER_FETCH (buffer[buffer_position++])
#define BUFFER_PEEK (buffer[buffer_position])

/* Read a single scanlne, encoded in the old style.
 */
static int
scanline_read_old( COLR *scanline, int width )
{
	int rshift;

	rshift = 0;
	
	while( width > 0 ) {
		if( buffer_need( 4 ) )
			return( -1 ); 

		scanline[0][RED] = BUFFER_FETCH;
		scanline[0][GRN] = BUFFER_FETCH;
		scanline[0][BLU] = BUFFER_FETCH;
		scanline[0][EXP] = BUFFER_FETCH;

		if( scanline[0][RED] == 1 &&
			scanline[0][GRN] == 1 &&
			scanline[0][BLU] == 1 ) {
			int i;

			for( i = scanline[0][EXP] << rshift; i > 0; i-- ) {
				copycolr( scanline[0], scanline[-1] );
				scanline += 1;
				width -= 1;
			}

			rshift += 8;
		} 
		else {
			scanline += 1;
			width -= 1;
			rshift = 0;
		}
	}

	return( 0 );
}

/* Read a single encoded scanline.
 */
static int
scanline_read( COLR *scanline, int width )
{
	int i, j;

	/* Detect old-style scanlines.
	 */
	if( width < MINELEN ||
		width > MAXELEN )
		return( scanline_read_old( scanline, width ) );

	if( buffer_need( 4 ) )
		return( -1 ); 

	if( BUFFER_PEEK != 2 ) 
		return( scanline_read_old( scanline, width ) );

	scanline[0][RED] = BUFFER_FETCH;
	scanline[0][GRN] = BUFFER_FETCH;
	scanline[0][BLU] = BUFFER_FETCH;
	scanline[0][EXP] = BUFFER_FETCH;
	if( scanline[0][GRN] != 2 || 
		scanline[0][BLU] & 128 ) 
		return( scanline_read_old( scanline + 1, width - 1 ) );

	if( ((scanline[0][BLU] << 8) | scanline[0][EXP]) != width ) {
		vips_error( "rad2vips", "%s", _( "scanline length mismatch" ) );
		return( -1 ); 
	}

	for( i = 0; i < 4; i++ ) 
		for( j = 0; j < width; ) {
			int code, len;
			gboolean run;

			if( buffer_need( 2 ) )
				return( -1 ); 

			code = BUFFER_FETCH; 
			run = code > 128;
			len = run ? code & 127 : code; 

			if( j + len > width ) {
				vips_error( "rad2vips", "%s", _( "overrun" ) ); 
				return( -1 );
			}

			if( run ) { 
				int val;

				val = BUFFER_FETCH; 
				while( len-- )
					scanline[j++][i] = val;
			} 
			else {
				if( buffer_need( len ) )
					return( -1 ); 
				while( len-- ) 
					scanline[j++][i] = BUFFER_FETCH;
			}
		}

	return( 0 );
}

/* An encoded scanline can't be larger than this.
 */
#define MAX_LINE (2 * MAXELEN * sizeof( COLR ))

/* Write a single scanline.
 */
static int
scanline_write( COLR *scanline, int width, FILE *fp )
{
	unsigned char buffer[MAX_LINE];
	int buffer_pos = 0;

#define PUTC( CH ) { \
	buffer[buffer_pos++] = (CH); \
	g_assert( buffer_pos <= MAX_LINE ); \
}

	int i, j, beg, cnt;
	int c2;

	if( width < MINELEN || 
		width > MAXELEN )
		/* Write as a flat scanline.
		 */
		return( fwrite( scanline, sizeof( COLR ), width, fp ) - width );

	/* An RLE scanline. Write magic header.
	 */
	PUTC( 2 ); 
	PUTC( 2 ); 
	PUTC( width >> 8 ); 
	PUTC( width & 255 ); 

	for( i = 0; i < 4; i++ ) {
		for( j = 0; j < width; ) {
			/* Set beg / cnt to the start and length of the next 
			 * run longer than MINRUN.
			 */
			for( beg = j; beg < width; beg += cnt ) {
				for( cnt = 1; 
					cnt < 127 && 
					beg + cnt < width &&
					scanline[beg + cnt][i] == 
						scanline[beg][i]; 
					cnt++ )
					;

				if( cnt >= MINRUN )
					break;
			}

			/* Code pixels leading up to the run as a set of
			 * non-runs. 
			 */
			while( j < beg ) {
				int len = VIPS_MIN( 128, beg - j ); 
				COLR *p = scanline + j; 

				int k;

				PUTC( len ); 
				for( k = 0; k < len; k++ )
					PUTC( p[k][i] );
				j += len;
			}

			/* Code the run we found, if any
			 */
			if( cnt >= MINRUN ) {
				PUTC( 128 + cnt ); 
				PUTC( scanline[j][i] ); 
				j += cnt; 
			} 
		}
	}

	return( fwrite( buffer, 1, buffer_pos, fp ) - buffer_pos );
}

/* What we track during radiance file read.
 */
typedef struct {
	char *filename;
	VipsImage *out;

	FILE *fin;
	char format[256];
	double expos;
	COLOR colcor;
	double aspect;
	RGBPRIMS prims;
	RESOLU rs;
} Read;

int
vips__rad_israd( const char *filename )
{
	FILE *fin;
	char format[256];
	int result;

#ifdef DEBUG
	printf( "israd: \"%s\"\n", filename );
#endif /*DEBUG*/

        if( !(fin = vips__file_open_read( filename, NULL, FALSE )) ) 
		return( 0 );
	strcpy( format, PICFMT );
	result = checkheader( fin, format, NULL );
	fclose( fin );

	return( result == 1 );
}

static void
read_destroy( VipsObject *object, Read *read )
{
	VIPS_FREE( read->filename );
	VIPS_FREEF( fclose, read->fin );
	buffer_init( NULL );
}

static Read *
read_new( const char *filename, VipsImage *out )
{
	Read *read;
	int i;

	if( !(read = VIPS_NEW( out, Read )) )
		return( NULL );

	read->filename = vips_strdup( NULL, filename );
	read->out = out;
	read->fin = NULL;
	strcpy( read->format, COLRFMT );
	read->expos = 1.0;
	for( i = 0; i < 3; i++ )
		read->colcor[i] = 1.0;
	read->aspect = 1.0;
	read->prims[0][0] = CIE_x_r;
	read->prims[0][1] = CIE_y_r;
	read->prims[1][0] = CIE_x_g;
	read->prims[1][1] = CIE_y_g;
	read->prims[2][0] = CIE_x_b;
	read->prims[2][1] = CIE_y_b;
	read->prims[3][0] = CIE_x_w;
	read->prims[3][1] = CIE_y_w;

	g_signal_connect( out, "close", 
		G_CALLBACK( read_destroy ), read );

	if( !(read->fin = vips__file_open_read( filename, NULL, FALSE )) ) 
		return( NULL );
	buffer_init( read->fin );

	return( read );
}

static int
rad2vips_process_line( char *line, Read *read )
{
	if( isformat( line ) ) {
		if( formatval( line, read->format ) )
			return( -1 );
	}
	else if( isexpos( line ) ) {
		read->expos *= exposval( line );
	}
	else if( iscolcor( line ) ) {
		COLOR cc;
		int i;

		colcorval( cc, line );
		for( i = 0; i < 3; i++ )
			read->colcor[i] *= cc[i];
	}
	else if( isaspect( line ) ) {
		read->aspect *= aspectval( line );
	}
	else if( isprims( line ) ) {
		primsval( read->prims, line );
	}

	return( 0 );
}

static const char *prims_name[4][2] = {
	{ "rad-prims-rx", "rad-prims-ry" }, 
	{ "rad-prims-gx", "rad-prims-gy" },
	{ "rad-prims-bx", "rad-prims-by" },
	{ "rad-prims-wx", "rad-prims-wy" }
};

static const char *colcor_name[3] = {
	"rad-colcor-r",
	"rad-colcor-g",
	"rad-colcor-b"
};

static int
rad2vips_get_header( Read *read, VipsImage *out )
{
	int i, j;
	VipsInterpretation interpretation;

	if( getheader( read->fin, (gethfunc *) rad2vips_process_line, read ) ||
		!fgetsresolu( &read->rs, read->fin ) ) {
		vips_error( "rad2vips", "%s", 
			_( "error reading radiance header" ) );
		return( -1 );
	}

	if( strcmp( read->format, COLRFMT ) == 0 )
		interpretation = VIPS_INTERPRETATION_scRGB;
	else if( strcmp( read->format, CIEFMT ) == 0 )
		interpretation = VIPS_INTERPRETATION_XYZ;
	else
		interpretation = VIPS_INTERPRETATION_MULTIBAND;

	vips_image_init_fields( out,
		scanlen( &read->rs ), numscans( &read->rs ),
		4,
		VIPS_FORMAT_UCHAR, VIPS_CODING_RAD,
		interpretation,
		1, read->aspect );

	vips_image_pipelinev( out, VIPS_DEMAND_STYLE_THINSTRIP, NULL );

	vips_image_set_string( out, "rad-format", read->format );

	vips_image_set_double( out, "rad-expos", read->expos );

	for( i = 0; i < 3; i++ )
		vips_image_set_double( out, 
			colcor_name[i], read->colcor[i] );

	vips_image_set_double( out, "rad-aspect", read->aspect );

	for( i = 0; i < 4; i++ )
		for( j = 0; j < 2; j++ )
			vips_image_set_double( out, 
				prims_name[i][j], read->prims[i][j] );

	return( 0 );
}

int
vips__rad_header( const char *filename, VipsImage *out )
{
	Read *read;

#ifdef DEBUG
	printf( "rad2vips_header: reading \"%s\"\n", filename );
#endif /*DEBUG*/

	if( !(read = read_new( filename, out )) ) 
		return( -1 );
	if( rad2vips_get_header( read, read->out ) ) 
		return( -1 );

	return( 0 );
}

static int
rad2vips_generate( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
        VipsRect *r = &or->valid;

	int y;

#ifdef DEBUG
	printf( "rad2vips_get_data\n" );
#endif /*DEBUG*/

	for( y = 0; y < r->height; y++ ) {
		COLR *buf = (COLR *) 
			VIPS_REGION_ADDR( or, 0, r->top + y );

		if( scanline_read( buf, or->im->Xsize ) ) {
			vips_error( "rad2vips", 
				_( "read error line %d" ), r->top + y );
			return( -1 );
		}
	}

	return( 0 );
}

int
vips__rad_load( const char *filename, VipsImage *out, gboolean readbehind )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( out ), 3 );

	Read *read;

#ifdef DEBUG
	printf( "rad2vips: reading \"%s\"\n", filename );
#endif /*DEBUG*/

	if( !(read = read_new( filename, out )) ) 
		return( -1 );

	t[0] = vips_image_new();
	if( rad2vips_get_header( read, t[0] ) )
		return( -1 );

	if( vips_image_generate( t[0], 
		NULL, rad2vips_generate, NULL, 
		read, NULL ) ||
		vips_sequential( t[0], &t[1], 
			"tile_height", 8,
			"access", readbehind ? 
				VIPS_ACCESS_SEQUENTIAL : 
				VIPS_ACCESS_SEQUENTIAL_UNBUFFERED,
			NULL ) ||
		vips_image_write( t[1], out ) )
		return( -1 );

	return( 0 );
}

/* What we track during a radiance file write.
 */
typedef struct {
	VipsImage *in;
	char *filename;

	FILE *fout;
	char format[256];
	double expos;
	COLOR colcor;
	double aspect;
	RGBPRIMS prims;
	RESOLU rs;
} Write;

static void
write_destroy( Write *write )
{
	VIPS_FREE( write->filename );
	VIPS_FREEF( fclose, write->fout );

	vips_free( write );
}

static Write *
write_new( VipsImage *in, const char *filename )
{
	Write *write;
	int i;

	if( !(write = VIPS_NEW( NULL, Write )) )
		return( NULL );

	write->in = in;
	write->filename = vips_strdup( NULL, filename );
        write->fout = vips__file_open_write( filename, FALSE );
	strcpy( write->format, COLRFMT );
	write->expos = 1.0;
	for( i = 0; i < 3; i++ )
		write->colcor[i] = 1.0;
	write->aspect = 1.0;
	write->prims[0][0] = CIE_x_r;
	write->prims[0][1] = CIE_y_r;
	write->prims[1][0] = CIE_x_g;
	write->prims[1][1] = CIE_y_g;
	write->prims[2][0] = CIE_x_b;
	write->prims[2][1] = CIE_y_b;
	write->prims[3][0] = CIE_x_w;
	write->prims[3][1] = CIE_y_w;

        if( !write->filename || !write->fout ) {
		write_destroy( write );
		return( NULL );
	}

	return( write );
}

static int
vips2rad_put_header( Write *write )
{
	const char *str;
	int i, j;
	double d;

	(void) vips_image_get_double( write->in, "rad-expos", &write->expos );
	(void) vips_image_get_double( write->in, "rad-aspect", &write->aspect );

	if( !vips_image_get_string( write->in, "rad-format", &str ) )
		vips_strncpy( write->format, str, 256 );
	if( write->in->Type == VIPS_INTERPRETATION_RGB )
		strcpy( write->format, COLRFMT );
	if( write->in->Type == VIPS_INTERPRETATION_XYZ )
		strcpy( write->format, CIEFMT );

	for( i = 0; i < 3; i++ )
		if( !vips_image_get_double( write->in, colcor_name[i], &d ) )
			write->colcor[i] = d;
	for( i = 0; i < 4; i++ )
		for( j = 0; j < 2; j++ )
			if( !vips_image_get_double( write->in, 
				prims_name[i][j], &d ) )
				write->prims[i][j] = d;

	/* Make y decreasing for consistency with vips.
	 */
	write->rs.rt = YDECR | YMAJOR;
	write->rs.xr = write->in->Xsize;
	write->rs.yr = write->in->Ysize;

	fprintf( write->fout, "#?RADIANCE\n" );

	fputformat( write->format, write->fout );
	fputexpos( write->expos, write->fout );
	fputcolcor( write->colcor, write->fout );
	fprintf( write->fout, "SOFTWARE=vips %s\n", vips_version_string() );
	fputaspect( write->aspect, write->fout );
	fputprims( write->prims, write->fout );
	fputs( "\n", write->fout );
	fputsresolu( &write->rs, write->fout );

	return( 0 );
}

static int
vips2rad_put_data_block( VipsRegion *region, Rect *area, void *a )
{
	Write *write = (Write *) a;
	int i;

	for( i = 0; i < area->height; i++ ) {
		VipsPel *p = VIPS_REGION_ADDR( region, 0, area->top + i );

		if( scanline_write( (COLR *) p, area->width, write->fout ) ) 
		//if( scanline_write_old( (COLR *) p, area->width, write->fout ) ) 
			return( -1 );
	}

	return( 0 );
}

static int
vips2rad_put_data( Write *write )
{
	if( vips_sink_disc( write->in, vips2rad_put_data_block, write ) )
		return( -1 );

	return( 0 );
}

int
vips__rad_save( VipsImage *in, const char *filename )
{
	Write *write;

#ifdef DEBUG
	printf( "vips2rad: writing \"%s\"\n", filename );
#endif /*DEBUG*/

	if( vips_image_pio_input( in ) ||
		vips_check_coding_rad( "vips2rad", in ) )
		return( -1 );
	if( !(write = write_new( in, filename )) )
		return( -1 );
	if( vips2rad_put_header( write ) ||
		vips2rad_put_data( write ) ) {
		write_destroy( write );
		return( -1 );
	}
	write_destroy( write );

	return( 0 );
}

const char *vips__rad_suffs[] = { ".hdr", NULL };
