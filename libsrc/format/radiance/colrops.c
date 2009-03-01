#ifndef lint
static const char	RCSid[] = "$Id: colrops.c,v 2.11 2003/07/30 10:11:06 schorsch Exp $";
#endif
/*
 * Integer operations on COLR scanlines
 */

#include "copyright.h"

#include <stdio.h>
#include <math.h>

#include "rtmisc.h"
#include "color.h"


#define MAXGSHIFT	31		/* maximum shift for gamma table */

static BYTE	*g_mant = NULL, *g_nexp = NULL;

static BYTE	(*g_bval)[256] = NULL;


int
setcolrcor(f, a2)		/* set brightness correction */
double	(*f)(double,double);
double	a2;
{
	double	mult;
	register int	i, j;
					/* allocate tables */
	if (g_bval == NULL && (g_bval =
			(BYTE (*)[256])bmalloc((MAXGSHIFT+1)*256)) == NULL)
		return(-1);
					/* compute colr -> gamb mapping */
	mult = 1.0/256.0;
	for (i = 0; i <= MAXGSHIFT; i++) {
		for (j = 0; j < 256; j++)
			g_bval[i][j] = 256.0 * (*f)((j+.5)*mult, a2);
		mult *= 0.5;
	}
	return(0);
}


int
setcolrinv(f, a2)		/* set inverse brightness correction */
double	(*f)(double,double);
double	a2;
{
	double	mult;
	register int	i, j;
					/* allocate tables */
	if (g_mant == NULL && (g_mant = (BYTE *)bmalloc(256)) == NULL)
		return(-1);
	if (g_nexp == NULL && (g_nexp = (BYTE *)bmalloc(256)) == NULL)
		return(-1);
					/* compute gamb -> colr mapping */
	i = 0;
	mult = 256.0;
	for (j = 256; j--; ) {
		while ((g_mant[j] = mult * (*f)((j+.5)/256.0, a2)) < 128) {
			i++;
			mult *= 2.0;
		}
		g_nexp[j] = i;
	}
	return(0);
}


int
setcolrgam(g)			/* set gamma conversion */
double	g;
{
	if (setcolrcor(pow, 1.0/g) < 0)
		return(-1);
	return(setcolrinv(pow, g));
}


int
colrs_gambs(scan, len)		/* convert scanline of colrs to gamma bytes */
register COLR	*scan;
int	len;
{
	register int	i, expo;

	if (g_bval == NULL)
		return(-1);
	while (len-- > 0) {
		expo = scan[0][EXP] - COLXS;
		if (expo < -MAXGSHIFT) {
			if (expo < -MAXGSHIFT-8) {
				scan[0][RED] =
				scan[0][GRN] =
				scan[0][BLU] = 0;
			} else {
				i = (-MAXGSHIFT-1) - expo;
				scan[0][RED] = 
				g_bval[MAXGSHIFT][((scan[0][RED]>>i)+1)>>1];
				scan[0][GRN] =
				g_bval[MAXGSHIFT][((scan[0][GRN]>>i)+1)>>1];
				scan[0][BLU] =
				g_bval[MAXGSHIFT][((scan[0][BLU]>>i)+1)>>1];
			}
		} else if (expo > 0) {
			if (expo > 8) {
				scan[0][RED] =
				scan[0][GRN] =
				scan[0][BLU] = 255;
			} else {
				i = (scan[0][RED]<<1 | 1) << (expo-1);
				scan[0][RED] = i > 255 ? 255 : g_bval[0][i];
				i = (scan[0][GRN]<<1 | 1) << (expo-1);
				scan[0][GRN] = i > 255 ? 255 : g_bval[0][i];
				i = (scan[0][BLU]<<1 | 1) << (expo-1);
				scan[0][BLU] = i > 255 ? 255 : g_bval[0][i];
			}
		} else {
			scan[0][RED] = g_bval[-expo][scan[0][RED]];
			scan[0][GRN] = g_bval[-expo][scan[0][GRN]];
			scan[0][BLU] = g_bval[-expo][scan[0][BLU]];
		}
		scan[0][EXP] = COLXS;
		scan++;
	}
	return(0);
}


int
gambs_colrs(scan, len)		/* convert gamma bytes to colr scanline */
register COLR	*scan;
int	len;
{
	register int	nexpo;

	if ((g_mant == NULL) | (g_nexp == NULL))
		return(-1);
	while (len-- > 0) {
		nexpo = g_nexp[scan[0][RED]];
		if (g_nexp[scan[0][GRN]] < nexpo)
			nexpo = g_nexp[scan[0][GRN]];
		if (g_nexp[scan[0][BLU]] < nexpo)
			nexpo = g_nexp[scan[0][BLU]];
		if (nexpo < g_nexp[scan[0][RED]])
			scan[0][RED] = g_mant[scan[0][RED]]
					>> (g_nexp[scan[0][RED]]-nexpo);
		else
			scan[0][RED] = g_mant[scan[0][RED]];
		if (nexpo < g_nexp[scan[0][GRN]])
			scan[0][GRN] = g_mant[scan[0][GRN]]
					>> (g_nexp[scan[0][GRN]]-nexpo);
		else
			scan[0][GRN] = g_mant[scan[0][GRN]];
		if (nexpo < g_nexp[scan[0][BLU]])
			scan[0][BLU] = g_mant[scan[0][BLU]]
					>> (g_nexp[scan[0][BLU]]-nexpo);
		else
			scan[0][BLU] = g_mant[scan[0][BLU]];
		scan[0][EXP] = COLXS - nexpo;
		scan++;
	}
	return(0);
}


void
shiftcolrs(scan, len, adjust)	/* shift a scanline of colors by 2^adjust */
register COLR	*scan;
register int	len;
register int	adjust;
{
	int	minexp;

	if (adjust == 0)
		return;
	minexp = adjust < 0 ? -adjust : 0;
	while (len-- > 0) {
		if (scan[0][EXP] <= minexp)
			scan[0][RED] = scan[0][GRN] = scan[0][BLU] =
			scan[0][EXP] = 0;
		else
			scan[0][EXP] += adjust;
		scan++;
	}
}


void
normcolrs(scan, len, adjust)	/* normalize a scanline of colrs */
register COLR  *scan;
int  len;
int  adjust;
{
	register int  c;
	register int  shift;

	while (len-- > 0) {
		shift = scan[0][EXP] + adjust - COLXS;
		if (shift > 0) {
			if (shift > 8) {
				scan[0][RED] =
				scan[0][GRN] =
				scan[0][BLU] = 255;
			} else {
				shift--;
				c = (scan[0][RED]<<1 | 1) << shift;
				scan[0][RED] = c > 255 ? 255 : c;
				c = (scan[0][GRN]<<1 | 1) << shift;
				scan[0][GRN] = c > 255 ? 255 : c;
				c = (scan[0][BLU]<<1 | 1) << shift;
				scan[0][BLU] = c > 255 ? 255 : c;
			}
		} else if (shift < 0) {
			if (shift < -8) {
				scan[0][RED] =
				scan[0][GRN] =
				scan[0][BLU] = 0;
			} else {
				shift = -1-shift;
				scan[0][RED] = ((scan[0][RED]>>shift)+1)>>1;
				scan[0][GRN] = ((scan[0][GRN]>>shift)+1)>>1;
				scan[0][BLU] = ((scan[0][BLU]>>shift)+1)>>1;
			}
		}
		scan[0][EXP] = COLXS - adjust;
		scan++;
	}
}
