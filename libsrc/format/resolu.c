#ifndef lint
static const char	RCSid[] = "$Id: resolu.c,v 2.6 2006/06/07 17:52:03 schorsch Exp $";
#endif
/*
 * Read and write image resolutions.
 *
 * Externals declared in resolu.h
 */

#include "copyright.h"

#include <stdlib.h>
#include <stdio.h>

#include "resolu.h"


char  resolu_buf[RESOLU_BUFLEN];	/* resolution line buffer */


void
fputresolu(ord, sl, ns, fp)		/* put out picture dimensions */
int  ord;			/* scanline ordering */
int  sl, ns;			/* scanline length and number */
FILE  *fp;
{
	RESOLU  rs;

	if ((rs.rt = ord) & YMAJOR) {
		rs.xr = sl;
		rs.yr = ns;
	} else {
		rs.xr = ns;
		rs.yr = sl;
	}
	fputsresolu(&rs, fp);
}


int
fgetresolu(sl, ns, fp)			/* get picture dimensions */
int  *sl, *ns;			/* scanline length and number */
FILE  *fp;
{
	RESOLU  rs;

	if (!fgetsresolu(&rs, fp))
		return(-1);
	if (rs.rt & YMAJOR) {
		*sl = rs.xr;
		*ns = rs.yr;
	} else {
		*sl = rs.yr;
		*ns = rs.xr;
	}
	return(rs.rt);
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


int
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
