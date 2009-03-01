#ifndef lint
static const char	RCSid[] = "$Id: ra_skel.c,v 2.13 2006/03/10 19:40:13 schorsch Exp $";
#endif
/*
 *  Skeletal 24-bit image conversion program.  Replace "skel"
 *  in this file with a more appropriate image type identifier.
 *
 *  The Rmakefile entry should look something like this:
 *	ra_skel:	ra_skel.o
 *		cc $(CFLAGS) -o ra_skel ra_skel.o -lrtrad -lm
 *	ra_skel.o:	../common/color.h ../common/resolu.h
 *
 *  If you like to do things the hard way, you can link directly
 *  to the object files "color.o colrops.o resolu.o header.o" in
 *  the common subdirectory instead of using the -lrtrad library.
 */

#include  <stdio.h>
#include  <math.h>
#include  <time.h>

#include  "platform.h"
#include  "color.h"
#include  "resolu.h"

double	gamcor = 2.2;			/* gamma correction */

int  bradj = 0;				/* brightness adjustment */

char  *progname;

int  xmax, ymax;


main(argc, argv)
int  argc;
char  *argv[];
{
	int  reverse = 0;
	int  i;
	
	progname = argv[0];

	for (i = 1; i < argc; i++)
		if (argv[i][0] == '-')
			switch (argv[i][1]) {
			case 'g':		/* gamma correction */
				gamcor = atof(argv[++i]);
				break;
			case 'e':		/* exposure adjustment */
				if (argv[i+1][0] != '+' && argv[i+1][0] != '-')
					goto userr;
				bradj = atoi(argv[++i]);
				break;
			case 'r':		/* reverse conversion */
				reverse = 1;
				break;
			default:
				goto userr;
			}
		else
			break;

	if (i < argc-2)
		goto userr;
	if (i <= argc-1 && freopen(argv[i], "r", stdin) == NULL) {
		fprintf(stderr, "%s: can't open input \"%s\"\n",
				progname, argv[i]);
		exit(1);
	}
	if (i == argc-2 && freopen(argv[i+1], "w", stdout) == NULL) {
		fprintf(stderr, "%s: can't open output \"%s\"\n",
				progname, argv[i+1]);
		exit(1);
	}
	SET_FILE_BINARY(stdin);
	SET_FILE_BINARY(stdout);
	setcolrgam(gamcor);		/* set up gamma correction */
	if (reverse) {
					/* get their image resolution */
		read_skel_head(&xmax, &ymax);
					/* put our header */
		newheader("RADIANCE", stdout);
		printargs(i, argv, stdout);
		fputformat(COLRFMT, stdout);
		putchar('\n');
		fprtresolu(xmax, ymax, stdout);
					/* convert file */
		skel2ra();
	} else {
					/* get our header */
		if (checkheader(stdin, COLRFMT, NULL) < 0 ||
				fgetresolu(&xmax, &ymax, stdin) < 0)
			quiterr("bad picture format");
					/* write their header */
		write_skel_head(xmax, ymax);
					/* convert file */
		ra2skel();
	}
	exit(0);
userr:
	fprintf(stderr,
		"Usage: %s [-r][-g gamma][-e +/-stops] [input [output]]\n",
			progname);
	exit(1);
}


quiterr(err)		/* print message and exit */
char  *err;
{
	if (err != NULL) {
		fprintf(stderr, "%s: %s\n", progname, err);
		exit(1);
	}
	exit(0);
}


skel2ra()		/* convert 24-bit scanlines to Radiance picture */
{
	COLR	*scanout;
	register int	x;
	int	y;
						/* allocate scanline */
	scanout = (COLR *)malloc(xmax*sizeof(COLR));
	if (scanout == NULL)
		quiterr("out of memory in skel2ra");
						/* convert image */
	for (y = ymax-1; y >= 0; y--) {
		for (x = 0; x < xmax; x++) {
			scanout[x][RED] = getc(stdin);
			scanout[x][GRN] = getc(stdin);
			scanout[x][BLU] = getc(stdin);
		}
		if (feof(stdin) | ferror(stdin))
			quiterr("error reading skel image");
						/* undo gamma */
		gambs_colrs(scanout, xmax);
		if (bradj)			/* adjust exposure */
			shiftcolrs(scanout, xmax, bradj);
		if (fwritecolrs(scanout, xmax, stdout) < 0)
			quiterr("error writing Radiance picture");
	}
						/* free scanline */
	free((void *)scanout);
}


ra2skel()		/* convert Radiance scanlines to 24-bit */
{
	COLR	*scanin;
	register int	x;
	int	y;
						/* allocate scanline */
	scanin = (COLR *)malloc(xmax*sizeof(COLR));
	if (scanin == NULL)
		quiterr("out of memory in ra2skel");
						/* convert image */
	for (y = ymax-1; y >= 0; y--) {
		if (freadcolrs(scanin, xmax, stdin) < 0)
			quiterr("error reading Radiance picture");
		if (bradj)			/* adjust exposure */
			shiftcolrs(scanin, xmax, bradj);
		colrs_gambs(scanin, xmax);	/* gamma correction */
		for (x = 0; x < xmax; x++) {
			putc(scanin[x][RED], stdout);
			putc(scanin[x][GRN], stdout);
			putc(scanin[x][BLU], stdout);
		}
		if (ferror(stdout))
			quiterr("error writing skel file");
	}
						/* free scanline */
	free((void *)scanin);
}
