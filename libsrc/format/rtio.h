/* RCSid $Id: rtio.h,v 3.9 2006/12/23 17:27:45 greg Exp $ */
/*
 *	Radiance i/o and string routines
 */

#ifndef _RAD_RTIO_H_
#define _RAD_RTIO_H_

#include  <stdio.h>
#include  <sys/types.h>
#include  <fcntl.h>
#include  <string.h>

#ifdef __cplusplus
extern "C" {
#endif
					/* defined in badarg.c */
extern int	badarg(int ac, char **av, char *fl);
					/* defined in expandarg.c */
extern int	expandarg(int *acp, char ***avp, int n);
					/* defined in fdate.c */
extern time_t	fdate(char *fname);
extern int	setfdate(char *fname, long ftim);
					/* defined in fgetline.c */
extern char	*fgetline(char *s, int n, FILE *fp);
					/* defined in fgetval.c */
extern int	fgetval(FILE *fp, int ty, void *vp);
					/* defined in fgetword.c */
extern char	*fgetword(char *s, int n, FILE *fp);
					/* defined in fputword.c */
extern void	fputword(char *s, FILE *fp);
					/* defined in fropen.c */
extern FILE	*frlibopen(char *fname);
					/* defined in getlibpath.c */
extern char	*getrlibpath(void);
					/* defined in gethomedir.c */
extern char *gethomedir(char *uname, char *path, int plen);
					/* defined in getpath.c */
extern char	*getpath(char *fname, char *searchpath, int mode);
					/* defined in byteswap.c */
extern void	swap16(char *wp, int n);
extern void	swap32(char *wp, int n);
extern void	swap64(char *wp, int n);
					/* defined in portio.c */
extern void	putstr(char *s, FILE *fp);
extern void	putint(long i, int siz, FILE *fp);
extern void	putflt(double f, FILE *fp);
extern char	*getstr(char *s, FILE *fp);
extern long	getint(int siz, FILE *fp);
extern double	getflt(FILE *fp);
					/* defined in rexpr.c */
extern int	ecompile(char *sp, int iflg, int wflag);
extern char	*expsave(void);
extern void	expset(char *ep);
extern char	*eindex(char *sp);
					/* defined in savestr.c */
extern char	*savestr(char *str);
extern void	freestr(char *s);
extern int	shash(char *s);
					/* defined in savqstr.c */
extern char	*savqstr(char *s);
extern void	freeqstr(char *s);
					/* defined in wordfile.c */
extern int	wordfile(char **words, char *fname);
extern int	wordstring(char **avl, char *str);
					/* defined in words.c */
extern char	*atos(char *rs, int nb, char *s);
extern char	*nextword(char *cp, int nb, char *s);
extern char	*sskip(char *s);
extern char	*sskip2(char *s, int n);
extern char	*iskip(char *s);
extern char	*fskip(char *s);
extern int	isint(char *s);
extern int	isintd(char *s, char *ds);
extern int	isflt(char *s);
extern int	isfltd(char *s, char *ds);
					/* defined in lamp.c */
extern float *	matchlamp(char *s);
extern int	loadlamps(char *file);
extern void	freelamps(void);

#ifdef __cplusplus
}
#endif
#endif /* _RAD_RTIO_H_ */

