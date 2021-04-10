/*
 * Copyright 2003 James Bursa <bursa@users.sourceforge.net>
 * Copyright 2004 John Tytgat <John.Tytgat@aaug.net>
 *
 * This file is part of NetSurf, http://www.netsurf-browser.org/
 * Licenced under the MIT License,
 *                http://www.opensource.org/licenses/mit-license.php
 */

#include <stdio.h>

#ifndef _LIBNSGIF_LOG_H_
#define _LIBNSGIF_LOG_H_

#ifdef NDEBUG
#  define LOG(x) ((void) 0)
#else
#  define LOG(x) do { fprintf(stderr, x), fputc('\n', stderr); } while (0)
#endif /* NDEBUG */

#endif /* _LIBNSGIF_LOG_H_ */
