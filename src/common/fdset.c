/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* Required for RTLD_DEFAULT. */
#endif

#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "common/fdset.h"
#include <config.h>

/* Workarounds for clock_gettime() not available on some platforms. */
#ifdef HAVE_CLOCK_GETTIME
#define time_now(x) clock_gettime(CLOCK_MONOTONIC, (x))
typedef struct timespec timev_t;
#elif HAVE_GETTIMEOFDAY
#define time_now(x) gettimeofday((x), NULL)
typedef struct timeval timev_t;
#else
#error Neither clock_gettime() nor gettimeofday() found. At least one is required.
#endif

struct fdset_backend_t _fdset_backend = {
};

/*! \brief Set backend implementation. */
static void fdset_set_backend(struct fdset_backend_t *backend) {
	memcpy(&_fdset_backend, backend, sizeof(struct fdset_backend_t));
}

/* Linux epoll API. */
#ifdef HAVE_EPOLL_WAIT
  #include "common/fdset_epoll.h"
#endif /* HAVE_EPOLL_WAIT */

/* BSD kqueue API */
#ifdef HAVE_KQUEUE
  #include "common/fdset_kqueue.h"
#endif /* HAVE_KQUEUE */

/* POSIX poll API */
#ifdef HAVE_POLL
  #include "common/fdset_poll.h"
#endif /* HAVE_POLL */

/*! \brief Bootstrap polling subsystem (it is called automatically). */
void __attribute__ ((constructor)) fdset_init()
{
	/* Preference: epoll */
#ifdef HAVE_EPOLL_WAIT
	if (dlsym(RTLD_DEFAULT, "epoll_wait") != 0) {
		fdset_set_backend(&FDSET_EPOLL);
		return;
	}
#endif

	/* Preference: kqueue */
#ifdef HAVE_KQUEUE
	if (dlsym(RTLD_DEFAULT, "kqueue") != 0) {
		fdset_set_backend(&FDSET_KQUEUE);
		return;
	}
#endif

	/* Fallback: poll */
#ifdef HAVE_POLL
	if (dlsym(RTLD_DEFAULT, "poll") != 0) {
		fdset_set_backend(&FDSET_POLL);
		return;
	}
#endif

	/* This shouldn't happen. */
	fprintf(stderr, "fdset: fatal error - no valid fdset backend found\n");
	return;
}

/*!
 * \brief Compare file descriptors.
 *
 * \param a File descriptor.
 * \param b File descriptor.
 *
 * \retval -1 if a < b
 * \retval  0 if a == b
 * \retval  1 if a > b
 */
static int fdset_compare(void *a, void *b)
{
	if ((size_t)a < (size_t)b) return -1;
	if ((size_t)a > (size_t)b) return  1;
	return 0;
}

fdset_t *fdset_new() {
	fdset_t* set = _fdset_backend.fdset_new();
	fdset_base_t *base = (fdset_base_t*)set;
	if (base != NULL) {
		/* Create atimes list. */
		base->atimes = skip_create_list(fdset_compare);
		if (base->atimes == NULL) {
			fdset_destroy(set);
			set = NULL;
		}
	}
	return set;
}

int fdset_destroy(fdset_t* fdset) {
	fdset_base_t *base = (fdset_base_t*)fdset;
	if (base != NULL && base->atimes != NULL) {
		skip_destroy_list(&base->atimes, NULL, free);
	}
	return _fdset_backend.fdset_destroy(fdset);
}

int fdset_remove(fdset_t *fdset, int fd) {
	fdset_base_t *base = (fdset_base_t*)fdset;
	if (base != NULL && base->atimes != NULL) {
		skip_remove(base->atimes, (void*)((size_t)fd), NULL, free);
	}
	return _fdset_backend.fdset_remove(fdset, fd);
}

int fdset_set_watchdog(fdset_t* fdset, int fd, int interval)
{
	fdset_base_t *base = (fdset_base_t*)fdset;
	if (base == NULL || base->atimes == NULL) {
		return -1;
	}
	
	/* Lift watchdog if interval is negative. */
	if (interval < 0) {
		skip_remove(base->atimes, (void*)((size_t)fd), NULL, free);
		return 0;
	}
	
	/* Find if exists. */
	timev_t *ts = NULL;
	ts = (timev_t*)skip_find(base->atimes, (void*)((size_t)fd));
	if (ts == NULL) {
		ts = malloc(sizeof(timev_t));
		if (ts == NULL) {
			return -1;
		}
		skip_insert(base->atimes, (void*)((size_t)fd), (void*)ts, NULL);
	}
	
	/* Update clock. */
	if (time_now(ts) < 0) {
		return -1;
	}
	
	ts->tv_sec += interval; /* Only seconds precision. */
	return 0;
}

int fdset_sweep(fdset_t* fdset, void(*cb)(fdset_t*, int))
{
	fdset_base_t *base = (fdset_base_t*)fdset;
	if (base == NULL || base->atimes == NULL) {
		return -1;
	}
	
	/* Get time threshold. */
	timev_t now;
	if (time_now(&now) < 0) {
		return -1;
	}
	
	/* Inspect all nodes. */
	int sweeped = 0;
	const skip_node_t *n = skip_first(base->atimes);
	while (n != NULL) {
		const skip_node_t* pnext = skip_next(n);
		
		/* Evaluate */
		timev_t *ts = (timev_t*)n->value;
		if (ts->tv_sec <= now.tv_sec) {
			cb(fdset, (int)(((ssize_t)n->key)));
			++sweeped;
		}
		n = pnext;
	}
	
	return sweeped;
}
