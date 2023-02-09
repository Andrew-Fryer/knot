/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <signal.h>

#include "knot/server/udp-handler.c"
#include "knot/common/log.h"

extern int fuzz_input_fd;
FILE *fuzz_input_file;

typedef struct {
	struct iovec iov[NBUFS];
	uint8_t buf[NBUFS][KNOT_WIRE_MAX_PKTSIZE];
	struct sockaddr_storage addr;
	bool afl_persistent;
} udp_stdin_t;

static inline void next(udp_stdin_t *rq)
{
	exit(0);
	// printf("this is running\n");
	// return;
	// printf("this is not running\n");
	// if (rq->afl_persistent) {
	// 	raise(SIGSTOP);
	// } else {
	// 	exit(0);
	// }
}

static void *udp_stdin_init(_unused_ udp_context_t *ctx, _unused_ void *xdp_sock)
{
	udp_stdin_t *rq = calloc(1, sizeof(udp_stdin_t));
	if (rq == NULL) {
		return NULL;
	}

	for (unsigned i = 0; i < NBUFS; ++i) {
		rq->iov[i].iov_base = rq->buf[i];
		rq->iov[i].iov_len = KNOT_WIRE_MAX_PKTSIZE;
	}

	struct sockaddr_in *a = (struct sockaddr_in *)&rq->addr;
	a->sin_family = AF_INET;
	a->sin_addr.s_addr = IN_LOOPBACKNET;
	a->sin_port = 42;

	rq->afl_persistent = getenv("AFL_PERSISTENT") != NULL;

	return rq;
}

static void udp_stdin_deinit(void *d)
{
	free(d);
}

static int udp_stdin_recv(_unused_ int fd, void *d)
{
	udp_stdin_t *rq = (udp_stdin_t *)d;
	printf("andrew: trying to read data\n");
	rq->iov[RX].iov_len = fread(rq->iov[RX].iov_base, 1,
	                            KNOT_WIRE_MAX_PKTSIZE, fuzz_input_file);
	if (rq->iov[RX].iov_len == 0) {
		printf("andrew: this shouldn't be happening (if our input file isn't empty)\n");
		next(rq);
	}

	return rq->iov[RX].iov_len;
}

static void udp_stdin_handle(udp_context_t *ctx, void *d)
{
	udp_stdin_t *rq = (udp_stdin_t *)d;
	udp_handle(ctx, STDIN_FILENO, &rq->addr, &rq->iov[RX], &rq->iov[TX], false);
}

static void udp_stdin_send(void *d)
{
	printf("andrew: in udp_stdin_send\n");
	udp_stdin_t *rq = (udp_stdin_t *)d;
	// write(3, "andrew: buf 0:\n", 15);
	// write(3, rq->iov[0].iov_base, rq->iov[0].iov_len);
	// write(3, "andrew: buf 1:\n", 15);
	write(3, rq->iov[1].iov_base, rq->iov[1].iov_len);
	next(rq);
}

static udp_api_t stdin_api = {
	udp_stdin_init,
	udp_stdin_deinit,
	udp_stdin_recv,
	udp_stdin_handle,
	udp_stdin_send
};

void udp_master_init_stdio(server_t *server) {

	log_info("AFL, UDP handler listening on stdin");

	// Register dummy interface to server.
	iface_t *ifc = calloc(1, sizeof(*ifc));
	assert(ifc);
	ifc->fd_udp = calloc(1, sizeof(*ifc->fd_udp));
	assert(ifc->fd_udp);
	ifc->fd_udp[0] = fuzz_input_fd;
	fuzz_input_file = fdopen(fuzz_input_fd, "r");
	// char buf[10];
	// int ret = read(fuzz_input_fd, buf, 10);
	// printf("reading %d bytes: ", ret);
	// for(int i = 0; i < ret; i++) {
	// 	printf("%x ", buf[i]);
	// }
	// printf(";\n");
	ifc->fd_udp_count = 1;

	server->n_ifaces = 1;
	server->ifaces = ifc;

	udp_recvfrom_api = stdin_api;
#ifdef ENABLE_RECVMMSG
	udp_recvmmsg_api = stdin_api;
#endif
}
