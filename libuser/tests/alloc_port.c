/* Copyright (C) 2011 Red Hat, Inc.
 *
 * This is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <config.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#undef NDEBUG
#include <assert.h>

/* Ask the kernel to allocate a port for 127.0.0.1, and return it.  Reusing the
   port number is inherently racy, but the kernel tends to randomize the
   returned port number, so this makes collisions (with concurrently running
   variants of the same test suite) extremely unlikely. */
int
main(void)
{
  static const int reuse = 1;

  struct sockaddr_in sin;
  socklen_t len;
  int sock;

  sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  assert(sock != -1);

  assert(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == 0);

  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr("127.0.0.1");
  sin.sin_port = htons(0);
  assert(bind(sock, (const struct sockaddr *)&sin, sizeof(sin)) == 0);

  len = sizeof(sin);
  assert(getsockname(sock, (struct sockaddr *)&sin, &len) == 0);
  printf("%d\n", (int)ntohs(sin.sin_port));

  close(sock);

  return EXIT_SUCCESS;
}
