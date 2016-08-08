/* Copyright (C) 2012 Red Hat, Inc.
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
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#undef NDEBUG
#include <assert.h>

static int
slapd_exited(const char *pid_file, int sock, const struct sockaddr_in *sin)
{
  return access(pid_file, F_OK) != 0
    && connect(sock, (const struct sockaddr *)sin, sizeof (*sin)) != 0;
}

/* Wait for slapd to remove its pid file and close its socket. */
int
main(int argc, char *argv[])
{
  long port;
  char *p;
  struct sockaddr_in sin;
  int sock, i;

  assert(argc == 3);

  errno = 0;
  port = strtol(argv[2], &p, 10);
  assert (errno == 0 && *p == 0 && p != argv[2] && (in_port_t)port == port);

  sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  assert(sock != -1);

  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr("127.0.0.1");
  sin.sin_port = htons(port);

  for (i = 0; i < 50; i++)
    {
      printf("\rWaiting for slapd exit: %.1f...", i / 10.0);
      fflush(stdout);
      if (slapd_exited(argv[1], sock, &sin))
	goto ok;
      usleep(100000);
    }
  for (i = 5; i < 30; i++)
    {
      printf("\rWaiting for slapd exit: %d...  ", i);
      fflush(stdout);
      if (slapd_exited(argv[1], sock, &sin))
	goto ok;
      sleep(1);
    }

  close(sock);
  putchar('\n');
  fprintf(stderr, "Timeout waiting for exit\n");
  return EXIT_FAILURE;

 ok:
  close(sock);
  putchar('\n');
  return EXIT_SUCCESS;
}
