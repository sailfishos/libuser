/*
 * Copyright (C) 2001,2002 Red Hat, Inc.
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
#include <libintl.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "../apps/apputil.h"

int
main(int argc, char **argv)
{
	struct lu_error *error = NULL;
	int add = 0, mod = 0, rem = 0, c;

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	while ((c = getopt(argc, argv, "arm")) != -1) {
		switch (c) {
		case 'a':
			add = 1;
			break;
		case 'r':
			rem = 1;
			break;
		case 'm':
			mod = 1;
			break;
		default:
			break;
		}
	}

	if (add) {
		struct lu_context *ctx;
		struct lu_error *error;

		error = NULL;
		ctx = lu_start(NULL, 0, NULL, NULL, lu_prompt_console, NULL,
			       &error);
		if (ctx == NULL) {
			fprintf(stderr, gettext("Error initializing %s: %s\n"),
				PACKAGE, lu_strerror(error));
			return 1;
		}
		if (!lu_homedir_populate(ctx, "/etc/skel", argv[optind], 500,
					 500, 0700, &error)) {
			fprintf(stderr, "populate_homedir(%s) failed: %s\n",
				argv[optind], lu_strerror(error));
			return 1;
		}
		lu_end(ctx);
	}
	if (mod
	    && !lu_homedir_move(argv[optind], argv[optind + 1], &error)) {
		fprintf(stderr, "move_homedir(%s, %s) failed: %s\n",
			argv[optind], argv[optind + 1], lu_strerror(error));
		return 1;
	}
	if (rem && !lu_homedir_remove(argv[optind], &error)) {
		fprintf(stderr, "remove_homedir(%s) failed: %s\n",
			argv[optind], lu_strerror(error));
		return 1;
	}

	return 0;
}
