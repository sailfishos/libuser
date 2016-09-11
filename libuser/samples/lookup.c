/*
 * Copyright (C) 2000-2002 Red Hat, Inc.
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
#include <errno.h>
#include <inttypes.h>
#include <libintl.h>
#include <locale.h>
#include <stdlib.h>
#include <unistd.h>
#include "../lib/user_private.h"

int
main(int argc, char **argv)
{
	struct lu_context *lu;
	gboolean success, group = FALSE, byid = FALSE;
	int c;
	id_t id;
	struct lu_ent *ent, *tmp;
	struct lu_error *error = NULL;
	const char *modules = NULL;

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	while ((c = getopt(argc, argv, "m:gn")) != -1) {
		switch (c) {
		case 'g':
			group = TRUE;
			break;
		case 'n':
			byid = TRUE;
			break;
		case 'm':
			modules = optarg;
			break;
		default:
			break;
		}
	}

	lu = lu_start(NULL, 0, modules, modules,
		      lu_prompt_console, NULL, &error);

	if (lu == NULL) {
		fprintf(stderr, gettext("Error initializing %s: %s\n"),
			PACKAGE, lu_strerror(error));
		return 1;
	}

	if (optind < argc) {
		intmax_t imax;
		char *end;

		errno = 0;
		imax = strtoimax(argv[optind], &end, 10);
		if (errno != 0 || *end != 0 || end == argv[optind]
		    || (id_t)imax != imax) {
			fprintf(stderr, gettext("Invalid ID %s\n"),
				argv[optind]);
			return 1;
		}
		id = imax;
	}
	else
		id = 0;

	tmp = lu_ent_new();
	if (group) {
		if (byid) {
			g_print(gettext("Searching for group with ID %jd.\n"),
				(intmax_t)id);
			success = lu_group_lookup_id(lu, id, tmp, &error);
		} else {
			g_print(gettext("Searching for group named %s.\n"),
				argv[optind]);
			success = lu_group_lookup_name(lu, argv[optind], tmp,
						       &error);
		}
	} else {
		if (byid) {
			g_print(gettext ("Searching for user with ID %jd.\n"),
				(intmax_t)id);
			success = lu_user_lookup_id(lu, id, tmp, &error);
		} else {
			g_print(gettext("Searching for user named %s.\n"),
				argv[optind]);
			success =
			    lu_user_lookup_name(lu, argv[optind], tmp,
						&error);
		}
	}

	ent = tmp;
	if (success) {
		fflush(NULL);
		lu_ent_dump(ent, stdout);
		fflush(NULL);
	} else {
		g_print(gettext("Entry not found.\n"));
	}

	lu_ent_free(ent);

	lu_end(lu);

	return 0;
}
