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
#include <libintl.h>
#include <locale.h>
#include <stdlib.h>
#include <unistd.h>
#include "../lib/user_private.h"

int
main(void)
{
	struct lu_prompt prompts[] = {
		{"main/name", "Name", PACKAGE, TRUE,
		 g_strdup("anonymous"), NULL, NULL},
		{"main/password1", "Password1", PACKAGE, TRUE,
		 g_strdup("anonymous"), NULL, NULL},
		{"main/password2", "Password2", PACKAGE, FALSE,
		 g_strdup("anonymous"), NULL, NULL},
	};
	struct lu_error *error = NULL;

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	if (lu_prompt_console(prompts,
			      sizeof(prompts) / sizeof(prompts[0]),
			      NULL, &error)) {
		size_t i;

		g_print(gettext("Prompts succeeded.\n"));
		for (i = 0; i < sizeof(prompts) / sizeof(prompts[0]); i++) {
			if (prompts[i].value) {
				g_print("`%s'\n", prompts[i].value);
				prompts[i].free_value(prompts[i].value);
			} else {
				g_print("(null)\n");
			}
		}
	} else {
		g_print(gettext("Prompts failed.\n"));
	}

	return 0;
}
