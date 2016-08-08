/*
 * Copyright (C) 2000-2002, 2004, 2005, 2006, 2007 Red Hat, Inc.
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
#include <glib.h>
#include <libintl.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#include <selinux/av_permissions.h>
#include <selinux/flask.h>
#include <selinux/context.h>
#endif
#include "../lib/error.h"
#include "../lib/user.h"
#include "../lib/user_private.h"
#include "apputil.h"

#ifdef WITH_SELINUX
static int
check_access(const char *chuser, access_vector_t access)
{
	int status;
	security_context_t user_context;

	status = -1;
	if (getprevcon(&user_context) == 0) {
		context_t c;
		const char *user;

		c = context_new(user_context);
		user = context_user_get(c);
		if (strcmp(chuser, user) == 0)
			status = 0;
		else {
			struct av_decision avd;
			int retval;

			retval = security_compute_av(user_context,
						     user_context,
						     SECCLASS_PASSWD,
 						     access, &avd);

			if (retval == 0 && (avd.allowed & access) == access)
				status = 0;
		}
		context_free(c);
		freecon(user_context);
	}
	return status;
}
#endif

#if 0
/* Concatenate a string onto another string on the heap. */
static char *
lu_strconcat(char *existing, const char *appendee)
{
	if (existing == NULL) {
		existing = g_strdup(appendee);
	} else {
		char *tmp;
		tmp = g_strconcat(existing, appendee, NULL);
		g_free(existing);
		existing = tmp;
	}
	return existing;
}

struct conv_data {
	lu_prompt_fn *prompt;
	gpointer callback_data;
};

/* PAM callback information. */
static int
lu_converse(int num_msg, const struct pam_message **msg,
	    struct pam_response **resp, void *appdata_ptr)
{
	struct conv_data *data = appdata_ptr;
	struct lu_prompt prompts[num_msg];
	struct lu_error *error = NULL;
	struct pam_response *responses;
	char *pending = NULL, *p;
	int i;

	memset(&prompts, 0, sizeof(prompts));

	/* Convert the PAM prompts to our own prompter type. */
	for (i = 0; i < num_msg; i++) {
		switch ((*msg)[i].msg_style) {
			case PAM_PROMPT_ECHO_ON:
				/* Append this text to any pending output text
				 * we already have. */
				prompts[i].prompt = lu_strconcat(pending,
								 (*msg)[i].msg);
				p = strrchr(prompts[i].prompt, ':');
				if (p != NULL) {
					*p = '\0';
				}
				prompts[i].visible = TRUE;
				pending = NULL;
				break;
			case PAM_PROMPT_ECHO_OFF:
				/* Append this text to any pending output text
				 * we already have. */
				prompts[i].prompt = lu_strconcat(pending,
								 (*msg)[i].msg);
				p = strrchr(prompts[i].prompt, ':');
				if (p != NULL) {
					*p = '\0';
				}
				prompts[i].visible = FALSE;
				pending = NULL;
				break;
			default:
				/* Make this pending output text. */
				pending = lu_strconcat(pending, (*msg)[i].msg);
				break;
		}
	}
	g_free(pending); /* Discards trailing PAM_ERROR_MSG or PAM_TEXT_INFO */

	/* Prompt the user. */
	if (data->prompt(prompts, num_msg, data->callback_data, &error)) {
		/* Allocate room for responses.  This memory will be
		 * freed by the calling application, so use malloc() instead
		 * of g_malloc() and friends. */
		responses = calloc(num_msg, sizeof(*responses));
		if (responses == NULL)
			return PAM_BUF_ERR;
		/* Transcribe the responses into the PAM structure. */
		for (i = 0; i < num_msg; i++) {
			/* Set the response code and text (if we have text),
			 * and free the prompt text. */
			responses[i].resp_retcode = PAM_SUCCESS;
			if (prompts[i].value != NULL) {
				responses[i].resp = strdup(prompts[i].value);
				prompts[i].free_value(prompts[i].value);
			}
			g_free((gpointer) prompts[i].prompt);
		}
		/* Set the return pointer. */
		*resp = responses;
	}

	if (error != NULL) {
		lu_error_free(&error);
	}

	return PAM_CONV_ERR;
}
#endif

/* Authenticate the user if the invoking user is not privileged.  If
 * authentication fails, exit immediately. */
void
lu_authenticate_unprivileged(struct lu_context *ctx, const char *user,
			     const char *appname)
{
	pam_handle_t *pamh;
	struct pam_conv conv;
	const void *puser;
	int ret;

	/* Don't bother (us and the user) if none of the modules makes use of
	 * elevated privileges and the program is not set*id. */
	if (lu_uses_elevated_privileges(ctx) == FALSE
	    && geteuid() == getuid() && getegid() == getgid())
		return;
#if 0
	struct conv_data data;
	/* Don't bother if none of the modules makes use of elevated
	 * privileges. */
	if (lu_uses_elevated_privileges(ctx) == FALSE) {
		/* Great!  We can drop privileges. */
		if (setegid(getgid()) == -1) {
			fprintf(stderr, _("Failed to drop privileges.\n"));
			goto err;
		}
		if (seteuid(getuid()) == -1) {
			fprintf(stderr, _("Failed to drop privileges.\n"));
			goto err;
		}
		return;
	}

	/* Get the address of the glue conversation function. */
	lu_get_prompter(ctx, &data.prompt, &data.callback_data);
	if (data.prompt == NULL) {
		fprintf(stderr, _("Internal error.\n"));
		goto err;
	}

	conv.conv = lu_converse;
	conv.appdata_ptr = &data;

#endif
	conv.conv = misc_conv;
	conv.appdata_ptr = NULL;

#ifdef WITH_SELINUX
	if (is_selinux_enabled() > 0) {
		/* FIXME: PASSWD_CHSH, PASSWD_PASSWD ? */
		if (getuid() == 0 && check_access(user, PASSWD__CHFN) != 0) {
			security_context_t user_context;

			if (getprevcon(&user_context) < 0)
				user_context = NULL;
			/* FIXME: "change the finger info?" */
			fprintf(stderr,
				_("%s is not authorized to change the finger "
				  "info of %s\n"), user_context ? user_context
				: _("Unknown user context"), user);
			if (user_context != NULL)
				freecon(user_context);
			goto err;
		}
		/* FIXME: is this right for lpasswd? */
		if (!lu_util_fscreate_from_file("/etc/passwd", NULL)) {
			fprintf(stderr,
				_("Can't set default context for "
				  "/etc/passwd\n"));
			goto err;
		}
	}
#endif

	/* Start up PAM. */
	if (pam_start(appname, user, &conv, &pamh) != PAM_SUCCESS) {
		fprintf(stderr, _("Error initializing PAM.\n"));
		goto err;
	}

	/* Use PAM to authenticate the user. */
	ret = pam_authenticate(pamh, 0);
	if (ret != PAM_SUCCESS) {
		if (pam_get_item(pamh, PAM_USER, &puser) != PAM_SUCCESS
		    || puser == NULL)
			puser = user;
		fprintf(stderr, _("Authentication failed for %s.\n"),
			(const char *)puser);
		goto err_pam;
	}

	/* Make sure we authenticated the user we wanted to authenticate. */
	ret = pam_get_item(pamh, PAM_USER, &puser);
	if (ret != PAM_SUCCESS) {
		fprintf(stderr, _("Internal PAM error `%s'.\n"),
			pam_strerror(pamh, ret));
		goto err_pam;
	}
	if (puser == NULL) {
		fprintf(stderr, _("Unknown user authenticated.\n"));
		goto err_pam;
	}
	if (strcmp(puser, user) != 0) {
		fprintf(stderr, _("User mismatch.\n"));
		goto err_pam;
	}

	/* Check if the user is allowed to run this program. */
	ret = pam_acct_mgmt(pamh, 0);
	if (ret != PAM_SUCCESS) {
		if (pam_get_item(pamh, PAM_USER, &puser) != PAM_SUCCESS
		    || puser == NULL)
			puser = user;
		fprintf(stderr, _("Authentication failed for %s.\n"),
			(const char *)puser);
		goto err_pam;
	}

	/* Clean up -- we're done. */
	pam_end(pamh, PAM_SUCCESS);
	return;

err_pam:
	pam_end(pamh, ret);
err:
	exit(1);
}
