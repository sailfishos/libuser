/*
 * Copyright (C) 2000-2002, 2004, 2005, 2006, 2007, 2008 Red Hat, Inc.
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
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <inttypes.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../lib/user_private.h"

#define CHUNK_SIZE	(LINE_MAX * 4)

LU_MODULE_INIT(libuser_files_init)
LU_MODULE_INIT(libuser_shadow_init)

enum lock_op { LO_LOCK, LO_UNLOCK, LO_UNLOCK_NONEMPTY };

/* Guides for parsing and formatting entries in the files we're looking at. */
struct format_specifier {
	const char *attribute;
	const char *def;
	gboolean multiple, suppress_if_def, def_if_empty;
};

static const struct format_specifier format_passwd[] = {
	{ LU_USERNAME, NULL, FALSE, FALSE, FALSE },
	{ LU_USERPASSWORD, LU_COMMON_DEFAULT_PASSWORD, FALSE, FALSE, FALSE },
	{ LU_UIDNUMBER, NULL, FALSE, FALSE, FALSE },
	{ LU_GIDNUMBER, NULL, FALSE, FALSE, FALSE },
	{ LU_GECOS, NULL, FALSE, FALSE, FALSE },
	{ LU_HOMEDIRECTORY, NULL, FALSE, FALSE, FALSE },
	{ LU_LOGINSHELL, LU_COMMON_DEFAULT_SHELL, FALSE, FALSE, TRUE },
};

static const struct format_specifier format_group[] = {
	{ LU_GROUPNAME, NULL, FALSE, FALSE, FALSE },
	{ LU_GROUPPASSWORD, LU_COMMON_DEFAULT_PASSWORD, FALSE, FALSE, FALSE },
	{ LU_GIDNUMBER, NULL, FALSE, FALSE, FALSE },
	{ LU_MEMBERNAME, NULL, TRUE, FALSE, FALSE },
};

static const struct format_specifier format_shadow[] = {
	{ LU_SHADOWNAME, NULL, FALSE, FALSE, FALSE },
	{ LU_SHADOWPASSWORD, LU_COMMON_DEFAULT_PASSWORD, FALSE, FALSE, FALSE },
	{ LU_SHADOWLASTCHANGE, "-1", FALSE, TRUE, TRUE },
	{ LU_SHADOWMIN, "-1", FALSE, TRUE, TRUE },
	{ LU_SHADOWMAX, "-1", FALSE, TRUE, TRUE },
	{ LU_SHADOWWARNING, "-1", FALSE, TRUE, TRUE },
	{ LU_SHADOWINACTIVE, "-1", FALSE, TRUE, TRUE },
	{ LU_SHADOWEXPIRE, "-1", FALSE, TRUE, TRUE },
	{ LU_SHADOWFLAG, "-1", FALSE, TRUE, TRUE },
};

static const struct format_specifier format_gshadow[] = {
	{ LU_GROUPNAME, NULL, FALSE, FALSE, FALSE },
	{ LU_SHADOWPASSWORD, LU_COMMON_DEFAULT_PASSWORD, FALSE, FALSE, FALSE },
	{ LU_ADMINISTRATORNAME, NULL, TRUE, FALSE, FALSE },
	{ LU_MEMBERNAME, NULL, TRUE, FALSE, FALSE },
};

/* Use these variables instead of string constants mainly to eliminate the risk
   of a typo */
static const char suffix_passwd[] = "/passwd";
static const char suffix_shadow[] = "/shadow";
static const char suffix_group[] = "/group";
static const char suffix_gshadow[] = "/gshadow";

/* Return the path of FILE_SUFFIX configured in MODULE, for g_free() */
static char *
module_filename(struct lu_module *module, const char *file_suffix)
{
	const char *dir;
	char *key;

	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	g_free(key);
	return g_strconcat(dir, file_suffix, NULL);
}

/* Copy contents of INPUT_FILENAME to OUTPUT_FILENAME, exclusively creating it
 * if EXCLUSIVE.
 * Return the file descriptor for OUTPUT_FILENAME, open for reading and writing,
 * or -1 on error.
 * Note that this does no locking and assumes the directories hosting the files
 * are not being manipulated by an attacker. */
static int
open_and_copy_file(const char *input_filename, const char *output_filename,
		   gboolean exclusive, struct lu_error **error)
{
	int ifd, ofd;
	struct stat st;
	int res = -1;
	int flags;

	g_assert(input_filename != NULL);
	g_assert(strlen(input_filename) > 0);
	g_assert(output_filename != NULL);
	g_assert(strlen(output_filename) > 0);

	/* Open the input file. */
	ifd = open(input_filename, O_RDONLY);
	if (ifd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), input_filename,
			     strerror(errno));
		goto err;
	}

	/* Read the input file's size. */
	if (fstat(ifd, &st) == -1) {
		lu_error_new(error, lu_error_stat,
			     _("couldn't stat `%s': %s"), input_filename,
			     strerror(errno));
		goto err_ifd;
	}

	/* We only need O_WRONLY, but the caller needs RDWR if ofd will be
	 * used as e->new_fd. */
	flags = O_RDWR | O_CREAT;
	if (exclusive) {
		/* This ensures that if there is a concurrent writer which is
		 * not doing locking for some reason, we will not truncate their
		 * temporary file. Still, the other writer may truncate our
		 * file, and ultimately the rename() committing the changes will
		 * lose one or the other set of changes. */
		(void)unlink(output_filename);
		flags |= O_EXCL;
	} else
		flags |= O_TRUNC;
	/* Start with absolutely restrictive permissions to make sure nobody
	 * can get a file descriptor for this file until we are done resetting
	 * ownership. */
	ofd = open(output_filename, flags, 0);
	if (ofd == -1) {
		lu_error_new(error, lu_error_open,
			     _("error creating `%s': %s"), output_filename,
			     strerror(errno));
		goto err_ifd;
	}

	/* Set the permissions on the new file to match the old one. */
	if (fchown(ofd, st.st_uid, st.st_gid) == -1 && errno != EPERM) {
		lu_error_new(error, lu_error_generic,
			     _("Error changing owner of `%s': %s"),
			     output_filename, strerror(errno));
		goto err_ofd;
	}
	if (fchmod(ofd, st.st_mode) == -1) {
		lu_error_new(error, lu_error_generic,
			     _("Error changing mode of `%s': %s"),
			     output_filename, strerror(errno));
		goto err_ofd;
	}

	/* Copy the data, block by block. */
	for (;;) {
		char buf[CHUNK_SIZE];
		ssize_t left;
		char *p;

		left = read(ifd, &buf, sizeof(buf));
		if (left == -1) {
			if (errno == EINTR)
				continue;
			lu_error_new(error, lu_error_read,
				     _("Error reading `%s': %s"),
				     input_filename, strerror(errno));
			goto err_ofd;
		}
		if (left == 0)
			break;
		p = buf;
		while (left > 0) {
			ssize_t out;

			out = write(ofd, p, left);
			if (out == -1) {
				if (errno == EINTR)
					continue;
				lu_error_new(error, lu_error_write,
					     _("Error writing `%s': %s"),
					     output_filename, strerror(errno));
				goto err_ofd;
			}
			p += out;
			left -= out;
		}
	}

	/* Flush data to disk. */
	if (fsync(ofd) != 0 || lseek(ofd, 0, SEEK_SET) == -1) {
		lu_error_new(error, lu_error_write, _("Error writing `%s': %s"),
			     output_filename, strerror(errno));
		goto err_ofd;
	}
	res = ofd;
	goto err_ifd; /* Do not close ofd */

 err_ofd:
	close(ofd);
 err_ifd:
	close(ifd);
 err:
	return res;
}

/* Deal with an existing LOCK_FILENAME.
 * Return TRUE if the caller should try again. */
static gboolean
lock_file_handle_existing(const char *lock_filename, struct lu_error **error)
{
	gchar *lock_contents;
	GError *gerror;
	gboolean ret = FALSE;
	uintmax_t pid;
	char *p;

	gerror = NULL;
	if (g_file_get_contents(lock_filename, &lock_contents, NULL, &gerror)
	    == FALSE) {
		lu_error_new(error, lu_error_read,
			     _("couldn't read from `%s': %s"), lock_filename,
			     gerror->message);
		g_error_free(gerror);
		goto err;
	}
	errno = 0;
	pid = strtoumax(lock_contents, &p, 10);
	if (errno != 0 || *p != 0 || p == lock_contents || (pid_t)pid != pid) {
		lu_error_new(error, lu_error_lock,
			     _("Invalid contents of lock `%s'"), lock_filename);
		goto err_lock_contents;
	}
	if (kill(pid, 0) == 0 || errno != ESRCH) {
		lu_error_new(error, lu_error_lock,
			     _("The lock %s is held by process %ju"),
			     lock_filename, pid);
		goto err_lock_contents;
	}
	/* This is unfixably racy, but that should matter only if a genuine
	 * lock owner crashes. */
	if (unlink(lock_filename) != 0) {
		lu_error_new(error, lu_error_lock,
		     _("Error removing stale lock `%s': %s"), lock_filename,
		     strerror(errno));
		goto err_lock_contents;
	}
	ret = TRUE;
	/* Fall through */

err_lock_contents:
	g_free(lock_contents);
err:
	return ret;
}

/* Create a lock file for FILENAME. */
static gboolean
lock_file_create(const char *filename, struct lu_error **error)
{
	char *lock_filename, *tmp_filename;
	char pid_string[sizeof (pid_t) * CHAR_BIT + 1];
	int fd;
	gboolean ret = FALSE;

	lock_filename = g_strconcat(filename, ".lock", NULL);
	tmp_filename = g_strdup_printf("%s.lock.XXXXXX", filename);

	fd = mkstemp(tmp_filename);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("error opening temporary file for `%s': %s"),
			     lock_filename, strerror(errno));
		goto err_tmp_filename;
	}
	if (snprintf(pid_string, sizeof(pid_string), "%ju", (uintmax_t)getpid())
	    >= sizeof(pid_string))
		g_assert_not_reached();
	if (write(fd, pid_string, strlen(pid_string)) != strlen(pid_string)) {
		lu_error_new(error, lu_error_write, _("Error writing `%s': %s"),
			     tmp_filename, strerror(errno));
		close(fd);
		goto err_tmp_file;
	}
	close(fd);

	if (link(tmp_filename, lock_filename) != 0) {
		if (errno == EEXIST) {
			if (lock_file_handle_existing(lock_filename, error)
			    == FALSE)
				goto err_tmp_file;
			if (link(tmp_filename, lock_filename) == 0)
				goto got_link;
		}
		lu_error_new(error, lu_error_lock,
			     _("Cannot obtain lock `%s': %s"), lock_filename,
			     strerror(errno));
		goto err_tmp_file;
	}
got_link:
	ret = TRUE;
	/* Fall through */

err_tmp_file:
	(void)unlink(tmp_filename);
err_tmp_filename:
	g_free(tmp_filename);
	g_free(lock_filename);
	return ret;
}

/* Remove the lock file for FILENAME. */
static void
lock_file_remove(const char *filename)
{
	char *lock_file;

	lock_file = g_strconcat(filename, ".lock", NULL);
	(void)unlink(lock_file);
	g_free(lock_file);
}

/* State related to a file currently open for editing. */
struct editing {
	char *filename;
	lu_security_context_t fscreate;
	char *new_filename;
	int new_fd;
};

/* Open and lock FILE_SUFFIX in MODULE for editing.
 * Return editing state, or NULL on error. */
static struct editing *
editing_open(struct lu_module *module, const char *file_suffix,
	     struct lu_error **error)
{
	struct editing *e;
	char *backup_name;
	int fd;

	e = g_malloc0(sizeof (*e));
	e->filename = module_filename(module, file_suffix);
	/* Make sure this all works if e->filename is a symbolic link, at least
	 * as long as it points to the same file system. */

	if (geteuid() == 0) {
		if (lckpwdf() != 0) {
			lu_error_new(error, lu_error_lock,
				     _("error locking file: %s"),
				     strerror(errno));
			goto err_filename;
		}
	}
	if (lock_file_create(e->filename, error) == FALSE)
		goto err_lckpwdf;

	if (!lu_util_fscreate_save(&e->fscreate, error))
		goto err_locked;
	if (!lu_util_fscreate_from_file(e->filename, error))
		goto err_fscreate;

	backup_name = g_strconcat(e->filename, "-", NULL);
	fd = open_and_copy_file(e->filename, backup_name, FALSE, error);
	g_free (backup_name);
	close(fd);
	if (fd == -1)
		goto err_fscreate;

	e->new_filename = g_strconcat(e->filename, "+", NULL);
	e->new_fd = open_and_copy_file(e->filename, e->new_filename, TRUE,
			       	       error);
	if (e->new_fd == -1)
		goto err_new_filename;

	return e;

err_new_filename:
 	g_free(e->new_filename);
err_fscreate:
	lu_util_fscreate_restore(e->fscreate);

err_locked:
	(void)lock_file_remove(e->filename);
err_lckpwdf:
	if (geteuid() == 0)
		(void)ulckpwdf();

err_filename:
 	g_free(e->filename);
 	g_free(e);
 	return NULL;
}


/* Replace DESTINATION with SOURCE, even if DESTINATION is a symbolic link. */
static gboolean
replace_file_or_symlink(const char *source, const char *destination,
		        struct lu_error **error)
{
	struct stat st;
	char *tmp;
	gboolean ret = FALSE;

	tmp = NULL;
	if (lstat(destination, &st) == 0 && S_ISLNK(st.st_mode)) {
		tmp = realpath(destination, NULL);
		if (tmp == NULL) {
			lu_error_new(error, lu_error_generic,
				     _("Error resolving `%s': %s"), destination,
				     strerror(errno));
			goto err;
		}
		destination = tmp;
	}
	if (rename(source, destination) != 0) {
		lu_error_new(error, lu_error_write,
			     _("Error replacing `%s': %s"), destination,
			     strerror(errno));
		goto err;
	}
	ret = TRUE;
	/* Fall through */

err:
	free(tmp);
	return ret;
}

/* Finish editing E, commit edits if COMMIT.
 * Return true only if RET_INPUT and everything went OK; suggested usage is
 *  ret = editing_close(e, commit, ret, error); */
static gboolean
editing_close(struct editing *e, gboolean commit, gboolean ret_input,
	      struct lu_error **error)
{
	gboolean ret = FALSE;
	gboolean unlink_new_filename = TRUE;

	g_assert(e != NULL);

	if (commit && fsync(e->new_fd) != 0) {
		lu_error_new(error, lu_error_write, _("Error writing `%s': %s"),
			     e->new_filename, strerror(errno));
		close(e->new_fd);
		goto err;
	}
	close(e->new_fd);

	if (commit) {
		if (replace_file_or_symlink(e->new_filename, e->filename,
					    error) == FALSE)
			goto err;
		unlink_new_filename = FALSE;
	}
	ret = ret_input;

err:
	if (unlink_new_filename)
		(void)unlink(e->new_filename);
	g_free(e->new_filename);
	lu_util_fscreate_restore(e->fscreate);

	(void)lock_file_remove(e->filename);
	if (geteuid() == 0)
		(void)ulckpwdf();

	g_free(e->filename);
	g_free(e);
	return ret;
}


/* Read a line from the file, no matter how long it is, and return it as a
 * newly-allocated string, with the terminator intact. */
static char *
line_read(FILE * fp)
{
	char *buf;
	size_t len, buf_size = CHUNK_SIZE;

	buf = g_malloc(buf_size);
	len = 0;
	while (fgets(buf + len, buf_size - len, fp) != NULL) {
		len += strlen(buf + len);
		if (len > 0 && buf[len - 1] == '\n')
			break;

		buf_size += CHUNK_SIZE;
		buf = g_realloc(buf, buf_size);
	}
	if (len == 0) {
		g_free(buf);
		return NULL;
	} else {
		return buf;
	}
}

/* Parse a single field value. */
static gboolean
parse_field(const struct format_specifier *format, GValue *value,
	    const char *string)
{
	struct lu_error *err;
	gboolean ret;

	err = NULL;
	ret = lu_value_init_set_attr_from_string(value, format->attribute,
						 string, &err);
	if (ret == FALSE) {
		g_assert(err != NULL);
		g_warning(lu_strerror(err));
		lu_error_free(&err);
	}
	return ret;
}

/* Parse a string into an ent structure using the elements in the format
 * specifier array. */
static gboolean
parse_generic(const gchar *line, const struct format_specifier *formats,
	      size_t format_count, struct lu_ent *ent)
{
	size_t i;
	gchar **v = NULL;
	GValue value;

	/* Make sure the line is properly formatted, meaning that it has enough
	   fields in it for us to parse out all the fields we want, allowing
	   for the last one to be empty. */
	v = g_strsplit(line, ":", format_count);
	g_assert(format_count > 0);
	if (g_strv_length(v) < format_count - 1) {
		g_warning("entry is incorrectly formatted");
		return FALSE;
	}

	/* Now parse out the fields. */
	memset(&value, 0, sizeof(value));
	for (i = 0; i < format_count; i++) {
		const gchar *val;

		val = v[i];
		if (val == NULL)
			val = "";
		/* Clear out old values in the destination structure. */
		lu_ent_clear_current(ent, formats[i].attribute);
		if (formats[i].multiple) {
			/* Field contains multiple comma-separated values. */
			gchar **w;
			size_t j;

			/* Split up the field. */
			w = g_strsplit(val, ",", 0);
			for (j = 0; (w != NULL) && (w[j] != NULL); j++) {
				gboolean ret;

				/* Skip over empty strings. */
				if (strlen(w[j]) == 0)
					continue;
				/* Always succeeds assuming the attribute
				   values use G_TYPE_STRING, which is currently
				   true. */
				ret = parse_field(formats + i, &value, w[j]);
				g_assert (ret != FALSE);
				/* Add it to the current values list. */
				lu_ent_add_current(ent, formats[i].attribute,
						   &value);
				g_value_unset(&value);
			}
			g_strfreev(w);
		} else {
			/* Check if we need to supply the default value. */
			if (formats[i].def_if_empty && formats[i].def != NULL
			    && strlen(val) == 0) {
				gboolean ret;

				/* Convert the default to the right type. */
				ret = parse_field(formats + i, &value,
						  formats[i].def);
				g_assert (ret != FALSE);
			} else {
				if (parse_field (formats + i, &value, val)
				    == FALSE)
					continue;
			}
			/* If we recovered a value, add it to the current
			 * values list for the entity. */
			lu_ent_add_current(ent, formats[i].attribute, &value);
			g_value_unset(&value);
		}
	}
	g_strfreev(v);
	return TRUE;
}

/* Parse an entry from /etc/passwd into an ent structure, using the attribute
 * names we know. */
static gboolean
lu_files_parse_user_entry(const gchar * line, struct lu_ent *ent)
{
	ent->type = lu_user;
	lu_ent_clear_all(ent);
	return parse_generic(line, format_passwd, G_N_ELEMENTS(format_passwd),
			     ent);
}

/* Parse an entry from /etc/group into an ent structure, using the attribute
 * names we know. */
static gboolean
lu_files_parse_group_entry(const gchar * line, struct lu_ent *ent)
{
	ent->type = lu_group;
	lu_ent_clear_all(ent);
	return parse_generic(line, format_group, G_N_ELEMENTS(format_group),
			     ent);
}

/* Parse an entry from /etc/shadow into an ent structure, using the attribute
 * names we know. */
static gboolean
lu_shadow_parse_user_entry(const gchar * line, struct lu_ent *ent)
{
	ent->type = lu_user;
	lu_ent_clear_all(ent);
	return parse_generic(line, format_shadow, G_N_ELEMENTS(format_shadow),
			     ent);
}

/* Parse an entry from /etc/shadow into an ent structure, using the attribute
 * names we know. */
static gboolean
lu_shadow_parse_group_entry(const gchar * line, struct lu_ent *ent)
{
	ent->type = lu_group;
	lu_ent_clear_all(ent);
	return parse_generic(line, format_gshadow,
			     G_N_ELEMENTS(format_gshadow), ent);
}

typedef gboolean(*parse_fn) (const gchar * line, struct lu_ent * ent);

/* Look up an entry in the named file, using the string stored in "name" as
 * a key, looking for it in the field'th field, using the given parsing
 * function to load any results we find into the entity structure. */
static gboolean
generic_lookup(struct lu_module *module, const char *file_suffix,
	       const char *name, int field, parse_fn parser,
	       struct lu_ent *ent, struct lu_error **error)
{
	gboolean ret;
	int fd = -1;
	char *line, *filename;

	g_assert(module != NULL);
	g_assert(name != NULL);
	g_assert(parser != NULL);
	g_assert(field > 0);
	g_assert(ent != NULL);

	filename = module_filename(module, file_suffix);

	/* Open the file. */
	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		g_free(filename);
		return FALSE;
	}
	g_free(filename);

	/* Search for the entry in this file. */
	line = lu_util_line_get_matchingx(fd, name, field, error);
	if (line == NULL) {
		close(fd);
		return FALSE;
	}

	/* If we found data, parse it and then free the data. */
	ret = parser(line, ent);
	g_free(line);
	close(fd);

	return ret;
}

/* Look up a user by name in /etc/passwd. */
static gboolean
lu_files_user_lookup_name(struct lu_module *module,
			  const char *name,
			  struct lu_ent *ent,
			  struct lu_error **error)
{
	return generic_lookup(module, suffix_passwd, name, 1,
			      lu_files_parse_user_entry, ent, error);
}

/* Look up a user by ID in /etc/passwd. */
static gboolean
lu_files_user_lookup_id(struct lu_module *module,
			uid_t uid,
			struct lu_ent *ent,
			struct lu_error **error)
{
	char key[sizeof (uid) * CHAR_BIT + 1];

	sprintf(key, "%jd", (intmax_t)uid);
	return generic_lookup(module, suffix_passwd, key, 3,
			      lu_files_parse_user_entry, ent, error);
}

/* Look up a user by name in /etc/shadow. */
static gboolean
lu_shadow_user_lookup_name(struct lu_module *module,
			   const char *name,
			   struct lu_ent *ent,
			   struct lu_error **error)
{
	return generic_lookup(module, suffix_shadow, name, 1,
			      lu_shadow_parse_user_entry, ent, error);
}

/* Look up a user by ID in /etc/shadow.  This becomes a bit tricky because
 * the shadow file doesn't contain UIDs, so we need to scan the passwd file
 * to convert the ID to a name first. */
static gboolean
lu_shadow_user_lookup_id(struct lu_module *module,
			 uid_t uid,
			 struct lu_ent *ent,
			 struct lu_error **error)
{
	gboolean ret;

	/* First look the user up by ID. */
	ret = lu_files_user_lookup_id(module, uid, ent, error);
	if (ret) {
		char *p;

		/* Now use the user's name to search the shadow file. */
		p = lu_ent_get_first_value_strdup(ent, LU_USERNAME);
		if (p != NULL) {
			ret = generic_lookup(module, suffix_shadow, p, 1,
					     lu_shadow_parse_user_entry,
					     ent, error);
			g_free(p);
		}
	}
	return ret;
}

/* Look a group up by name in /etc/group. */
static gboolean
lu_files_group_lookup_name(struct lu_module *module,
			   const char *name,
			   struct lu_ent *ent,
			   struct lu_error **error)
{
	return generic_lookup(module, suffix_group, name, 1,
			      lu_files_parse_group_entry, ent, error);
}

/* Look a group up by ID in /etc/group. */
static gboolean
lu_files_group_lookup_id(struct lu_module *module,
			 gid_t gid,
			 struct lu_ent *ent,
			 struct lu_error **error)
{
	char key[sizeof (gid) * CHAR_BIT + 1];

	sprintf(key, "%jd", (intmax_t)gid);
	return generic_lookup(module, suffix_group, key, 3,
			      lu_files_parse_group_entry, ent, error);
}

/* Look a group up by name in /etc/gshadow. */
static gboolean
lu_shadow_group_lookup_name(struct lu_module *module, const char *name,
			    struct lu_ent *ent, struct lu_error **error)
{
	return generic_lookup(module, suffix_gshadow, name, 1,
			      lu_shadow_parse_group_entry, ent, error);
}

/* Look up a group by ID in /etc/gshadow.  This file doesn't contain any
 * GIDs, so we have to use /etc/group to convert the GID to a name first. */
static gboolean
lu_shadow_group_lookup_id(struct lu_module *module, gid_t gid,
			  struct lu_ent *ent, struct lu_error **error)
{
	gboolean ret;

	ret = lu_files_group_lookup_id(module, gid, ent, error);
	if (ret) {
		char *p;

		p = lu_ent_get_first_value_strdup(ent, LU_GROUPNAME);
		if (p != NULL) {
			ret = generic_lookup(module, suffix_gshadow, p, 1,
					     lu_shadow_parse_group_entry,
					     ent, error);
			g_free(p);
		}
	}
	return ret;
}

/* Format a single field.
   Return field string for g_free (). */
static char *
format_field(struct lu_ent *ent, const struct format_specifier *format)
{
	GValueArray *values;
	char *ret;

	values = lu_ent_get(ent, format->attribute);
	if (values != NULL) {
		size_t j;

		/* Iterate over all of the data items we can, prepending a
		   comma to all but the first. */
		ret = NULL;
		j = 0;
		do {
			GValue *val;
			char *p, *tmp;

			val = g_value_array_get_nth(values, j);
			p = lu_value_strdup(val);
			/* Add it to the end, prepending a comma if we need to
			   separate it from another value, unless this is the
			   default value for the field and we need to suppress
			   it. */
			if (format->multiple == FALSE
			    && format->suppress_if_def == TRUE
			    && format->def != NULL
			    && strcmp(format->def, p) == 0)
				tmp = g_strdup("");
			else
				tmp = g_strconcat(ret ? ret : "",
						  (j > 0) ? "," : "", p, NULL);
			g_free(p);
			g_free(ret);
			ret = tmp;
			j++;
		} while (format->multiple && j < values->n_values);
	} else {
		/* We have no values, so check for a default value,
		 * unless we're suppressing it. */
		if (format->def != NULL && format->suppress_if_def == FALSE)
			ret = g_strdup(format->def);
		else
			ret = g_strdup("");
	}
	return ret;
}

/* Format a line for the user/group, using the information in ent, using
   formats to guide the formatting.
   Return a line for g_free(), or NULL on error. */
static char *
format_generic(struct lu_ent *ent, const struct format_specifier *formats,
	       size_t format_count, struct lu_error **error)
{
	char *ret = NULL, *tmp;
	size_t i;

	g_return_val_if_fail(ent != NULL, NULL);

	for (i = 0; i < format_count; i++) {
		char *field;

		field = format_field(ent, formats + i);
		if (strchr(field, '\n') != NULL) {
			lu_error_new(error, lu_error_invalid_attribute_value,
				     _("%s value `%s': `\\n' not allowed"),
				     formats[i].attribute, field);
			g_free(field);
			goto err;
		}
		if (i != format_count - 1 && strchr(field, ':') != NULL) {
			lu_error_new(error, lu_error_invalid_attribute_value,
				     _("%s value `%s': `:' not allowed"),
				     formats[i].attribute, field);
			g_free(field);
			goto err;
		}
		if (i == 0)
			tmp = field;
		else {
			tmp = g_strconcat(ret, ":", field, NULL);
			g_free(field);
		}
		g_free(ret);
		ret = tmp;
	}
	/* Add an end-of-line terminator. */
	g_assert(format_count != 0 && ret != NULL);
	tmp = g_strconcat(ret, "\n", NULL);
	g_free(ret);
	ret = tmp;

	return ret;

err:
	g_free(ret);
	return NULL;
}

/* Does NUL-terminated CONTENTS contains an entry with the same entry name used
   in LINE? */
static gboolean
entry_name_conflicts(const char *contents, const char *line)
{
	size_t prefix_len;
	char *prefix, *fragment;
	gboolean res;

	if (strchr(line, ':') != NULL)
		prefix_len = strchr(line, ':') - line + 1;
	else if (strchr(line, '\n') != NULL)
		prefix_len = strchr(line, '\n') - line + 1;
	else
		prefix_len = strlen(line);
	if (strncmp(contents, line, prefix_len) == 0)
		return TRUE;

	prefix = g_strndup(line, prefix_len);
	fragment = g_strconcat("\n", prefix, NULL);
	g_free(prefix);

	res = strstr(contents, fragment) != NULL;
	g_free(fragment);
	return res;
}

/* Add an entity to a given flat file, using a given formatting functin to
 * construct the proper text data. */
static gboolean
generic_add(struct lu_module *module, const char *file_suffix,
	    const struct format_specifier *formats, size_t format_count,
	    struct lu_ent *ent, struct lu_error **error)
{
	struct editing *e;
	char *line, *contents;
	ssize_t r;
	struct stat st;
	off_t offset;
	gboolean ret = FALSE;

	g_assert(module != NULL);
	g_assert(formats != NULL);
	g_assert(format_count > 0);
	g_assert(ent != NULL);

	line = format_generic(ent, formats, format_count, error);
	if (line == NULL)
		goto err;

	e = editing_open(module, file_suffix, error);
	if (e == NULL)
		goto err_line;

	/* Read the file's size. */
	if (fstat(e->new_fd, &st) == -1) {
		lu_error_new(error, lu_error_stat,
			     _("couldn't stat `%s': %s"), e->new_filename,
			     strerror(errno));
		goto err_editing;
	}

	/* Read the entire file in.  There's some room for improvement here,
	 * but at least we still have the lock, so it's not going to get
	 * funky on us. */
	contents = g_malloc0(st.st_size + 1);
	if (read(e->new_fd, contents, st.st_size) != st.st_size) {
		lu_error_new(error, lu_error_read,
			     _("couldn't read from `%s': %s"),
			     e->new_filename, strerror(errno));
		goto err_contents;
	}

	/* Sanity-check to make sure that the entity isn't already listed in
	   the file. */
	if (entry_name_conflicts(contents, line)) {
		lu_error_new(error, lu_error_generic,
			     _("entry already present in file"));
		goto err_contents;
	}
	/* Hooray, we can add this entry at the end of the file. */
	offset = lseek(e->new_fd, 0, SEEK_END);
	if (offset == -1) {
		lu_error_new(error, lu_error_write,
			     _("couldn't write to `%s': %s"),
			     e->new_filename, strerror(errno));
		goto err_contents;
	}
	/* If the last byte in the file isn't a newline, add one, and silently
	 * curse people who use text editors (which shall remain unnamed) which
	 * allow saving of the file without a final line terminator. */
	if ((st.st_size > 0) && (contents[st.st_size - 1] != '\n')) {
		if (write(e->new_fd, "\n", 1) != 1) {
			lu_error_new(error, lu_error_write,
				     _("couldn't write to `%s': %s"),
				     e->new_filename, strerror(errno));
			goto err_contents;
		}
	}
	/* Attempt to write the entire line to the end. */
	r = write(e->new_fd, line, strlen(line));
	if ((size_t)r != strlen(line)) {
		/* Oh, come on! */
		lu_error_new(error, lu_error_write,
			     _("couldn't write to `%s': %s"), e->new_filename,
			     strerror(errno));
		goto err_contents;
	}
	ret = TRUE;
	/* Fall through */

err_contents:
	g_free(contents);
err_editing:
	ret = editing_close(e, ret, ret, error); /* Commit/rollback happens here. */
err_line:
	g_free(line);
err:
	return ret;
}

/* Make last-minute changes to the structures before adding them. */
static gboolean
lu_files_user_add_prep(struct lu_module *module, struct lu_ent *ent,
		       struct lu_error **error)
{
	(void)module;
	(void)ent;
	(void)error;
	return TRUE;
}

/* Add the user record to the passwd file. */
static gboolean
lu_files_user_add(struct lu_module *module, struct lu_ent *ent,
		  struct lu_error **error)
{
	return generic_add(module, suffix_passwd, format_passwd,
			   G_N_ELEMENTS(format_passwd), ent, error);
}

/* Make last-minute changes to the record before adding it to /etc/shadow. */
static gboolean
lu_shadow_user_add_prep(struct lu_module *module, struct lu_ent *ent,
		        struct lu_error **error)
{
	(void)module;
	(void)error;
	/* Make sure the regular password says "shadow!" */
	lu_ent_set_string(ent, LU_USERPASSWORD, "x");
	return TRUE;
}

/* Add the user to the shadow file. */
static gboolean
lu_shadow_user_add(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	return generic_add(module, suffix_shadow, format_shadow,
			   G_N_ELEMENTS(format_shadow), ent, error);
}

/* Make last-minute changes before adding the group to the group file. */
static gboolean
lu_files_group_add_prep(struct lu_module *module, struct lu_ent *ent,
		        struct lu_error **error)
{
	(void)module;
	(void)ent;
	(void)error;
	return TRUE;
}

/* Add the group to the group file. */
static gboolean
lu_files_group_add(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	return generic_add(module, suffix_group, format_group,
			   G_N_ELEMENTS(format_group), ent, error);
}

/* Make last-minute changes before adding the shadowed group. */
static gboolean
lu_shadow_group_add_prep(struct lu_module *module, struct lu_ent *ent,
		         struct lu_error **error)
{
	(void)module;
	(void)error;
	/* Make sure the regular password says "shadow!" */
	lu_ent_set_string(ent, LU_GROUPPASSWORD, "x");
	return TRUE;
}

/* Add a shadowed group. */
static gboolean
lu_shadow_group_add(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	return generic_add(module, suffix_gshadow, format_gshadow,
			   G_N_ELEMENTS(format_gshadow), ent, error);
}

/* Modify a particular record in the given file, field by field, using the
 * given format specifiers. */
static gboolean
generic_mod(struct lu_module *module, const char *file_suffix,
	    const struct format_specifier *formats, size_t format_count,
	    struct lu_ent *ent, struct lu_error **error)
{
	struct editing *e;
	char *new_line, *contents, *line, *rest;
	char *current_name, *fragment;
	const char *name_attribute;
	gboolean ret = FALSE;
	struct stat st;
	size_t len;

	g_assert(module != NULL);
	g_assert(formats != NULL);
	g_assert(format_count > 0);
	g_assert(ent != NULL);
	g_assert((ent->type == lu_user) || (ent->type == lu_group));

	/* Get the array of names for the entity object. */
	if (ent->type == lu_user)
		name_attribute = LU_USERNAME;
	else if (ent->type == lu_group)
		name_attribute = LU_GROUPNAME;
	else
		g_assert_not_reached();

	current_name = lu_ent_get_first_value_strdup_current(ent,
							     name_attribute);
	if (current_name == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("entity object has no %s attribute"),
			     name_attribute);
		return FALSE;
	}

	new_line = format_generic(ent, formats, format_count, error);
	if (new_line == NULL)
		goto err_current_name;

	e = editing_open(module, file_suffix, error);
	if (e == NULL)
		goto err_new_line;

	if (fstat(e->new_fd, &st) == -1) {
		lu_error_new(error, lu_error_stat, _("couldn't stat `%s': %s"),
			     e->new_filename, strerror(errno));
		goto err_editing;
	}

	contents = g_malloc(st.st_size + 1 + strlen(new_line));
	if (read(e->new_fd, contents, st.st_size) != st.st_size) {
		lu_error_new(error, lu_error_read,
			     _("couldn't read from `%s': %s"), e->new_filename,
			     strerror(errno));
		goto err_contents;
	}
	contents[st.st_size] = '\0';

	fragment = g_strconcat("\n", current_name, ":", (const gchar *)NULL);
	len = strlen(current_name);
	if (strncmp(contents, current_name, len) == 0 && contents[len] == ':')
		line = contents;
	else {
		line = strstr(contents, fragment);
		if (line != NULL)
			line++;
	}
	g_free(fragment);

	if ((strncmp(new_line, current_name, len) != 0 || new_line[len] != ':')
	    && entry_name_conflicts(contents, new_line)) {
		lu_error_new(error, lu_error_generic,
			     _("entry with conflicting name already present "
			       "in file"));
		goto err_contents;
	}

	if (line == NULL) {
		lu_error_new(error, lu_error_search, NULL);
		goto err_contents;
	}

	rest = strchr(line, '\n');
	if (rest != NULL)
		rest++;
	else
		rest = strchr(line, '\0');
	memmove(line + strlen(new_line), rest,
		contents + st.st_size + 1 - rest);
	memcpy(line, new_line, strlen(new_line));
	if (lseek(e->new_fd, line - contents, SEEK_SET) == -1) {
		lu_error_new(error, lu_error_write, NULL);
		goto err_contents;
	}
	len = strlen(line);
	if ((size_t)write(e->new_fd, line, len) != len) {
		lu_error_new(error, lu_error_write, NULL);
		goto err_contents;
	}
	if (ftruncate(e->new_fd, (line - contents) + len) != 0) {
		lu_error_new(error, lu_error_write, NULL);
		goto err_contents;
	}
	ret = TRUE;
	/* Fall through */

err_contents:
	g_free(contents);
err_editing:
	ret = editing_close(e, ret, ret, error); /* Commit/rollback happens here. */
err_new_line:
	g_free(new_line);
err_current_name:
	g_free(current_name);
	return ret;
}

/* Modify an entry in the passwd file. */
static gboolean
lu_files_user_mod(struct lu_module *module, struct lu_ent *ent,
		  struct lu_error **error)
{
	return generic_mod(module, suffix_passwd, format_passwd,
			   G_N_ELEMENTS(format_passwd), ent, error);
}

/* Modify an entry in the group file. */
static gboolean
lu_files_group_mod(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	return generic_mod(module, suffix_group, format_group,
			   G_N_ELEMENTS(format_group), ent, error);
}

/* Modify an entry in the shadow file. */
static gboolean
lu_shadow_user_mod(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	return generic_mod(module, suffix_shadow, format_shadow,
			   G_N_ELEMENTS(format_shadow), ent, error);
}

/* Modify an entry in the gshadow file. */
static gboolean
lu_shadow_group_mod(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	return generic_mod(module, suffix_gshadow, format_gshadow,
			   G_N_ELEMENTS(format_gshadow), ent, error);
}

/* Delete an entity from the given file. */
static gboolean
generic_del(struct lu_module *module, const char *file_suffix,
	    struct lu_ent *ent, struct lu_error **error)
{
	struct editing *e;
	char *name;
	char *contents;
	char *fragment2;
	struct stat st;
	size_t len;
        gboolean commit = FALSE, ret = FALSE;
	gboolean found;

	/* Get the entity's current name. */
	if (ent->type == lu_user)
		name = lu_ent_get_first_value_strdup_current(ent, LU_USERNAME);
	else if (ent->type == lu_group)
		name = lu_ent_get_first_value_strdup_current(ent, LU_GROUPNAME);
	else
		g_assert_not_reached();
	g_assert(name != NULL);

	g_assert(module != NULL);
	g_assert(ent != NULL);

	e = editing_open(module, file_suffix, error);
	if (e == NULL)
		goto err_name;

	/* Determine the file's size. */
	if (fstat(e->new_fd, &st) == -1) {
		lu_error_new(error, lu_error_stat,
			     _("couldn't stat `%s': %s"), e->new_filename,
			     strerror(errno));
		goto err_editing;
	}

	/* Allocate space to hold the file and read it all in. */
	contents = g_malloc(st.st_size + 1);
	if (read(e->new_fd, contents, st.st_size) != st.st_size) {
		lu_error_new(error, lu_error_read,
			     _("couldn't read from `%s': %s"), e->new_filename,
			     strerror(errno));
		goto err_contents;
	}
	contents[st.st_size] = '\0';

	/* Generate a pattern for a beginning of a non-first line */
	fragment2 = g_strconcat("\n", name, ":", (const gchar *)NULL);

	/* Remove all occurrences of this entry from the file. */
	len = strlen(name);
	do {
		char *tmp;

		found = FALSE;
		/* If the data is on the first line of the file, we remove the
		 * first line. */
		if (strncmp(contents, name, len) == 0
			&& contents[len] == ':') {
			char *p;

			p = strchr(contents, '\n');
			if (p != NULL)
				memmove(contents, p + 1, strlen(p + 1) + 1);
			else
				strcpy(contents, "");
			found = TRUE;
		} else
		/* If the data occurs elsewhere, cover it up. */
		if ((tmp = strstr(contents, fragment2)) != NULL) {
			char *p;

			p = strchr(tmp + 1, '\n');
			if (p != NULL)
				memmove(tmp + 1, p + 1, strlen (p + 1) + 1);
			else
				strcpy(tmp + 1, "");
			found = TRUE;
		}
	} while(found);

	g_free(fragment2);

	/* If the resulting memory chunk is the same size as the file, then
	 * nothing's changed. */
	len = strlen(contents);
	if ((off_t)len == st.st_size) {
		ret = TRUE;
		goto err_contents;
	}

	/* Otherwise we need to write the new data to the file.  Jump back to
	 * the beginning of the file. */
	if (lseek(e->new_fd, 0, SEEK_SET) == -1) {
		lu_error_new(error, lu_error_write,
			     _("couldn't write to `%s': %s"), e->new_filename,
			     strerror(errno));
		goto err_contents;
	}

	/* Write the new contents out. */
	if ((size_t)write(e->new_fd, contents, len) != len) {
		lu_error_new(error, lu_error_write,
			     _("couldn't write to `%s': %s"), e->new_filename,
			     strerror(errno));
		goto err_contents;
	}

	/* Truncate the file to the new (certainly shorter) length. */
	if (ftruncate(e->new_fd, len) == -1) {
		lu_error_new(error, lu_error_generic,
			     _("couldn't write to `%s': %s"), e->new_filename,
			     strerror(errno));
		goto err_contents;
	}
	commit = TRUE;
	ret = TRUE;
	/* Fall through */

 err_contents:
	g_free(contents);
err_editing:
	/* Commit/rollback happens here. */
	ret = editing_close(e, commit, ret, error);
err_name:
	g_free(name);
	return ret;
}

/* Remove a user from the passwd file. */
static gboolean
lu_files_user_del(struct lu_module *module, struct lu_ent *ent,
		  struct lu_error **error)
{
	return generic_del(module, suffix_passwd, ent, error);
}

/* Remove a group from the group file. */
static gboolean
lu_files_group_del(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	return generic_del(module, suffix_group, ent, error);
}

/* Remove a user from the shadow file. */
static gboolean
lu_shadow_user_del(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	return generic_del(module, suffix_shadow, ent, error);
}

/* Remove a group from the gshadow file. */
static gboolean
lu_shadow_group_del(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	return generic_del(module, suffix_gshadow, ent, error);
}

/* Return a modified version of the cryptedPassword string, depending on
   op, or NULL on error. */
static char *
lock_process(char *cryptedPassword, enum lock_op op, struct lu_ent *ent,
	     struct lu_error **error)
{
	char *ret = NULL;

	switch (op) {
	case LO_LOCK:
		ret = ent->cache->cache(ent->cache, cryptedPassword);
		if (ret[0] != '!') {
			cryptedPassword = g_strconcat("!!", ret, NULL);
			ret = ent->cache->cache(ent->cache, cryptedPassword);
			g_free(cryptedPassword);
		}
		break;
	case LO_UNLOCK:
		for (ret = cryptedPassword; ret[0] == '!'; ret++)
			;
		ret = ent->cache->cache(ent->cache, ret);
		break;
	case LO_UNLOCK_NONEMPTY:
		for (ret = cryptedPassword; ret[0] == '!'; ret++)
			;
		if (*ret == '\0') {
			lu_error_new(error, lu_error_unlock_empty, NULL);
			return NULL;
		}
		ret = ent->cache->cache(ent->cache, ret);
		break;

	default:
		g_assert_not_reached ();
	}
	return ret;
}

/* Lock or unlock an account in the given file, with its encrypted password
 * stored in the given field number. */
static gboolean
generic_lock(struct lu_module *module, const char *file_suffix, int field,
	     struct lu_ent *ent, enum lock_op op, struct lu_error **error)
{
	struct editing *e;
	char *value, *new_value, *name;
	gboolean commit = FALSE, ret = FALSE;

	/* Get the name which keys the entries of interest in the file. */
	g_assert((ent->type == lu_user) || (ent->type == lu_group));
	if (ent->type == lu_user)
		name = lu_ent_get_first_value_strdup_current(ent, LU_USERNAME);
	if (ent->type == lu_group)
		name = lu_ent_get_first_value_strdup_current(ent, LU_GROUPNAME);
	g_assert(name != NULL);

	g_assert(module != NULL);
	g_assert(ent != NULL);

	e = editing_open(module, file_suffix, error);
	if (e == NULL)
		goto err_name;

	/* Read the old value from the file. */
	value = lu_util_field_read(e->new_fd, name, field, error);
	if (value == NULL)
		goto err_editing;

	/* Check that we actually care about this.  If there's a non-empty,
	 * not locked string in there, but it's too short to be a hash, then
	 * we don't care, so we just nod our heads and smile. */
	if (LU_CRYPT_INVALID(value)) {
		g_free(value);
		ret = TRUE;
		goto err_editing;
	}

	/* Generate a new value for the file. */
	new_value = lock_process(value, op, ent, error);
	g_free(value);
	if (new_value == NULL)
		goto err_editing;

	/* Make the change. */
	if (lu_util_field_write(e->new_fd, name, field, new_value, error)
	    == FALSE)
		goto err_editing;
	commit = TRUE;
	ret = TRUE;
	/* Fall through */

err_editing:
	/* Commit/rollback happens here. */
	ret = editing_close(e, commit, ret, error);
err_name:
	g_free(name);
	return ret;
}

/* Check if an account [password] is locked. */
static gboolean
generic_is_locked(struct lu_module *module, const char *file_suffix,
		  int field, struct lu_ent *ent, struct lu_error **error)
{
	char *filename;
	char *value, *name;
	int fd;
	gboolean ret = FALSE;

	/* Get the name of this account. */
	g_assert((ent->type == lu_user) || (ent->type == lu_group));
	if (ent->type == lu_user)
		name = lu_ent_get_first_value_strdup_current(ent, LU_USERNAME);
	if (ent->type == lu_group)
		name = lu_ent_get_first_value_strdup_current(ent, LU_GROUPNAME);
	g_assert(name != NULL);

	g_assert(module != NULL);
	g_assert(ent != NULL);

	filename = module_filename(module, file_suffix);

	/* Open the file. */
	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		goto err_filename;
	}

	/* Read the value. */
	value = lu_util_field_read(fd, name, field, error);
	if (value == NULL)
		goto err_fd;

	/* It all comes down to this. */
	ret = value[0] == '!';
	g_free(value);
	/* Fall through */

err_fd:
	close(fd);
err_filename:
	g_free(filename);
	g_free(name);
	return ret;
}

/* Lock a user from the passwd file. */
static gboolean
lu_files_user_lock(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	return generic_lock(module, suffix_passwd, 2, ent, LO_LOCK, error);
}

static gboolean
lu_files_user_unlock(struct lu_module *module, struct lu_ent *ent,
		     struct lu_error **error)
{
	return generic_lock(module, suffix_passwd, 2, ent, LO_UNLOCK, error);
}

static gboolean
lu_files_user_unlock_nonempty(struct lu_module *module, struct lu_ent *ent,
			      struct lu_error **error)
{
	return generic_lock(module, suffix_passwd, 2, ent, LO_UNLOCK_NONEMPTY,
			    error);
}

/* Lock a group from the group file. */
static gboolean
lu_files_group_lock(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	return generic_lock(module, suffix_group, 2, ent, LO_LOCK, error);
}

static gboolean
lu_files_group_unlock(struct lu_module *module, struct lu_ent *ent,
		      struct lu_error **error)
{
	return generic_lock(module, suffix_group, 2, ent, LO_UNLOCK, error);
}

static gboolean
lu_files_group_unlock_nonempty(struct lu_module *module, struct lu_ent *ent,
			       struct lu_error **error)
{
	return generic_lock(module, suffix_group, 2, ent, LO_UNLOCK_NONEMPTY,
			    error);
}

/* Lock a user in the shadow file. */
static gboolean
lu_shadow_user_lock(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	return generic_lock(module, suffix_shadow, 2, ent, LO_LOCK, error);
}

static gboolean
lu_shadow_user_unlock(struct lu_module *module, struct lu_ent *ent,
		      struct lu_error **error)
{
	return generic_lock(module, suffix_shadow, 2, ent, LO_UNLOCK, error);
}

static gboolean
lu_shadow_user_unlock_nonempty(struct lu_module *module, struct lu_ent *ent,
			       struct lu_error **error)
{
	return generic_lock(module, suffix_shadow, 2, ent, LO_UNLOCK_NONEMPTY,
			    error);
}

/* Lock a group in the gshadow file. */
static gboolean
lu_shadow_group_lock(struct lu_module *module, struct lu_ent *ent,
		     struct lu_error **error)
{
	return generic_lock(module, suffix_gshadow, 2, ent, LO_LOCK, error);
}

static gboolean
lu_shadow_group_unlock(struct lu_module *module, struct lu_ent *ent,
		       struct lu_error **error)
{
	return generic_lock(module, suffix_gshadow, 2, ent, LO_UNLOCK, error);
}

static gboolean
lu_shadow_group_unlock_nonempty(struct lu_module *module, struct lu_ent *ent,
				struct lu_error **error)
{
	return generic_lock(module, suffix_gshadow, 2, ent, LO_UNLOCK_NONEMPTY,
			    error);
}

/* Check if the account is locked. */
static gboolean
lu_files_user_is_locked(struct lu_module *module, struct lu_ent *ent,
		        struct lu_error **error)
{
	return generic_is_locked(module, suffix_passwd, 2, ent, error);
}

static gboolean
lu_files_group_is_locked(struct lu_module *module, struct lu_ent *ent,
			 struct lu_error **error)
{
	return generic_is_locked(module, suffix_group, 2, ent, error);
}

static gboolean
lu_shadow_user_is_locked(struct lu_module *module, struct lu_ent *ent,
			 struct lu_error **error)
{
	return generic_is_locked(module, suffix_shadow, 2, ent, error);
}

static gboolean
lu_shadow_group_is_locked(struct lu_module *module, struct lu_ent *ent,
			 struct lu_error **error)
{
	return generic_is_locked(module, suffix_gshadow, 2, ent, error);
}

/* Was ent found by the shadow module? */
static gboolean
ent_has_shadow (struct lu_ent *ent)
{
	size_t i;

	for (i = 0; i < ent->modules->n_values; i++) {
		GValue *value;

		value = g_value_array_get_nth(ent->modules, i);
		g_assert(G_VALUE_HOLDS_STRING(value));
		if (strcmp(g_value_get_string(value), LU_MODULE_NAME_SHADOW)
		    == 0)
			return TRUE;
	}
	return FALSE;
}

/* Change a password, in a given file, in a given field, for a given account,
 * to a given value.  Got that? */
static gboolean
generic_setpass(struct lu_module *module, const char *file_suffix, int field,
		struct lu_ent *ent, const char *password, gboolean is_shadow,
		struct lu_error **error)
{
	struct editing *e;
	char *value, *name;
	gboolean ret = FALSE;

	/* Get the name of this account. */
	g_assert((ent->type == lu_user) || (ent->type == lu_group));
	if (ent->type == lu_user)
		name = lu_ent_get_first_value_strdup_current(ent, LU_USERNAME);
	else if (ent->type == lu_group)
		name = lu_ent_get_first_value_strdup_current(ent, LU_GROUPNAME);
	g_assert(name != NULL);

	g_assert(module != NULL);
	g_assert(ent != NULL);

	e = editing_open(module, file_suffix, error);
	if (e == NULL)
		goto err_name;

	/* Read the current contents of the field. */
	value = lu_util_field_read(e->new_fd, name, field, error);
	if (value == NULL)
		goto err_editing;

	/* pam_unix uses shadow passwords only if pw_passwd is "x"
	   (or ##${username}).  Make sure to preserve the shadow marker
	   unmodified (most importantly, don't replace it by an encrypted
	   password) -- but only if a shadow entry exists. */
	if (!is_shadow && ent_has_shadow(ent)
	    && lu_ent_get_current(ent, LU_SHADOWPASSWORD) != NULL
	    && (strcmp(value, "x") == 0
		|| (strncmp(value, "##", 2) == 0
		    && strcmp(value + 2, name) == 0))) {
		ret = TRUE;
		goto err_value;
	}
	/* Otherwise, if there is a shadow password and the shadow marker is
	   invalid, set it to the standard value. */
	if (!is_shadow && ent_has_shadow(ent)
	    && lu_ent_get_current(ent, LU_SHADOWPASSWORD) != NULL
	    && LU_CRYPT_INVALID(value))
		password = "x";
	/* The crypt prefix indicates that the password is already hashed.  If
	 * we don't see it, hash the password. */
	else if (g_ascii_strncasecmp(password, LU_CRYPTED, strlen(LU_CRYPTED))
		 == 0) {
		password = password + strlen(LU_CRYPTED);
		if (strpbrk(password, ":\n") != NULL) {
			lu_error_new(error, lu_error_invalid_attribute_value,
				     _("`:' and `\\n' not allowed in encrypted "
				       "password"));
			goto err_value;
		}
	} else {
		char *salt;

		salt = lu_util_default_salt_specifier(module->lu_context);
		password = lu_make_crypted(password, salt);
		g_free(salt);
		if (password == NULL) {
			lu_error_new(error, lu_error_generic,
				     _("error encrypting password"));
			goto err_value;
		}
	}

	/* Now write our changes to the file. */
	ret = lu_util_field_write(e->new_fd, name, field, password, error);
	/* Fall through */

err_value:
	g_free(value);
err_editing:
	ret = editing_close(e, ret, ret, error); /* Commit/rollback happens here. */
err_name:
	g_free(name);
	return ret;
}

/* Set a user's password in the passwd file. */
static gboolean
lu_files_user_setpass(struct lu_module *module, struct lu_ent *ent,
		      const char *password, struct lu_error **error)
{
	return generic_setpass(module, suffix_passwd, 2, ent, password, FALSE,
			       error);
}

static gboolean
lu_files_group_setpass(struct lu_module *module, struct lu_ent *ent,
		       const char *password, struct lu_error **error)
{
	return generic_setpass(module, suffix_group, 2, ent, password, FALSE,
			       error);
}

static gboolean
lu_files_user_removepass(struct lu_module *module, struct lu_ent *ent,
		         struct lu_error **error)
{
	return generic_setpass(module, suffix_passwd, 2, ent, LU_CRYPTED, FALSE,
			       error);
}

static gboolean
lu_files_group_removepass(struct lu_module *module, struct lu_ent *ent,
		          struct lu_error **error)
{
	return generic_setpass(module, suffix_group, 2, ent, LU_CRYPTED, FALSE,
			       error);
}

static gboolean
lu_shadow_user_setpass(struct lu_module *module, struct lu_ent *ent,
		       const char *password, struct lu_error **error)
{
	return generic_setpass(module, suffix_shadow, 2, ent, password, TRUE,
			       error);
}

static gboolean
lu_shadow_group_setpass(struct lu_module *module, struct lu_ent *ent,
			const char *password, struct lu_error **error)
{
	return generic_setpass(module, suffix_gshadow, 2, ent, password, TRUE,
			       error);
}

static gboolean
lu_shadow_user_removepass(struct lu_module *module, struct lu_ent *ent,
		          struct lu_error **error)
{
	return generic_setpass(module, suffix_shadow, 2, ent, LU_CRYPTED, TRUE,
			       error);
}

static gboolean
lu_shadow_group_removepass(struct lu_module *module, struct lu_ent *ent,
			   struct lu_error **error)
{
	return generic_setpass(module, suffix_gshadow, 2, ent, LU_CRYPTED, TRUE,
			       error);
}

/* Get a list of all of the entries in a given file which patch a
 * particular pattern. */
static GValueArray *
lu_files_enumerate(struct lu_module *module, const char *file_suffix,
		   const char *pattern, struct lu_error **error)
{
	int fd;
	GValueArray *ret;
	GValue value;
	char *buf;
	char *filename;
	FILE *fp;

	g_assert(module != NULL);
	pattern = pattern ?: "*";

	filename = module_filename(module, file_suffix);

	/* Open the file. */
	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		g_free(filename);
		return NULL;
	}

	/* Wrap the file for stdio operations. */
	fp = fdopen(fd, "r");
	if (fp == NULL) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		close(fd);
		g_free(filename);
		return NULL;
	}

	/* Create a new array to hold values. */
	ret = g_value_array_new(0);
	memset(&value, 0, sizeof(value));
	g_value_init(&value, G_TYPE_STRING);
	/* Read each line, */
	while ((buf = line_read(fp)) != NULL) {
		char *p;

		if (strlen(buf) == 1) {
			g_free(buf);
			continue;
		}
		/* require that each non-empty line has meaningful data in it */
		p = strchr(buf, ':');
		if (p != NULL) {
			/* snip off the parts we don't care about, */
			*p = '\0';
			if (buf[0] != '+' && buf[0] != '-' &&
			    fnmatch(pattern, buf, 0) == 0) {
				/* add add it to the list we're returning. */
				g_value_set_string(&value, buf);
				g_value_array_append(ret, &value);
				g_value_reset(&value);
			}
		}
		g_free(buf);
	}

	/* Clean up. */
	g_value_unset(&value);
	fclose(fp);
	g_free(filename);

	return ret;
}

/* Get a list of all users or groups. */
static GValueArray *
lu_files_users_enumerate(struct lu_module *module, const char *pattern,
			 struct lu_error **error)
{
	return lu_files_enumerate(module, suffix_passwd, pattern, error);
}

static GValueArray *
lu_files_groups_enumerate(struct lu_module *module, const char *pattern,
			  struct lu_error **error)
{
	return lu_files_enumerate(module, suffix_group, pattern, error);
}

/* Get a list of all of the users who are in a given group. */
static GValueArray *
lu_files_users_enumerate_by_group(struct lu_module *module,
				  const char *group, gid_t gid,
				  struct lu_error **error)
{
	int fd;
	GValueArray *ret;
	GValue value;
	char *buf, grp[CHUNK_SIZE];
	char *pwdfilename, *grpfilename, *p, *q;
	FILE *fp;

	g_assert(module != NULL);
	g_assert(group != NULL);

	/* Generate the names of the two files we'll be looking at. */
	pwdfilename = module_filename(module, suffix_passwd);
	grpfilename = module_filename(module, suffix_group);

	/* Open the passwd file. */
	fd = open(pwdfilename, O_RDONLY);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), pwdfilename,
			     strerror(errno));
		g_free(pwdfilename);
		g_free(grpfilename);
		return NULL;
	}

	/* Wrap the descriptor in a stdio FILE. */
	fp = fdopen(fd, "r");
	if (fp == NULL) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), pwdfilename,
			     strerror(errno));
		close(fd);
		g_free(pwdfilename);
		g_free(grpfilename);
		return NULL;
	}

	/* Create an array to store values we're going to return. */
	ret = g_value_array_new(0);
	memset(&value, 0, sizeof(value));
	g_value_init(&value, G_TYPE_STRING);
	snprintf(grp, sizeof(grp), "%jd", (intmax_t)gid);

	/* Iterate over each line. */
	while ((buf = line_read(fp)) != NULL) {
		if (strlen(buf) == 1 || buf[0] == '-' || buf[0] == '+') {
			g_free(buf);
			continue;
		}
		/* Find the end of the first field. */
		p = strchr(buf, ':');
		q = NULL;
		/* If the field has an end, find the end of the second field. */
		if (p != NULL) {
			*p = '\0';
			p++;
			p = strchr(p, ':');
		}
		/* If the second field has an end, find the end of the third. */
		if (p != NULL) {
			*p = '\0';
			p++;
			p = strchr(p, ':');
		}
		/* If the third has an end, find the fourth. */
		if (p != NULL) {
			*p = '\0';
			p++;
			q = p;
			p = strchr(p, ':');
		}
		/* If we haven't run out of fields by now, we can match. */
		if (q != NULL) {
			/* Terminate the fourth field. */
			if (p != NULL) {
				*p = '\0';
			}
			/* If it matches the gid, add this user's name to the
			 * list. */
			if (strcmp(q, grp) == 0) {
				g_value_set_string(&value, buf);
				g_value_array_append(ret, &value);
				g_value_reset(&value);
			}
		}
		g_free(buf);
	}
	/* Close the file. */
	g_value_unset(&value);
	fclose(fp);

	/* Open the group file. */
	fd = open(grpfilename, O_RDONLY);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), grpfilename,
			     strerror(errno));
		g_free(pwdfilename);
		g_free(grpfilename);
		g_value_array_free(ret);
		return NULL;
	}

	/* Wrap the group file in an stdio file. */
	fp = fdopen(fd, "r");
	if (fp == NULL) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), grpfilename,
			     strerror(errno));
		close(fd);
		g_free(pwdfilename);
		g_free(grpfilename);
		g_value_array_free(ret);
		return NULL;
	}

	/* Iterate over all of these lines as well. */
	while ((buf = line_read(fp)) != NULL) {
		if (strlen(buf) == 1 || buf[0] == '+' || buf[0] == '-') {
			g_free(buf);
			continue;
		}
		/* Terminate at the end of the first field, and find the end of
		 * the second field. */
		p = strchr(buf, ':');
		if (p != NULL) {
			*p = '\0';
			p++;
			p = strchr(p, ':');
		}
		/* If the first field matches, continue. */
		if (strcmp(buf, group) == 0) {
			/* Find the end of the third field. */
			if (p != NULL) {
				*p = '\0';
				p++;
				p = strchr(p, ':');
			}
			/* Find the beginning of the fourth field. */
			if (p != NULL) {
				*p = '\0';
				p++;
				/* Iterate through all of the pieces of
				 * the field. */
				while ((q = strsep(&p, ",\n")) != NULL) {
					/* Add this name. */
					if (strlen(q) > 0) {
						g_value_init(&value,
							     G_TYPE_STRING);
						g_value_set_string(&value, q);
						g_value_array_append(ret,
								     &value);
						g_value_unset(&value);
					}
				}
			}
			g_free(buf);
			break;
		}
		g_free(buf);
	}

	/* Clean up. */
	fclose(fp);

	g_free(pwdfilename);
	g_free(grpfilename);

	return ret;
}

/* Get a list of groups to which the user belongs. */
static GValueArray *
lu_files_groups_enumerate_by_user(struct lu_module *module,
				  const char *user,
				  uid_t uid,
				  struct lu_error **error)
{
	int fd;
	GValueArray *ret;
	GValue value;
	char *buf;
	char *key, *pwdfilename, *grpfilename, *p, *q;
	FILE *fp;

	(void)uid;
	g_assert(module != NULL);
	g_assert(user != NULL);

	/* Generate the names of files we'll be looking at. */
	pwdfilename = module_filename(module, suffix_passwd);
	grpfilename = module_filename(module, suffix_group);

	/* Open the first file. */
	fd = open(pwdfilename, O_RDONLY);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), pwdfilename,
			     strerror(errno));
		goto err_pwdfilename;
	}

	/* Open it so that we can use stdio. */
	fp = fdopen(fd, "r");
	if (fp == NULL) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), pwdfilename,
			     strerror(errno));
		close(fd);
		goto err_pwdfilename;
	}

	/* Initialize the list of values we'll return. */
	ret = g_value_array_new(0);
	memset(&value, 0, sizeof(value));
	g_value_init(&value, G_TYPE_STRING);

	/* Iterate through all of the lines in the file. */
	key = NULL;
	while ((buf = line_read(fp)) != NULL) {
		if (strlen(buf) == 1 || buf[0] == '+' || buf[0] == '-') {
			g_free(buf);
			continue;
		}
		/* Find the end of the first field. */
		p = strchr(buf, ':');
		/* Find the end of the second field. */
		if (p != NULL) {
			*p = '\0';
			p++;
			p = strchr(p, ':');
		}
		/* Find the end of the third field. */
		if (p != NULL) {
			*p = '\0';
			p++;
			p = strchr(p, ':');
		}
		/* Find the the fourth field. */
		if (p != NULL) {
			*p = '\0';
			p++;
			q = strchr(p, ':');
			/* If it matches, save the gid. */
			if (strcmp(buf, user) == 0) {
				if (q) {
					*q = '\0';
				}
				key = g_strdup(p);
				g_free(buf);
				break;
			}
		}
		g_free(buf);
	}
	fclose(fp);

	/* Open the groups file. */
	fd = open(grpfilename, O_RDONLY);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), grpfilename,
			     strerror(errno));
		goto err_key;
	}

	/* Open it so that we can use stdio. */
	fp = fdopen(fd, "r");
	if (fp == NULL) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), grpfilename,
			     strerror(errno));
		close(fd);
		goto err_key;
	}

	/* Iterate through all of the lines in the file. */
	while ((buf = line_read(fp)) != NULL) {
		if (strlen(buf) == 1 || buf[0] == '+' || buf[0] == '-') {
			g_free(buf);
			continue;
		}
		/* Find the end of the first field. */
		p = strchr(buf, ':');
		/* Find the end of the second field. */
		if (p != NULL) {
			*p = '\0';
			p++;
			p = strchr(p, ':');
		}
		/* Find the end of the third field. */
		if (p != NULL) {
			*p = '\0';
			p++;
			q = strchr(p, ':');
			if (q && key) {
				/* Terminate the third field. */
				*q = '\0';
				if (strcmp(p, key) == 0) {
					/* Add the name of the group because its
					 * gid is the user's primary. */
					g_value_set_string(&value, buf);
					g_value_array_append(ret, &value);
					g_value_reset(&value);
				}
			}
			p = q;
		}
		/* Find the beginning of the third field. */
		if (p != NULL) {
			p++;
			/* Break out each piece of the fourth field. */
			while ((q = strsep(&p, ",\n")) != NULL) {
				if (strlen(q) > 0) {
					if (strcmp(q, user) == 0) {
						g_value_set_string(&value, buf);
						g_value_array_append(ret,
								     &value);
						g_value_reset(&value);
					}
				}
			}
		}
		g_free(buf);
	}
	g_free(key);
	g_value_unset(&value);

	fclose(fp);
	g_free(pwdfilename);
	g_free(grpfilename);

	return ret;

 err_key:
	g_free(key);
	g_value_array_free(ret);
 err_pwdfilename:
	g_free(pwdfilename);
	g_free(grpfilename);
	return NULL;
}

/* Enumerate all of the accounts listed in the given file, using the
 * given parser to parse matching accounts into an array of entity pointers. */
static GPtrArray *
lu_files_enumerate_full(struct lu_module *module, const char *file_suffix,
			parse_fn parser, const char *pattern,
			struct lu_error **error)
{
	int fd;
	GPtrArray *ret = NULL;
	char *buf;
	char *key, *filename;
	FILE *fp;

	g_assert(module != NULL);
	pattern = pattern ?: "*";

	filename = module_filename(module, file_suffix);

	/* Open the file. */
	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		goto err_filename;
	}

	/* Wrap the file up in stdio. */
	fp = fdopen(fd, "r");
	if (fp == NULL) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		close(fd);
		goto err_filename;
	}

	/* Allocate an array to hold results. */
	ret = g_ptr_array_new();
	while ((buf = line_read(fp)) != NULL) {
		struct lu_ent *ent;

		if (strlen(buf) == 1 || buf[0] == '+' || buf[0] == '-') {
			g_free(buf);
			continue;
		}
		ent = lu_ent_new();
		/* Snip the line off at the right place. */
		key = strchr(buf, '\n');
		if (key != NULL) {
			*key = '\0';
		}
		if (strchr(buf, ':')) {
			key = g_strndup(buf, strchr(buf, ':') - buf);
		} else {
			key = g_strdup(buf);
		}
		/* If the account name matches the pattern, parse it and add
		 * it to the list. */
		if (fnmatch(pattern, key, 0) == 0 && parser(buf, ent) != FALSE)
			g_ptr_array_add(ret, ent);
		else
			lu_ent_free(ent);
		g_free(buf);
		g_free(key);
	}

	fclose(fp);

 err_filename:
	g_free(filename);
	return ret;
}

static GPtrArray *
lu_files_users_enumerate_full(struct lu_module *module,
			      const char *user,
			      struct lu_error **error)
{
	return lu_files_enumerate_full(module, suffix_passwd,
				       lu_files_parse_user_entry, user, error);
}

static GPtrArray *
lu_files_groups_enumerate_full(struct lu_module *module,
			       const char *group,
			       struct lu_error **error)
{
	return lu_files_enumerate_full(module, suffix_group,
				       lu_files_parse_group_entry, group,
				       error);
}

static GValueArray *
lu_shadow_users_enumerate(struct lu_module *module,
			  const char *pattern,
			  struct lu_error **error)
{
	(void)module;
	(void)pattern;
	(void)error;
	return NULL;
}

static GValueArray *
lu_shadow_groups_enumerate(struct lu_module *module,
			   const char *pattern,
			   struct lu_error **error)
{
	(void)module;
	(void)pattern;
	(void)error;
	return NULL;
}

static GValueArray *
lu_shadow_users_enumerate_by_group(struct lu_module *module,
				   const char *group,
				   gid_t gid,
				   struct lu_error **error)
{
	(void)module;
	(void)group;
	(void)gid;
	(void)error;
	return NULL;
}

static GValueArray *
lu_shadow_groups_enumerate_by_user(struct lu_module *module,
				   const char *user,
				   uid_t uid,
				   struct lu_error **error)
{
	(void)module;
	(void)user;
	(void)uid;
	(void)error;
	return NULL;
}

static GPtrArray *
lu_shadow_users_enumerate_full(struct lu_module *module,
			       const char *pattern,
			       struct lu_error **error)
{
	return lu_files_enumerate_full(module, suffix_shadow,
				       lu_shadow_parse_user_entry, pattern,
				       error);
}

static GPtrArray *
lu_shadow_groups_enumerate_full(struct lu_module *module,
				const char *pattern,
				struct lu_error **error)
{
	return lu_files_enumerate_full(module, suffix_gshadow,
				       lu_shadow_parse_group_entry, pattern,
				       error);
}

static gboolean
lu_files_shadow_valid_module_combination(struct lu_module *module,
					 GValueArray *names,
					 struct lu_error **error)
{
	size_t i;

	g_assert(module != NULL);
	g_assert(names != NULL);
	LU_ERROR_CHECK(error);
	for (i = 0; i < names->n_values; i++) {
		const char *name;

		name = g_value_get_string(g_value_array_get_nth(names, i));
		if (strcmp(name, LU_MODULE_NAME_LDAP) == 0) {
			/* LDAP uses an incompatible LU_*PASSWORD format: the
			   LU_CRYPTED prefix, or a similar indicator of an
			   LDAP-defined hashing method, is included. */
			lu_error_new(error, lu_error_invalid_module_combination,
				     _("the `%s' and `%s' modules can not be "
				       "combined"), module->name, name);
			return FALSE;
		}
	}
	return TRUE;
}


/* Check if we use/need elevated privileges to manipulate our files. */
static gboolean
lu_files_uses_elevated_privileges(struct lu_module *module)
{
	char *path;
	gboolean ret = FALSE;

	/* If we can't access the passwd file as a normal user, then the
	 * answer is "yes". */
	path = module_filename(module, suffix_passwd);
	if (access(path, R_OK | W_OK) != 0) {
		ret = TRUE;
	}
	g_free(path);
	/* If we can't access the group file as a normal user, then the
	 * answer is "yes". */
	path = module_filename(module, suffix_group);
	if (access(path, R_OK | W_OK) != 0) {
		ret = TRUE;
	}
	g_free(path);
	return ret;
}

/* Check if we use/need elevated privileges to manipulate our files. */
static gboolean
lu_shadow_uses_elevated_privileges(struct lu_module *module)
{
	char *path;
	gboolean ret = FALSE;

	/* If we can't access the shadow file as a normal user, then the
	 * answer is "yes". */
	path = module_filename(module, suffix_shadow);
	if (access(path, R_OK | W_OK) != 0) {
		ret = TRUE;
	}
	g_free(path);
	/* If we can't access the gshadow file as a normal user, then the
	 * answer is "yes". */
	path = module_filename(module, suffix_gshadow);
	if (access(path, R_OK | W_OK) != 0) {
		ret = TRUE;
	}
	g_free(path);
	return ret;
}

static gboolean
close_module(struct lu_module *module)
{
	g_return_val_if_fail(module != NULL, FALSE);

	module->scache->free(module->scache);
	memset(module, 0, sizeof(struct lu_module));
	g_free(module);
	return TRUE;
}

struct lu_module *
libuser_files_init(struct lu_context *context,
		   struct lu_error **error)
{
	struct lu_module *ret;

	g_return_val_if_fail(context != NULL, FALSE);

	/* Handle authenticating to the data source. */
	if (geteuid() != 0) {
		const char *val;

		/* Needed for the test suite, handy for debugging. */
		val = lu_cfg_read_single(context, "files/nonroot", NULL);
		if (val == NULL || strcmp (val, "yes") != 0) {
			lu_error_new(error, lu_error_privilege,
				     _("not executing with superuser "
				       "privileges"));
			return NULL;
		}
	}

	/* Allocate the method structure. */
	ret = g_malloc0(sizeof(struct lu_module));
	ret->version = LU_MODULE_VERSION;
	ret->scache = lu_string_cache_new(TRUE);
	ret->name = ret->scache->cache(ret->scache, LU_MODULE_NAME_FILES);

	/* Set the method pointers. */
	ret->valid_module_combination
	  = lu_files_shadow_valid_module_combination;
	ret->uses_elevated_privileges = lu_files_uses_elevated_privileges;

	ret->user_lookup_name = lu_files_user_lookup_name;
	ret->user_lookup_id = lu_files_user_lookup_id;

	ret->user_default = lu_common_user_default;
	ret->user_add_prep = lu_files_user_add_prep;
	ret->user_add = lu_files_user_add;
	ret->user_mod = lu_files_user_mod;
	ret->user_del = lu_files_user_del;
	ret->user_lock = lu_files_user_lock;
	ret->user_unlock = lu_files_user_unlock;
	ret->user_unlock_nonempty = lu_files_user_unlock_nonempty;
	ret->user_is_locked = lu_files_user_is_locked;
	ret->user_setpass = lu_files_user_setpass;
	ret->user_removepass = lu_files_user_removepass;
	ret->users_enumerate = lu_files_users_enumerate;
	ret->users_enumerate_by_group = lu_files_users_enumerate_by_group;
	ret->users_enumerate_full = lu_files_users_enumerate_full;

	ret->group_lookup_name = lu_files_group_lookup_name;
	ret->group_lookup_id = lu_files_group_lookup_id;

	ret->group_default = lu_common_group_default;
	ret->group_add_prep = lu_files_group_add_prep;
	ret->group_add = lu_files_group_add;
	ret->group_mod = lu_files_group_mod;
	ret->group_del = lu_files_group_del;
	ret->group_lock = lu_files_group_lock;
	ret->group_unlock = lu_files_group_unlock;
	ret->group_unlock_nonempty = lu_files_group_unlock_nonempty;
	ret->group_is_locked = lu_files_group_is_locked;
	ret->group_setpass = lu_files_group_setpass;
	ret->group_removepass = lu_files_group_removepass;
	ret->groups_enumerate = lu_files_groups_enumerate;
	ret->groups_enumerate_by_user = lu_files_groups_enumerate_by_user;
	ret->groups_enumerate_full = lu_files_groups_enumerate_full;

	ret->close = close_module;

	/* Done. */
	return ret;
}

struct lu_module *
libuser_shadow_init(struct lu_context *context,
	            struct lu_error **error)
{
	struct lu_module *ret;
	struct stat st;
	char *shadow_file;
	const char *dir;

	g_return_val_if_fail(context != NULL, NULL);

	/* Handle authenticating to the data source. */
	if (geteuid() != 0) {
		const char *val;

		/* Needed for the test suite, handy for debugging. */
		val = lu_cfg_read_single(context, "shadow/nonroot", NULL);
		if (val == NULL || strcmp (val, "yes") != 0) {
			lu_error_new(error, lu_error_privilege,
				     _("not executing with superuser "
				       "privileges"));
			return NULL;
		}
	}

	/* Get the name of the shadow file. */
	dir = lu_cfg_read_single(context, "shadow/directory", "/etc");
	shadow_file = g_strconcat(dir, suffix_shadow, NULL);

	/* Make sure we're actually using shadow passwords on this system. */
	if ((stat(shadow_file, &st) == -1) && (errno == ENOENT)) {
		lu_error_new(error, lu_warning_config_disabled,
			     _("no shadow file present -- disabling"));
		g_free(shadow_file);
		return NULL;
	}
	g_free(shadow_file);

	/* Allocate the method structure. */
	ret = g_malloc0(sizeof(struct lu_module));
	ret->version = LU_MODULE_VERSION;
	ret->scache = lu_string_cache_new(TRUE);
	ret->name = ret->scache->cache(ret->scache, LU_MODULE_NAME_SHADOW);

	/* Set the method pointers. */
	ret->valid_module_combination
	  = lu_files_shadow_valid_module_combination;
	ret->uses_elevated_privileges = lu_shadow_uses_elevated_privileges;

	ret->user_lookup_name = lu_shadow_user_lookup_name;
	ret->user_lookup_id = lu_shadow_user_lookup_id;

	ret->user_default = lu_common_suser_default;
	ret->user_add_prep = lu_shadow_user_add_prep;
	ret->user_add = lu_shadow_user_add;
	ret->user_mod = lu_shadow_user_mod;
	ret->user_del = lu_shadow_user_del;
	ret->user_lock = lu_shadow_user_lock;
	ret->user_unlock = lu_shadow_user_unlock;
	ret->user_unlock_nonempty = lu_shadow_user_unlock_nonempty;
	ret->user_is_locked = lu_shadow_user_is_locked;
	ret->user_setpass = lu_shadow_user_setpass;
	ret->user_removepass = lu_shadow_user_removepass;
	ret->users_enumerate = lu_shadow_users_enumerate;
	ret->users_enumerate_by_group = lu_shadow_users_enumerate_by_group;
	ret->users_enumerate_full = lu_shadow_users_enumerate_full;

	ret->group_lookup_name = lu_shadow_group_lookup_name;
	ret->group_lookup_id = lu_shadow_group_lookup_id;

	ret->group_default = lu_common_sgroup_default;
	ret->group_add_prep = lu_shadow_group_add_prep;
	ret->group_add = lu_shadow_group_add;
	ret->group_mod = lu_shadow_group_mod;
	ret->group_del = lu_shadow_group_del;
	ret->group_lock = lu_shadow_group_lock;
	ret->group_unlock = lu_shadow_group_unlock;
	ret->group_unlock_nonempty = lu_shadow_group_unlock_nonempty;
	ret->group_is_locked = lu_shadow_group_is_locked;
	ret->group_setpass = lu_shadow_group_setpass;
	ret->group_removepass = lu_shadow_group_removepass;
	ret->groups_enumerate = lu_shadow_groups_enumerate;
	ret->groups_enumerate_by_user = lu_shadow_groups_enumerate_by_user;
	ret->groups_enumerate_full = lu_shadow_groups_enumerate_full;

	ret->close = close_module;

	/* Done. */
	return ret;
}
