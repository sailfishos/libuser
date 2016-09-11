/*
 * Copyright (C) 2000-2002, 2007, 2008 Red Hat, Inc.
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
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <crypt.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#endif
#define LU_DEFAULT_SALT_TYPE "$1$"
#define LU_DEFAULT_SALT_LEN  8
#define LU_MAX_LOCK_ATTEMPTS 6
#define LU_LOCK_TIMEOUT      2
#include "user_private.h"
#include "internal.h"

#define HASH_ROUNDS_MIN 1000
#define HASH_ROUNDS_MAX 999999999

struct lu_lock {
	int fd;
	struct flock lock;
};

/* A wrapper for strcasecmp(). */
gint
lu_strcasecmp(gconstpointer v1, gconstpointer v2)
{
	g_return_val_if_fail(v1 != NULL, 0);
	g_return_val_if_fail(v2 != NULL, 0);
	return g_ascii_strcasecmp((char *) v1, (char *) v2);
}

/* A wrapper for strcmp(). */
gint
lu_strcmp(gconstpointer v1, gconstpointer v2)
{
	g_return_val_if_fail(v1 != NULL, 0);
	g_return_val_if_fail(v2 != NULL, 0);
	return strcmp((char *) v1, (char *) v2);
}

/* A list of allowed salt characters, according to SUSv2. */
#define ACCEPTABLE "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
		   "abcdefghijklmnopqrstuvwxyz" \
		   "./0123456789"

static gboolean
is_acceptable(const char c)
{
	if (c == 0) {
		return FALSE;
	}
	return (strchr(ACCEPTABLE, c) != NULL);
}

static gboolean
fill_urandom(char *output, size_t length)
{
	int fd;
	size_t got = 0;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1)
		return FALSE;

	memset(output, '\0', length);

	while (got < length) {
		ssize_t len;

		len = read(fd, output + got, length - got);
		if (len == -1) {
			if (errno == EINTR)
				continue;
			else {
				close(fd);
				return FALSE;
			}
		}
		while (len != 0 && isprint((unsigned char)output[got])
		       && !isspace((unsigned char)output[got])
		       && is_acceptable(output[got])) {
			got++;
			len--;
		}
	}

	close(fd);
	return TRUE;
}

static const struct {
	const char initial[5];
	char separator[2];
	size_t salt_length;
	gboolean sha_rounds;
} salt_type_info[] = {
	{"$1$", "$", 8, FALSE },
	/* FIXME: number of rounds, base64 of 128 bits */
	{"$2a$", "$", 8, FALSE },
	{"$5$", "$", 16, TRUE },
	{"$6$", "$", 16, TRUE },
	{ "", "", 2 },
};

const char *
lu_make_crypted(const char *plain, const char *previous)
{
	char salt[2048];
	size_t i, len = 0;

	if (previous == NULL) {
		previous = LU_DEFAULT_SALT_TYPE;
	}

	for (i = 0; i < G_N_ELEMENTS(salt_type_info); i++) {
		len = strlen(salt_type_info[i].initial);
		if (strncmp(previous, salt_type_info[i].initial, len) == 0) {
			break;
		}
	}

	g_assert(i < G_N_ELEMENTS(salt_type_info));

	if (salt_type_info[i].sha_rounds != FALSE
	    && strncmp(previous + len, "rounds=", strlen("rounds=")) == 0) {
		const char *start, *end;

		start = previous + len + strlen("rounds=");
		end = strchr(start, '$');
		if (end != NULL
		    && end <= start + strlen(G_STRINGIFY(HASH_ROUNDS_MAX)))
			len = (end + 1) - previous;
	}

	g_assert(len + salt_type_info[i].salt_length
		 + strlen(salt_type_info[i].separator) < sizeof(salt));
	memcpy(salt, previous, len);

	if (fill_urandom(salt + len, salt_type_info[i].salt_length) == FALSE)
		return NULL;
	strcpy(salt + len + salt_type_info[i].salt_length,
	       salt_type_info[i].separator);

	return crypt(plain, salt);
}


static const char *
parse_hash_rounds(struct lu_context *context, const char *key,
		  unsigned long *value)
{
	const char *s;

	s = lu_cfg_read_single(context, key, NULL);
	if (s != NULL) {
		char *end;

		errno = 0;
		*value = strtoul(s, &end, 10);
		if (errno != 0 || *end != 0 || end == s) {
			g_warning("Invalid %s value '%s'", key, s);
			s = NULL;
		}
	}
	return s;
}

static unsigned long
select_hash_rounds(struct lu_context *context)
{
	const char *min_s, *max_s;
	unsigned long min, max, rounds;

	min_s = parse_hash_rounds(context, "defaults/hash_rounds_min", &min);
	max_s = parse_hash_rounds(context, "defaults/hash_rounds_max", &max);
	if (min_s == NULL && max_s == NULL)
		return 0;
	if (min_s != NULL && max_s != NULL) {
		if (min <= max) {
			if (max > HASH_ROUNDS_MAX)
				/* To avoid overflow in (max + 1) below */
				max = HASH_ROUNDS_MAX;
			rounds = g_random_int_range(min, max + 1);
		} else
			rounds = min;
	} else if (min_s != NULL)
		rounds = min;
	else /* max_s != NULL */
		rounds = max;
	if (rounds < HASH_ROUNDS_MIN)
		rounds = HASH_ROUNDS_MIN;
	else if (rounds > HASH_ROUNDS_MAX)
		rounds = HASH_ROUNDS_MAX;
	return rounds;
}

char *
lu_util_default_salt_specifier(struct lu_context *context)
{
	static const struct {
		const char *name, *initializer;
		gboolean sha_rounds;
	} salt_types[] = {
		{ "des", "", FALSE },
		{ "md5", "$1$", FALSE },
		{ "blowfish", "$2a$", FALSE },
		{ "sha256", "$5$", TRUE },
		{ "sha512", "$6$", TRUE },
	};

	const char *salt_type;
	size_t i;

	g_return_val_if_fail(context != NULL, g_strdup(""));

	salt_type = lu_cfg_read_single(context, "defaults/crypt_style", "des");

	for (i = 0; i < G_N_ELEMENTS(salt_types); i++) {
		if (strcasecmp(salt_types[i].name, salt_type) == 0)
			goto found;
	}
	return g_strdup("");

found:
	if (salt_types[i].sha_rounds != FALSE) {
		unsigned long rounds;

		rounds = select_hash_rounds(context);
		if (rounds != 0)
			return g_strdup_printf("%srounds=%lu$",
					       salt_types[i].initializer,
					       rounds);
	}
	return g_strdup(salt_types[i].initializer);
}

gpointer
lu_util_lock_obtain(int fd, struct lu_error ** error)
{
	int i;
	int maxtries = LU_MAX_LOCK_ATTEMPTS;
	int delay = LU_LOCK_TIMEOUT;
	struct lu_lock *ret;

	LU_ERROR_CHECK(error);

	g_assert(fd != -1);
	ret = g_malloc0(sizeof(*ret));

	for (;;) {
		struct timeval tv;

		ret->fd = fd;
		ret->lock.l_type = F_RDLCK;
		if (write(ret->fd, NULL, 0) == 0)
			ret->lock.l_type = F_WRLCK;
		i = fcntl(ret->fd, F_SETLK, &ret->lock);
		if (i != -1)
			return ret;

		if (errno != EINTR && errno != EAGAIN)
			break;

		if (maxtries-- <= 0)
			break;
		memset(&tv, 0, sizeof(tv));
		tv.tv_usec = (delay *= 2);
		select(0, NULL, NULL, NULL, &tv);
	}

	lu_error_new(error, lu_error_lock,
		     _("error locking file: %s"), strerror(errno));
	g_free(ret);
	return NULL;
}

void
lu_util_lock_free(gpointer lock)
{
	struct lu_lock *ret;
	int i;
	g_return_if_fail(lock != NULL);
	ret = (struct lu_lock*) lock;
	do {
		ret->lock.l_type = F_UNLCK;
		i = fcntl(ret->fd, F_SETLK, &ret->lock);
	} while ((i == -1) && ((errno == EINTR) || (errno == EAGAIN)));
	g_free(ret);
}

char *
lu_util_line_get_matchingx(int fd, const char *part, int field,
			   struct lu_error **error)
{
	char *contents, *contents_end;
	struct stat st;
	off_t offset;
	char *ret = NULL, *line;
	gboolean mapped = FALSE;
	size_t part_len;

	LU_ERROR_CHECK(error);

	g_assert(fd != -1);
	g_assert(part != NULL);
	g_assert(field > 0);

	offset = lseek(fd, 0, SEEK_CUR);
	if (offset == -1) {
		lu_error_new(error, lu_error_read, NULL);
		return NULL;
	}

	if (fstat(fd, &st) == -1) {
		lu_error_new(error, lu_error_stat, NULL);
		return NULL;
	}

	contents = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (contents == MAP_FAILED) {
		contents = g_malloc(st.st_size);
		if (lseek(fd, 0, SEEK_SET) == -1
		    || read(fd, contents, st.st_size) != st.st_size
		    || lseek(fd, offset, SEEK_SET) == -1) {
			lu_error_new(error, lu_error_read, NULL);
			g_free(contents);
			return NULL;
		}
	} else {
		mapped = TRUE;
	}
	contents_end = contents + st.st_size;

	part_len = strlen(part);
	line = contents;
	for (;;) {
		char *line_end, *field_start;

		line_end = memchr(line, '\n', contents_end - line);

		if (field == 1)
			field_start = line;
		else {
			int i;
			char *p;

			field_start = NULL;
			i = 1;
			for (p = line; p < contents_end && *p != '\n'; p++) {
				if (*p == ':') {
					i++;
					if (i >= field) {
						field_start = p + 1;
						break;
					}
				}
			}
		}

		if (field_start != NULL
		    && contents_end - field_start >= part_len) {
			char *expected_field_end;

			expected_field_end = field_start + part_len;
			if (strncmp(field_start, part, part_len) == 0
			    && (expected_field_end == contents_end
				|| *expected_field_end == ':'
				|| *expected_field_end == '\n')) {
				if (line_end == NULL)
					line_end = contents_end;
				ret = g_strndup(line, line_end - line);
				break;
			}
		}

		if (line_end == NULL)
			break;
		line = line_end + 1;
	}

	if (mapped) {
		munmap(contents, st.st_size);
	} else {
		g_free(contents);
	}

	return ret;
}

char *
lu_util_line_get_matching1(int fd, const char *part,
			   struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_util_line_get_matchingx(fd, part, 1, error);
}

char *
lu_util_line_get_matching3(int fd, const char *part,
			   struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_util_line_get_matchingx(fd, part, 3, error);
}

char *
lu_util_field_read(int fd, const char *first, unsigned int field,
		   struct lu_error **error)
{
	struct stat st;
	char *buf, *buf_end;
	char *pattern;
	char *line, *start = NULL;
	char *ret;
	size_t len;
	gboolean mapped = FALSE;

	LU_ERROR_CHECK(error);

	g_assert(fd != -1);
	g_assert(first != NULL);
	g_assert(strlen(first) != 0);
	g_assert(field >= 1);

	if (fstat(fd, &st) == -1) {
		lu_error_new(error, lu_error_stat, NULL);
		return NULL;
	}

	buf = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		buf = g_malloc(st.st_size);
		if (lseek(fd, 0, SEEK_SET) == -1
		    || read(fd, buf, st.st_size) != st.st_size) {
			lu_error_new(error, lu_error_read, NULL);
			g_free(buf);
			return NULL;
		}
	} else {
		mapped = TRUE;
	}
	buf_end = buf + st.st_size;

	pattern = g_strdup_printf("%s:", first);
	len = strlen(pattern);
	line = buf;
	for (;;) {
		if (buf_end - line >= len && memcmp (line, pattern, len) == 0)
			goto found_line;
		line = memchr(line, '\n', buf_end - line);
		if (line == NULL)
			break;
		line++;
	}
	lu_error_new(error, lu_error_search, NULL);
	ret = NULL;
	goto err;

found_line:

	/* find the start of the field */
	if (field == 1)
		start = line;
	else {
		unsigned i = 1;
		char *p;

		start = NULL;
		for (p = line; p < buf_end && *p != '\n'; p++) {
			if (*p == ':') {
				i++;
				if (i >= field) {
					start = p + 1;
					break;
				}
			}
		}
	}

	/* find the end of the field */
	if (start != NULL) {
		char *end;

		end = start;
		while (end < buf_end && *end != '\n' && *end != ':')
			end++;
		g_assert(end == buf_end || *end == '\n' || *end == ':');
		ret = g_strndup(start, end - start);
	} else {
		ret = g_strdup("");
	}

err:
	g_free(pattern);
	if (mapped) {
		munmap(buf, st.st_size);
	} else {
		g_free(buf);
	}

	return ret;
}

gboolean
lu_util_field_write(int fd, const char *first, unsigned int field,
		    const char *value, struct lu_error ** error)
{
	struct stat st;
	char *buf;
	char *pattern;
	char *line, *start = NULL, *end = NULL;
	gboolean ret = FALSE;
	unsigned fi = 1;
	size_t len;

	LU_ERROR_CHECK(error);

	g_assert(fd != -1);
	g_assert(field >= 1);

	first = first ? : "";
	value = value ? : "";

	if (fstat(fd, &st) == -1) {
		lu_error_new(error, lu_error_stat, NULL);
		return FALSE;
	}

	if (lseek(fd, 0, SEEK_SET) == -1) {
		lu_error_new(error, lu_error_read, NULL);
		return FALSE;
	}

	buf = g_malloc0(st.st_size + 1 + strlen(value) + field);
	if (read(fd, buf, st.st_size) != st.st_size) {
		lu_error_new(error, lu_error_read, NULL);
		goto err_buf;
	}

	pattern = g_strdup_printf("\n%s:", first);
	if (strncmp(buf, pattern + 1, strlen(pattern) - 1) == 0) {
		/* found it on the first line */
		line = buf;
	} else if ((line = strstr(buf, pattern)) != NULL) {
		/* found it somewhere in the middle */
		line++;
	}
	if (line == NULL) {
		lu_error_new(error, lu_error_search, NULL);
		goto err_pattern;
	}

	/* find the start of the field */
	if (fi == field)
		start = line;
	else {
		char *p;

		start = NULL;
		for (p = line; fi < field && *p != '\n' && *p != '\0'; p++) {
			if (*p == ':') {
				fi++;
				if (fi >= field) {
					start = p + 1;
					break;
				}
			}
		}
	}

	/* find the end of the field */
	if (start != NULL) {
		end = start;
		while ((*end != '\0') && (*end != '\n') && (*end != ':')) {
			end++;
		}
	} else {
		lu_error_new(error, lu_error_search, NULL);
		goto err_pattern;
	}

	if (start != NULL) {
		/* insert the text here, after moving the data around */
		memmove(start + strlen(value), end,
			st.st_size - (end - buf) + 1);
		memcpy(start, value, strlen(value));
	} else {
		/* FIXME: this code currently can't execute */
		/* fi contains the number of fields, so the difference between
		 * field and fi is the number of colons we need to add to the
		 * end of the line to create the field */
		for (end = line; *end != '\0' && *end != '\n'; end++)
			;
		start = end;
		memmove(start + strlen(value) + (field - fi), end,
			st.st_size - (end - buf) + 1);
		memset(start, ':', field - fi);
		memcpy(start + (field - fi), value, strlen(value));
	}

	if (lseek(fd, 0, SEEK_SET) == -1) {
		lu_error_new(error, lu_error_write, NULL);
		goto err_pattern;
	}
	len = strlen(buf);
	if (write(fd, buf, len) != len) {
		lu_error_new(error, lu_error_write, NULL);
		goto err_pattern;
	}
	if (ftruncate(fd, len) == -1) {
		lu_error_new(error, lu_error_write, NULL);
		goto err_pattern;
	}
	ret = TRUE;

err_pattern:
	g_free(pattern);
err_buf:
	g_free(buf);

	return ret;
}

/* Return current date in days since the epoch (suitable for LU_SHADOW*),
   or -1 if the current date is unknown or obviously implausible (e.g. on a
   system without a RTC). */
long
lu_util_shadow_current_date_or_minus_1(void)
{
	const struct tm *gmt;
	time_t now;
	GDate *today, *epoch;
	long days;

	now = time(NULL);
	if (now == (time_t)-1)
		return -1;
	gmt = gmtime(&now);

	today = g_date_new_dmy(gmt->tm_mday, gmt->tm_mon + 1,
			       gmt->tm_year + 1900);
	epoch = g_date_new_dmy(1, 1, 1970);
	days = g_date_get_julian(today) - g_date_get_julian(epoch);
	g_date_free(today);
	g_date_free(epoch);

	/* Refuse to return 0 (Jan 1, 1970): it is unquestionably incorrect in
	   the real world, which is not really libuser's concern, but it is
	   also a special case for LU_SHADOWLASTCHANGE (marking the account for
	   forced password change) and LU_SHADOWEXPIRE (forbidden in
	   shadow(5)).  In both cases, setting the value to -1 deactivates the
	   real-time-related actions, which is a reasonable thing to do when
	   the only available RTC is incorrect. */
	if (days == 0)
		return -1;

	return days;
}

/* Set the shadow last-changed field to today's date. */
void
lu_util_update_shadow_last_change(struct lu_ent *ent)
{
	lu_ent_set_long(ent, LU_SHADOWLASTCHANGE,
			lu_util_shadow_current_date_or_minus_1());
}

#ifdef WITH_SELINUX
/* Store current fscreate context to ctx. */
gboolean
lu_util_fscreate_save(security_context_t *ctx, struct lu_error **error)
{
	*ctx = NULL;
	if (is_selinux_enabled() > 0 && getfscreatecon(ctx) < 0) {
		lu_error_new(error, lu_error_generic,
			     _("couldn't get default security context: %s"),
			     strerror(errno));
		return FALSE;
	}
	return TRUE;
}

/* Restore fscreate context from ctx, and free it. */
void
lu_util_fscreate_restore(security_context_t ctx)
{
	if (is_selinux_enabled() > 0) {
		(void)setfscreatecon(ctx);
		if (ctx)
			freecon(ctx);
	}
}

/* Set fscreate context from context of fd.  Use path only for diagnostics. */
gboolean
lu_util_fscreate_from_fd(int fd, const char *path, struct lu_error **error)
{
	if (is_selinux_enabled() > 0) {
		security_context_t ctx;

		if (fgetfilecon(fd, &ctx) < 0) {
			lu_error_new(error, lu_error_stat,
				     _("couldn't get security context of "
				       "`%s': %s"), path, strerror(errno));
			return FALSE;
		}
		if (setfscreatecon(ctx) < 0) {
			lu_error_new(error, lu_error_generic,
				     _("couldn't set default security context "
				       "to `%s': %s"), ctx, strerror(errno));
			freecon(ctx);
			return FALSE;
		}
		freecon(ctx);
	}
	return TRUE;
}


/* Set fscreate context from context of file. */
gboolean
lu_util_fscreate_from_file(const char *file, struct lu_error **error)
{
	if (is_selinux_enabled() > 0) {
		security_context_t ctx;

		if (getfilecon(file, &ctx) < 0) {
			lu_error_new(error, lu_error_stat,
				     _("couldn't get security context of "
				       "`%s': %s"), file, strerror(errno));
			return FALSE;
		}
		if (setfscreatecon(ctx) < 0) {
			lu_error_new(error, lu_error_generic,
				     _("couldn't set default security context "
				       "to `%s': %s"), ctx, strerror(errno));
			freecon(ctx);
			return FALSE;
		}
		freecon(ctx);
	}
	return TRUE;
}

/* Set fscreate context from context of file, not resolving it if it is a
   symlink. */
gboolean
lu_util_fscreate_from_lfile(const char *file, struct lu_error **error)
{
	if (is_selinux_enabled() > 0) {
		security_context_t ctx;

		if (lgetfilecon(file, &ctx) < 0) {
			lu_error_new(error, lu_error_stat,
				     _("couldn't get security context of "
				       "`%s': %s"), file, strerror(errno));
			return FALSE;
		}
		if (setfscreatecon(ctx) < 0) {
			lu_error_new(error, lu_error_generic,
				     _("couldn't set default security context "
				       "to `%s': %s"), ctx, strerror(errno));
			freecon(ctx);
			return FALSE;
		}
		freecon(ctx);
	}
	return TRUE;
}

/* Set fscreate context for creating a file at path, with file type specified
   by mode. */
gboolean
lu_util_fscreate_for_path(const char *path, mode_t mode,
			  struct lu_error **error)
{
	if (is_selinux_enabled() > 0) {
		security_context_t ctx;

		if (matchpathcon(path, mode, &ctx) < 0) {
			if (errno == ENOENT)
				ctx = NULL;
			else {
				lu_error_new(error, lu_error_stat,
					     _("couldn't determine security "
					       "context for `%s': %s"), path,
					     strerror(errno));
				return FALSE;
			}
		}
		if (setfscreatecon(ctx) < 0) {
			lu_error_new(error, lu_error_generic,
				     _("couldn't set default security context "
				       "to `%s': %s"),
				     ctx != NULL ? ctx : "<<none>>",
				     strerror(errno));
			freecon(ctx);
			return FALSE;
		}
		freecon(ctx);
	}
	return TRUE;
}
#endif

/* Append a copy of VALUES to DEST */
void
lu_util_append_values(GValueArray *dest, GValueArray *values)
{
	size_t i;

	for (i = 0; i < values->n_values; i++)
		g_value_array_append(dest, g_value_array_get_nth(values, i));
}
