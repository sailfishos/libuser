/* Copyright (C) 2000-2002, 2004, 2005, 2006, 2007, 2012 Red Hat, Inc.
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
#include <dirent.h>
#include <fcntl.h>
#include <glib.h>
#include <grp.h>
#include <libintl.h>
#include <limits.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utime.h>
#include "error.h"
#include "fs.h"
#include "user.h"
#include "user_private.h"

/**
 * SECTION:fs
 * @short_description: Utilities for modifying the file system and other
 * aspects of user/group management.
 * @include: libuser/fs.h
 *
 * These routines allow an application to work with home directories, mail
 * spools and nscd caches.
 */

/* Return current umask value */
static mode_t
current_umask(void)
{
	mode_t value;

	value = umask(S_IRWXU | S_IRWXG | S_IRWXO);
	umask(value);
	return value;
}

/* What should the ownership and permissions of the copied files be? */
struct copy_access_options
{
	/* Preserve ownership and permissions of the original unmodified;
	   otherwise, use matchpathcon() for SELinux contexts and apply
	   the following fields.. */
	gboolean preserve_source;
	uid_t uid;	     /* UID to use for the copy if !preserve_source. */
	/* GID to use for the copy if !preserve_source and original is owned by
	   GID 0. */
	gid_t gid;
	mode_t umask;	      /* umask to apply to modes if !preserve_source */
};

/* Return an UID appropriate for a copy of ST given OPTIONS. */
static uid_t
uid_for_copy(const struct copy_access_options *options, const struct stat *st)
{
	if (options->preserve_source)
		return st->st_uid;
	return options->uid;
}

/* Return a GID appropriate for a copy of ST given OPTIONS. */
static gid_t
gid_for_copy(const struct copy_access_options *options, const struct stat *st)
{
	if (options->preserve_source)
		return st->st_gid;
	if (st->st_gid != 0) /* Skeleton wants us to us a different group */
		return st->st_gid;
	return options->gid;
}

/* Return a mode_t value appropriate for a copy of ST given OPTIONS. */
static mode_t
mode_for_copy(const struct copy_access_options *options, const struct stat *st)
{
	if (options->preserve_source)
		return st->st_mode;
	return st->st_mode & ~options->umask;
}

/* Copy symlink SYMLINK_NAME in SRC_DIR_FD, which corresponds to SRC_PATH, to
   SYMLINK_NAME in DEST_DIR_FD, which corresponds to DEST_PATH.  Use
   ACCESS_OPTIONS.  Use SRC_STAT for data about SRC_PATH.

   On return from this function, SELinux fscreate context is unspecified.

   Note that SRC_PATH should only be used for error messages, not to access the
   files; if the user is still logged in, a directory in the path may be
   replaced by a symbolic link, redirecting the access outside of
   SRC_DIR_FD/SYMLINK_NAME.  Likewise for DEST_*. */
static gboolean
copy_symlink(int src_dir_fd, const char *src_path, int dest_dir_fd,
	     const char *dest_path, const char *symlink_name,
	     const struct stat *src_stat,
	     const struct copy_access_options *access_options,
	     struct lu_error **error)
{
	char buf[PATH_MAX];
	ssize_t len;
	struct timespec timebuf[2];

	LU_ERROR_CHECK(error);

	/* In the worst case here, we end up with a wrong SELinux context for a
	   symbolic link due to a path name lookup race.  That's unfortunate,
	   but symlink contents are more or less public anyway... (A possible
	   improvement would be to use Linux-only O_PATH to open src_path
	   first, then see if it is a symlink, and "upgrade" to an O_RDONLY if
	   not.  But O_PATH is available only in Linux >= 2.6.39.)

	   The symlinkat()/fchownat()/utimensat() calls are also not safe
	   against an user meddling; we might be able to ensure the
	   fchownat()/utimensat() are done on the same file using O_PATH again,
	   but symlinkat()/the rest is definitely unatomic.  Rely on having an
	   unwritable the parent directory, same as in the mkdirat()/openat()
	   case of lu_homedir_copy_and_close(). */
	if (access_options->preserve_source) {
		if (!lu_util_fscreate_from_lfile(src_path, error))
			return FALSE;
	} else if (!lu_util_fscreate_for_path(dest_path,
					      src_stat->st_mode & S_IFMT,
					      error))
		return FALSE;

	len = readlinkat(src_dir_fd, symlink_name, buf, sizeof(buf) - 1);
	if (len == -1) {
		lu_error_new(error, lu_error_generic,
			     _("Error reading `%s': %s"), src_path,
			     strerror(errno));
		return FALSE;
	}
	buf[len] = '\0';
	if (symlinkat(buf, dest_dir_fd, symlink_name) == -1) {
		lu_error_new(error, lu_error_generic,
			     _("Error creating `%s': %s"), dest_path,
			     strerror(errno));
		return FALSE;
	}
	if (fchownat(dest_dir_fd, symlink_name,
		     uid_for_copy(access_options, src_stat),
		     gid_for_copy(access_options, src_stat),
		     AT_SYMLINK_NOFOLLOW) == -1
	    && errno != EPERM && errno != EOPNOTSUPP) {
		lu_error_new(error, lu_error_generic,
			     _("Error changing owner of `%s': %s"), dest_path,
			     strerror(errno));
		return FALSE;
	}
	timebuf[0] = src_stat->st_atim;
	timebuf[1] = src_stat->st_mtim;
	utimensat(dest_dir_fd, symlink_name, timebuf, AT_SYMLINK_NOFOLLOW);
	return TRUE;
}

/* Copy SRC_FD, which corresponds to SRC_PATH, to DEST_NAME in DEST_DIR_FD,
   which corresponds to DEST_PATH.  Use ACCESS_OPTIONS.  Use SRC_STAT for data
   about SRC_PATH.

   On return from this function, SELinux fscreate context is unspecified.

   Note that SRC_PATH should only be used for error messages, not to access the
   files; if the user is still logged in, a directory in the path may be
   replaced by a symbolic link, redirecting the access outside of SRC_FD.
   Likewise for DEST_*. */
static gboolean
copy_regular_file(int src_fd, const char *src_path, int dest_dir_fd,
		  const char *dest_name, const char *dest_path,
		  const struct stat *src_stat,
		  const struct copy_access_options *access_options,
		  struct lu_error **error)
{
	int dest_fd;
	struct timespec timebuf[2];
	gboolean ret = FALSE;

	LU_ERROR_CHECK(error);

	if (access_options->preserve_source) {
		if (!lu_util_fscreate_from_fd(src_fd, src_path, error))
			return FALSE;
	} else if (!lu_util_fscreate_for_path(dest_path,
					      src_stat->st_mode & S_IFMT,
					      error))
		return FALSE;
	/* Start with absolutely restrictive permissions; the original file may
	   be e.g. a hardlink to /etc/shadow. */
	dest_fd = openat(dest_dir_fd, dest_name,
			 O_EXCL | O_CREAT | O_WRONLY | O_NOFOLLOW, 0);
	if (dest_fd == -1) {
		lu_error_new(error, lu_error_open, _("Error writing `%s': %s"),
			     dest_path, strerror(errno));
		return FALSE;
	}

	/* Now just copy the data. */
	for (;;) {
		unsigned char buf[BUFSIZ];
		ssize_t left;
		unsigned char *p;

		left = read(src_fd, &buf, sizeof(buf));
		if (left == -1) {
			if (errno == EINTR)
				continue;
			lu_error_new(error, lu_error_read,
				     _("Error reading `%s': %s"), src_path,
				     strerror(errno));
			goto err_dest_fd;
		}
		if (left == 0)
			break;
		p = buf;
		while (left > 0) {
			ssize_t out;

			out = write(dest_fd, p, left);
			if (out == -1) {
				if (errno == EINTR)
					continue;
				lu_error_new(error, lu_error_write,
					     _("Error writing `%s': %s"),
					     dest_path, strerror(errno));
				goto err_dest_fd;
			}
			p += out;
			left -= out;
		}
	}

	/* Set the ownership; permissions are still restrictive. */
	if (fchown(dest_fd, uid_for_copy(access_options, src_stat),
		   gid_for_copy(access_options, src_stat)) == -1
	    && errno != EPERM) {
		lu_error_new(error, lu_error_generic,
			     _("Error changing owner of `%s': %s"), dest_path,
			     strerror(errno));
		goto err_dest_fd;
	}

	/* Set the desired mode.  Do this explicitly to preserve S_ISGID and
	   other bits.  Do this after chown, because chown is permitted to
	   reset these bits. */
	if (fchmod(dest_fd, mode_for_copy(access_options, src_stat)) == -1) {
		lu_error_new(error, lu_error_generic,
			     _("Error setting mode of `%s': %s"), dest_path,
			     strerror(errno));
		goto err_dest_fd;
	}

	timebuf[0] = src_stat->st_atim;
	timebuf[1] = src_stat->st_mtim;
	futimens(dest_fd, timebuf);

	ret = TRUE;
	/* Fall through */

err_dest_fd:
	close(dest_fd);
	return ret;
}

/* Forward declaration. */
static gboolean lu_copy_dir_and_close(int src_dir_fd, GString *src_path_buf,
				      int dest_parent_fd,
				      const char *dest_dir_name,
				      GString *dest_path_buf,
				      const struct stat *src_dir_stat,
				      const struct copy_access_options
				      *access_options, struct lu_error **error);

/* Copy ENT_NAME in SRC_DIR_FD, which corresponds to SRC_PATH_BUF,
   to DEST_DIR_FD, which corresponds to DEST_PATH_BUF.  Use ACCESS_OPTIONS.

   On return from this function, SELinux fscreate context is unspecified.  This
   function may temporarily modify SRC_PATH_BUF and DEST_PATH_BUF, but they
   will be unchanged on return.

   Note that SRC_PATH_BUF should only be used for error messages, not to access
   the files; if the user is still logged in, a directory in the path may be
   replaced by a symbolic link, redirecting the access outside of SRC_DIR_FD.
   Likewise for DEST_*. */
static gboolean
copy_dir_entry(int src_dir_fd, GString *src_path_buf, int dest_dir_fd,
	       GString *dest_path_buf, const char *ent_name,
	       const struct copy_access_options *access_options,
	       struct lu_error **error)
{
	struct stat st;
	int ifd;
	gboolean ret = FALSE;

	LU_ERROR_CHECK(error);

	/* Open the input entry first, then we can fstat() it and be certain
	   that it is still the same file.  O_NONBLOCK protects us against
	   FIFOs and perhaps side-effects of the open() of a device file if
	   there ever was one here, and doesn't matter for regular files or
	   directories. */
	ifd = openat(src_dir_fd, ent_name,
		     O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (ifd == -1) {
		int saved_errno;

		saved_errno = errno;
		if (errno != ELOOP || fstatat(src_dir_fd, ent_name, &st,
					      AT_SYMLINK_NOFOLLOW) != 0
		    || !S_ISLNK(st.st_mode)) {
			lu_error_new(error, lu_error_open,
				     _("Error opening `%s': %s"),
				     src_path_buf->str, strerror(saved_errno));
			return FALSE;
		}

		return copy_symlink(src_dir_fd, src_path_buf->str, dest_dir_fd,
				    dest_path_buf->str, ent_name, &st,
				    access_options, error);
	}

	if (fstat(ifd, &st) != 0) {
		lu_error_new(error, lu_error_stat, _("couldn't stat `%s': %s"),
			     src_path_buf->str, strerror(errno));
		goto err_ifd;
	}
	g_assert(!S_ISLNK(st.st_mode));

	if (S_ISDIR(st.st_mode)) {
		ret = lu_copy_dir_and_close(ifd, src_path_buf, dest_dir_fd,
					    ent_name, dest_path_buf, &st,
					    access_options, error);
		ifd = -1;
	} else if (S_ISREG(st.st_mode))
		ret = copy_regular_file(ifd, src_path_buf->str, dest_dir_fd,
					ent_name, dest_path_buf->str, &st,
					access_options, error);
	else
		/* Note that we don't copy device specials. */
		ret = TRUE;
	/* Fall through */

err_ifd:
	if (ifd != -1)
		close(ifd);
	return ret;
}

/* Copy SRC_DIR_FD, which corresponds to SRC_PATH_BUF, to DEST_DIR_NAME under
   DEST_PARENT_FD, which corresponds to DEST_PATH_BUF.  Use ACCESS_OPTIONS.  Use
   SRC_DIR_STAT for data about SRC_PATH_BUF.

   In every case, even on error, close SRC_DIR_FD.

   DEST_PARENT_FD may be AT_FDCWD.  On return from this function, SELinux
   fscreate context is unspecified.  This function may temporarily modify
   SRC_PATH_BUF and DEST_PATH_BUF, but they will be unchanged on return.

   Note that SRC_PATH_BUF should only be used for error messages, not to access
   the files; if the user is still logged in, a directory in the path may be
   replaced by a symbolic link, redirecting the access outside of
   SRC_PARENT_FD/SRC_DIR_NAME.   Likewise for DEST_*. */
static gboolean
lu_copy_dir_and_close(int src_dir_fd, GString *src_path_buf, int dest_parent_fd,
		      const char *dest_dir_name, GString *dest_path_buf,
		      const struct stat *src_dir_stat,
		      const struct copy_access_options *access_options,
		      struct lu_error **error)
{
	size_t orig_src_path_buf_len, orig_dest_path_buf_len;
	struct dirent *ent;
	DIR *dir;
	int dest_dir_fd;
	struct timespec timebuf[2];
	gboolean ret = FALSE;

	LU_ERROR_CHECK(error);
	orig_src_path_buf_len = src_path_buf->len;
	orig_dest_path_buf_len = dest_path_buf->len;

	if (*dest_path_buf->str != '/') {
		lu_error_new(error, lu_error_generic,
			     _("Home directory path `%s' is not absolute"),
			     dest_path_buf->str);
		goto err_src_dir_fd;
	}

	dir = fdopendir(src_dir_fd);
	if (dir == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("Error reading `%s': %s"), src_path_buf->str,
			     strerror(errno));
		goto err_src_dir_fd;
	}

	if (access_options->preserve_source) {
		if (!lu_util_fscreate_from_fd(src_dir_fd, src_path_buf->str,
					      error))
			goto err_dir;
	} else if (!lu_util_fscreate_for_path(dest_path_buf->str,
					      src_dir_stat->st_mode & S_IFMT,
					      error))
		goto err_dir;

	/* Create the directory.  It starts owned by us (presumbaly root), with
	   fairly restrictive permissions that still allow us to use the
	   directory. */
	if (mkdirat(dest_parent_fd, dest_dir_name, S_IRWXU) == -1) {
		lu_error_new(error, lu_error_generic,
			     _("Error creating `%s': %s"), dest_path_buf->str,
			     strerror(errno));
		goto err_dir;
	}
	/* FIXME: O_SEARCH would be ideal here, but Linux doesn't currently
	   provide it. */
	dest_dir_fd = openat(dest_parent_fd, dest_dir_name,
			     O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
	if (dest_dir_fd == -1) {
		lu_error_new(error, lu_error_open, _("Error opening `%s': %s"),
			     dest_path_buf->str, strerror(errno));
		goto err_dir;
	}
	/* The openat() after mkdirat() is not 100% safe; we may be modifying
	   ownership/permissions of another user's directory that was moved to
	   dest_dir_name in the mean time!  (Although why there would exist an
	   another user's directory, assuming lack hardlinks of directories, is
	   not clear.)

	   There's no way to do this completely atomically; so, rely on
	   permissions of the parent directory (write access to parent is
	   required to rename directories).  This holds for the top-level
	   directory, and for the others we achieve this by creating them
	   root-owned and S_IRWXU, and only applying the original ownership and
	   permissions after finishing other work.  See also the comment in
	   copy_symlink(). */

	while ((ent = readdir(dir)) != NULL) {
		if (strcmp(ent->d_name, ".") == 0
		    || strcmp(ent->d_name, "..") == 0)
			continue;

		/* Build the path of the source file or directory and its
		   corresponding member in the new tree. */
		g_string_append_c(src_path_buf, '/');
		g_string_append(src_path_buf, ent->d_name);
		g_string_append_c(dest_path_buf, '/');
		g_string_append(dest_path_buf, ent->d_name);

		if (!copy_dir_entry(src_dir_fd, src_path_buf, dest_dir_fd,
				    dest_path_buf, ent->d_name, access_options,
				    error))
			goto err_dest_dir_fd;

		g_string_truncate(src_path_buf, orig_src_path_buf_len);
		g_string_truncate(dest_path_buf, orig_dest_path_buf_len);
	}

	/* Set the ownership on the directory.  Permissions are still
	   fairly restrictive. */
	if (fchown(dest_dir_fd, uid_for_copy(access_options, src_dir_stat),
		   gid_for_copy(access_options, src_dir_stat)) == -1
	    && errno != EPERM) {
		lu_error_new(error, lu_error_generic,
			     _("Error changing owner of `%s': %s"),
			     dest_path_buf->str, strerror(errno));
		goto err_dest_dir_fd;
	}

	/* Set the desired mode.  Do this explicitly to preserve S_ISGID and
	   other bits.  Do this after chown, because chown is permitted to
	   reset these bits. */
	if (fchmod(dest_dir_fd,
		   mode_for_copy(access_options, src_dir_stat)) == -1) {
		lu_error_new(error, lu_error_generic,
			     _("Error setting mode of `%s': %s"),
			     dest_path_buf->str, strerror(errno));
		goto err_dest_dir_fd;
	}

	timebuf[0] = src_dir_stat->st_atim;
	timebuf[1] = src_dir_stat->st_mtim;
	futimens(dest_dir_fd, timebuf);

	ret = TRUE;
	/* Fall through */

 err_dest_dir_fd:
	close(dest_dir_fd);
 err_dir:
	closedir(dir);
	src_dir_fd = -1;
 err_src_dir_fd:
	if (src_dir_fd != -1)
		close(src_dir_fd);
	g_string_truncate(src_path_buf, orig_src_path_buf_len);
	g_string_truncate(dest_path_buf, orig_dest_path_buf_len);
	return ret;
}

/* Copy SRC_DIR to DEST_DIR.  Use ACCESS_OPTIONS.

   Return TRUE on error.

   To be secure, neither SRC_DIR nor DEST_DIR should contain any
   user-controlled parent directories in the path.  SRC_DIR may be an
   user-owned directory, or even a symlink, but its parent should not be
   user-writable (so that the user can't replace it with a symlink or change
   the symlink). */
static gboolean
lu_homedir_copy(const char *src_dir, const char *dest_dir,
		const struct copy_access_options *access_options,
		struct lu_error **error)
{
	lu_security_context_t fscreate;
	int fd;
	struct stat st;
	GString *src_path_buf, *dest_path_buf;
	gboolean ret;

	LU_ERROR_CHECK(error);

	ret = FALSE;
	if (!lu_util_fscreate_save(&fscreate, error))
		goto err;

	fd = open(src_dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
	if (fd == -1) {
		lu_error_new(error, lu_error_open, _("Error opening `%s': %s"),
			     src_dir, strerror(errno));
		goto err_fscreate;
	}
	if (fstat(fd, &st) == -1) {
		lu_error_new(error, lu_error_stat, _("couldn't stat `%s': %s"),
			     src_dir, strerror(errno));
		goto err_fd;
	}

	src_path_buf = g_string_new(src_dir);
	dest_path_buf = g_string_new(dest_dir);
	ret = lu_copy_dir_and_close(fd, src_path_buf, AT_FDCWD, dest_dir,
				    dest_path_buf, &st, access_options, error);
	g_string_free(dest_path_buf, TRUE);
	g_string_free(src_path_buf, TRUE);
	goto err_fscreate;

err_fd:
	close(fd);
err_fscreate:
	lu_util_fscreate_restore(fscreate);
err:
	return ret;
}

/**
 * lu_homedir_populate:
 * @ctx: A context
 * @skeleton: Path to a "skeleton" directory, or %NULL for the system default
 * @directory: The home directory to populate
 * @owner: UID to use for contents of the new home directory
 * @group: GID to use for contents of the new home directory that have GID set
 * to 0 in the skeleton director
 * @mode: Mode to use for the top-level directory, also affected by umask
 * @error: Filled with #lu_error if an error occurs
 *
 * Creates a new home directory for an user.
 *
 * If you want to use this in a hostile environment, ensure that no untrusted
 * user has write permission to any parent of @skeleton or @directory.  Usually
 * /home is only writable by root, which is safe.
 *
 * Returns: %TRUE on success
 */
gboolean
lu_homedir_populate(struct lu_context *ctx, const char *skeleton,
		    const char *directory, uid_t owner, gid_t group,
		    mode_t mode, struct lu_error **error)
{
	struct copy_access_options access_options;

	LU_ERROR_CHECK(error);
	g_return_val_if_fail(ctx != NULL, FALSE);
	g_return_val_if_fail(directory != NULL, FALSE);

	if (skeleton == NULL)
		skeleton = lu_cfg_read_single(ctx, "defaults/skeleton",
					      "/etc/skel");
	access_options.preserve_source = FALSE;
	access_options.uid = owner;
	access_options.gid = group;
	access_options.umask = current_umask();
	if (!lu_homedir_copy(skeleton, directory, &access_options, error))
		return FALSE;

	/* Now reconfigure the toplevel directory as desired.  The directory
	   thus might have incorrect owner/permissions for a while; this is OK
	   because the contents are public anyway (every users sees them on
	   first access), and write access is not allowed because the skeleton
	   is not writable. */

	/* Set the ownership on the top-level directory manually again,
	   lu_homedir_copy() would have preserved st.st_gid if it were not root
	   for some reason; our API promises to use precisely "owner" and
	   "group". */
	if (chown(directory, owner, group) == -1 && errno != EPERM) {
		lu_error_new(error, lu_error_generic,
			     _("Error changing owner of `%s': %s"), directory,
			     strerror(errno));
		return FALSE;
	}
	/* Set modes as required instead of preserving st.st_mode.  Do this
	   after chown, because chown is permitted to reset these bits. */
	if (chmod(directory, mode & ~access_options.umask) == -1) {
		lu_error_new(error, lu_error_generic,
			     _("Error setting mode of `%s': %s"), directory,
			     strerror(errno));
		return FALSE;
	}

	return TRUE;
}

/* Recursively remove directory DIR_NAME under PARENT_FD, which corresponds to
   PATH_BUF.

   Before doing anything, if REQUIRED_TOPLEVEL_UID is not LU_VALUE_INVALID_ID,
   make sure that DIR_NAME is owned by that UID, or fail with
   lu_error_homedir_not_owned.

   Return TRUE on sucess.

   PARENT_FD may be AT_FDCWD.  This function may temporarily modify PATH_BUF,
   but it will be unchanged on return.

   Note that PATH_BUF should only be used for error messages, not to access
   the files; if the user is still logged in, a directory in the path may be
   replaced by a symbolic link, redirecting the access outside of
   PARENT_FD/DIR_NAME. */
static gboolean
remove_subdirectory(int parent_fd, const char *dir_name, GString *path_buf,
		    uid_t required_toplevel_uid, struct lu_error **error)
{
	size_t orig_path_buf_len;
	int dir_fd;
	struct dirent *ent;
	DIR *dir;

	LU_ERROR_CHECK(error);
	orig_path_buf_len = path_buf->len;

	dir_fd = openat(parent_fd, dir_name,
			O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
	if (dir_fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("Error opening `%s': %s"), path_buf->str,
			     strerror(errno));
		return FALSE;
	}

	if (required_toplevel_uid != LU_VALUE_INVALID_ID) {
		struct stat st;

		if (fstat(dir_fd, &st) == -1) {
			lu_error_new(error, lu_error_stat,
				     _("couldn't stat `%s': %s"), path_buf->str,
				     strerror(errno));
			goto err_dir_fd;
		}
		if (st.st_uid != required_toplevel_uid) {
			lu_error_new(error, lu_error_homedir_not_owned,
				     _("`%s' is not owned by UID `%d'"),
				     path_buf->str, required_toplevel_uid);
			goto err_dir_fd;
		}
	}

	dir = fdopendir(dir_fd);
	if (dir == NULL) {
		lu_error_new(error, lu_error_open,
			     _("Error opening `%s': %s"), path_buf->str,
			     strerror(errno));
		goto err_dir_fd;
	}

	/* Iterate over all of its contents. */
	while ((ent = readdir(dir)) != NULL) {
		struct stat st;

		/* Skip over the self and parent hard links. */
		if (strcmp(ent->d_name, ".") == 0
		    || strcmp(ent->d_name, "..") == 0)
			continue;

		/* Generate the full path of the next victim. */
		g_string_append_c(path_buf, '/');
		g_string_append(path_buf, ent->d_name);

		/* What we do next depends on whether or not the next item to
		   remove is a directory. */
		if (fstatat(dir_fd, ent->d_name, &st,
			    AT_SYMLINK_NOFOLLOW) == -1) {
			lu_error_new(error, lu_error_stat,
				     _("couldn't stat `%s': %s"), path_buf->str,
				     strerror(errno));
			goto err_dir;
		}
		if (S_ISDIR(st.st_mode)) {
			/* We descend into subdirectories... */
			if (remove_subdirectory(dir_fd, ent->d_name, path_buf,
						LU_VALUE_INVALID_ID,
						error) == FALSE)
				goto err_dir;
		} else {
			/* ... and unlink everything else. */
			if (unlinkat(dir_fd, ent->d_name, 0) == -1) {
				lu_error_new(error, lu_error_generic,
					     _("Error removing `%s': %s"),
					     path_buf->str, strerror(errno));
				goto err_dir;
			}
		}

		g_string_truncate(path_buf, orig_path_buf_len);
	}

	closedir(dir);

	/* As a final step, remove the directory itself. */
	if (unlinkat(parent_fd, dir_name, AT_REMOVEDIR) == -1) {
		lu_error_new(error, lu_error_generic,
			     _("Error removing `%s': %s"), path_buf->str,
			     strerror(errno));
		return FALSE;
	}

	return TRUE;

err_dir:
	closedir(dir);
	g_string_truncate(path_buf, orig_path_buf_len);
	return FALSE;

err_dir_fd:
	close(dir_fd);
	return FALSE;
}

/**
 * lu_homedir_remove:
 * @directory: Path to the root of the directory tree
 * @error: Filled with #lu_error if an error occurs
 *
 * Recursively removes a user's home (or really, any) directory.
 *
 * If you want to use this in a hostile environment, ensure that no untrusted
 * user has write permission to any parent of @directory.
 *
 * Returns: %TRUE on success
 */
gboolean
lu_homedir_remove(const char *directory, struct lu_error ** error)
{
	gboolean ret;
	GString *path_buf;

	LU_ERROR_CHECK(error);
	g_return_val_if_fail(directory != NULL, FALSE);
	path_buf = g_string_new(directory);
	ret = remove_subdirectory(AT_FDCWD, directory, path_buf,
				  LU_VALUE_INVALID_ID, error);
	g_string_free(path_buf, TRUE);
	return ret;
}

/* Recursively remove the home directory of user ENT if the top-level directory
   is owned by REQUIRED_TOPLEVEL_UID or if REQUIRED_TOPLEVEL_UID is
   LU_VALUE_INVALID_ID.  Otherwise fail with lu_error_homedir_not_owned.

   Return TRUE on sucess.

   If you want to use this in a hostile environment, ensure that no untrusted
   user has write permission to any parent of ENT's home directory. */
static gboolean
homedir_remove_for_user(struct lu_ent *ent, uid_t required_toplevel_uid,
			struct lu_error **error)
{
	gboolean ret;
	const char *home;
	GString *path_buf;

	LU_ERROR_CHECK(error);
	g_assert(ent->type == lu_user);

	home = lu_ent_get_first_string(ent, LU_HOMEDIRECTORY);
	if (home == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("user object had no %s attribute"),
			     LU_HOMEDIRECTORY);
		return FALSE;
	}
	path_buf = g_string_new(home);
	ret = remove_subdirectory(AT_FDCWD, home, path_buf,
				  required_toplevel_uid, error);
	g_string_free(path_buf, TRUE);
	return ret;
}

/**
 * lu_homedir_remove_for_user:
 * @ent: An entity describing the user
 * @error: Filled with #lu_error if an error occurs
 *
 * Recursively removes the home directory of user @ent.
 *
 * If you want to use this in a hostile environment, ensure that no untrusted
 * user has write permission to any parent of @ent's home directory.
 *
 * Returns: %TRUE on success
 */
gboolean
lu_homedir_remove_for_user(struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->type == lu_user, FALSE);

	return homedir_remove_for_user(ent, LU_VALUE_INVALID_ID, error);
}

/**
 * lu_homedir_remove_for_user_if_owned:
 * @ent: An entity describing the user
 * @error: Filled with #lu_error if an error occurs
 *
 * Recursively removes the home directory of user @ent, only if the directory
 * is owned by @ent.  Otherwise fails with %lu_error_homedir_not_owned.
 *
 * If you want to use this in a hostile environment, ensure that no untrusted
 * user has write permission to any parent of @ent's home directory.
 *
 * Returns: %TRUE on success
 */
gboolean
lu_homedir_remove_for_user_if_owned(struct lu_ent *ent, struct lu_error **error)
{
	uid_t uid;

	LU_ERROR_CHECK(error);
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->type == lu_user, FALSE);

	uid = lu_ent_get_first_id(ent, LU_UIDNUMBER);
	if (uid == LU_VALUE_INVALID_ID) {
		lu_error_new(error, lu_error_generic,
			     _("user object had no %s attribute"),
			     LU_UIDNUMBER);
		return FALSE;
	}

	return homedir_remove_for_user(ent, uid, error);
}

/**
 * lu_homedir_move:
 * @oldhome: Path to the old home directory
 * @newhome: Path to the new home directory
 * @error: Filled with #lu_error if an error occurs
 *
 * Moves user's home directory to @newhome.
 *
 * Currently implemented by first creating a copy, then deleting the original,
 * expect this to take a long time.
 *
 * If you want to use this in a hostile environment, ensure that no untrusted
 * user has write permission to any parent of @oldhome or @newhome.  Usually
 * /home is only writable by root, which is safe; user's write permission to
 * @oldhome itself is OK.
 *
 * Returns: %TRUE on success
 */
gboolean
lu_homedir_move(const char *oldhome, const char *newhome,
		struct lu_error ** error)
{
	struct copy_access_options access_options;

	LU_ERROR_CHECK(error);
	g_return_val_if_fail(oldhome != NULL, FALSE);
	g_return_val_if_fail(newhome != NULL, FALSE);

	access_options.preserve_source = TRUE;
	if (!lu_homedir_copy(oldhome, newhome, &access_options, error))
		return FALSE;

	return lu_homedir_remove(oldhome, error);
}

/**
 * lu_nscd_flush_cache:
 * @table: Name of the relevant nscd table
 *
 * Flushes the specified nscd cache to make the changes performed by other
 * libuser functions immediately visible.
 */
void
lu_nscd_flush_cache (const char *table)
{
	static char *const envp[] = { NULL };

	g_return_if_fail(table != NULL);

	posix_spawn_file_actions_t fa;
        char *argv[4];
        pid_t pid;

	if (posix_spawn_file_actions_init(&fa) != 0
	    || posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/dev/null",
						O_RDWR, 0) != 0)
                return;

	argv[0] = NSCD;
	argv[1] = "-i";
	argv[2] = (char *)table;
	argv[3] = NULL;
	if (posix_spawn(&pid, argv[0], &fa, NULL, argv, envp) != 0)
		return;
	posix_spawn_file_actions_destroy(&fa);

        /* Wait for the spawned process to exit */
	while (waitpid(pid, NULL, 0) == -1 && errno == EINTR)
		; /* Nothing */
}

/* Return mail spool path for an USER.
   Returns: A path for g_free (), or NULL on error */
static char *
mail_spool_path(struct lu_context *ctx, struct lu_ent *ent,
		struct lu_error **error)
{
	const char *spooldir;
	char *p, *username;

	LU_ERROR_CHECK(error);

	/* Now get the user's login. */
	username = lu_ent_get_first_value_strdup(ent, LU_USERNAME);
	if (username == NULL) {
		lu_error_new(error, lu_error_name_bad,
			     _("Missing user name"));
		return NULL;
	}

	/* Get the location of the spool directory. */
	spooldir = lu_cfg_read_single(ctx, "defaults/mailspooldir",
				      "/var/mail");

	p = g_strconcat(spooldir, "/", username, (const gchar *)NULL);
	g_free(username);
	return p;
}

/**
 * lu_mail_spool_create:
 * @ctx: A context
 * @ent: An entity representing the relevant user
 * @error: Filled with #lu_error if an error occurs
 *
 * Creates a mail spool for the specified user.
 *
 * Returns: %TRUE on success
 */
gboolean
lu_mail_spool_create(struct lu_context *ctx, struct lu_ent *ent,
		     struct lu_error **error)
{
	uid_t uid;
	gid_t gid;
	char *spool_path;
	struct lu_ent *groupEnt;
	struct lu_error *err2;
	int fd;

	LU_ERROR_CHECK(error);
	g_return_val_if_fail(ctx != NULL, FALSE);
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->type == lu_user, FALSE);

	spool_path = mail_spool_path(ctx, ent, error);
	if (spool_path == NULL)
		goto err;

	/* Find the GID of the owner of the file. */
	gid = LU_VALUE_INVALID_ID;
	groupEnt = lu_ent_new();
	err2 = NULL;
	if (lu_group_lookup_name(ctx, "mail", groupEnt, &err2))
		gid = lu_ent_get_first_id(groupEnt, LU_GIDNUMBER);
	if (err2 != NULL)
		lu_error_free(&err2);
	lu_ent_free(groupEnt);

	/* Er, okay.  Check with libc. */
	if (gid == LU_VALUE_INVALID_ID) {
		struct group grp, *err;
		char buf[LINE_MAX * 4];

		if ((getgrnam_r("mail", &grp, buf, sizeof(buf), &err) == 0) &&
		    (err == &grp)) {
			gid = grp.gr_gid;
		}
	}

	/* Aiieee.  Use the user's group. */
	if (gid == LU_VALUE_INVALID_ID)
		gid = lu_ent_get_first_id(ent, LU_GIDNUMBER);
	if (gid == LU_VALUE_INVALID_ID) {
		lu_error_new(error, lu_error_generic,
			     _("Cannot determine GID to use for mail spool"));
		goto err_spool_path;
	}

	/* Now get the user's UID. */
	uid = lu_ent_get_first_id(ent, LU_UIDNUMBER);
	if (uid == LU_VALUE_INVALID_ID) {
		lu_error_new(error, lu_error_generic,
			     _("Cannot determine UID to use for mail spool"));
		goto err_spool_path;
	}

	fd = open(spool_path, O_WRONLY | O_CREAT, 0);
	if (fd == -1) {
		lu_error_new(error, lu_error_open, _("couldn't open `%s': %s"),
			     spool_path, strerror(errno));
		goto err_spool_path;
	}
	if (fchown(fd, uid, gid) == -1) {
		lu_error_new(error, lu_error_generic,
			     _("Error changing owner of `%s': %s"), spool_path,
			     strerror(errno));
		goto err_fd;
	}
	if (fchmod(fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) == -1) {
		lu_error_new(error, lu_error_generic,
			     _("Error changing mode of `%s': %s"), spool_path,
			     strerror(errno));
		goto err_fd;
	}
	close(fd);

	g_free(spool_path);
	return TRUE;

err_fd:
	close(fd);
err_spool_path:
	g_free(spool_path);
err:
	return FALSE;
}

/**
 * lu_mail_spool_remove:
 * @ctx: A context
 * @ent: An entity representing the relevant user
 * @error: Filled with #lu_error if an error occurs
 *
 * Creates a mail spool for the specified user.
 *
 * Returns: %TRUE on success
 */
gboolean
lu_mail_spool_remove(struct lu_context *ctx, struct lu_ent *ent,
		     struct lu_error **error)
{
	char *p;

	LU_ERROR_CHECK(error);
	g_return_val_if_fail(ctx != NULL, FALSE);
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->type == lu_user, FALSE);

	p = mail_spool_path(ctx, ent, error);
	if (p == NULL)
		return FALSE;

	if (unlink(p) != 0 && errno != ENOENT) {
		lu_error_new(error, lu_error_generic,
			     _("Error removing `%s': %s"), p, strerror (errno));
		g_free(p);
		return FALSE;
	}

	g_free(p);
	return TRUE;
}
