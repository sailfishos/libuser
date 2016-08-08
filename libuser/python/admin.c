/* Copyright (C) 2001, 2002, 2004, 2006 Red Hat, Inc.
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

#include <Python.h>
#include <config.h>
#include <errno.h>
#include <grp.h>
#include <inttypes.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>
#include <glib.h>
#include "common.h"
#include "../lib/user.h"
#include "../lib/user_private.h"
#include "../apps/apputil.h"

/* Destroy the object. */
static void
libuser_admin_destroy(PyObject *self)
{
	struct libuser_admin *me = (struct libuser_admin *) self;
	size_t i;
	DEBUG_ENTRY;
	/* Free the context. */
	if (me->ctx != NULL) {
		lu_end(me->ctx);
		me->ctx = NULL;
	}
	/* Free the prompt data. */
	for (i = 0;
	     i < sizeof(me->prompt_data) / sizeof(me->prompt_data[0]);
	     i++) {
		if (me->prompt_data[i]) {
			Py_DECREF(me->prompt_data[i]);
		}
		me->prompt_data[i] = NULL;
	}
	/* Delete the python object. */
	PyObject_DEL(self);
	DEBUG_EXIT;
}

/* "prompt" attribute getter */
static PyObject *
libuser_admin_get_prompt(PyObject *self, void *unused)
{
	struct libuser_admin *me = (struct libuser_admin *)self;

	(void)unused;
	DEBUG_CALL;
	Py_INCREF(me->prompt_data[0]);
	return me->prompt_data[0];
}

/* "prompt" attribute setter */
static int
libuser_admin_set_prompt(PyObject *self, PyObject *value, void *unused)
{
	struct libuser_admin *me = (struct libuser_admin *)self;

	(void)unused;
	DEBUG_ENTRY;
	/* If it's a wrapped up function, set the first prompt data
	 * to the function, and the second to an empty tuple. */
	if (PyCFunction_Check(value)) {
		Py_DECREF(me->prompt_data[0]);
		Py_DECREF(me->prompt_data[1]);
		me->prompt_data[0] = value;
		Py_INCREF(me->prompt_data[0]);
		me->prompt_data[1] = Py_None;
		Py_INCREF(me->prompt_data[0]);
	}
	/* If it's a tuple, the first item is the function, and the
	 * rest are arguments to pass to it. */
	if (PyTuple_Check(value)) {
		Py_DECREF(me->prompt_data[0]);
		Py_DECREF(me->prompt_data[1]);

		me->prompt_data[0] = PyTuple_GetItem(value, 0);
		Py_INCREF(me->prompt_data[0]);

		me->prompt_data[1] = PyTuple_GetSlice(value, 1,
						      PyTuple_Size(value));
	}
	DEBUG_EXIT;
	return 0;
}

/* "prompt_args" attribute getter */
static PyObject *
libuser_admin_get_prompt_args(PyObject *self, void *unused)
{
	struct libuser_admin *me = (struct libuser_admin *)self;

	(void)unused;
	DEBUG_CALL;
	Py_INCREF(me->prompt_data[1]);
	return me->prompt_data[1];
}

/* "prompt_args" attribute setter */
static int
libuser_admin_set_prompt_args(PyObject *self, PyObject *value, void *unused)
{
	struct libuser_admin *me = (struct libuser_admin *)self;

	(void)unused;
	DEBUG_ENTRY;
	Py_DECREF(me->prompt_data[1]);
	me->prompt_data[1] = value;
	Py_INCREF(me->prompt_data[1]);
	DEBUG_EXIT;
	return 0;
}

/* Look up a user by name. */
static PyObject *
libuser_admin_lookup_user_name(PyObject *self, PyObject *args,
			       PyObject *kwargs)
{
	char *arg;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	char *keywords[] = { "name", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* We expect a single string (no mapping shenanigans here). */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", keywords, &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Create the entity to return, and look it up. */
	ent = lu_ent_new();
	if (lu_user_lookup_name(me->ctx, arg, ent, &error)) {
		/* Wrap it up, and return it. */
		DEBUG_EXIT;
		return libuser_wrap_ent(ent);
	} else {
		/* No such user.  Clean up and bug out. */
		if (error)
			lu_error_free(&error);
		lu_ent_free(ent);
		DEBUG_EXIT;
		Py_RETURN_NONE;
	}
}

/* Look up a user give the UID. */
static PyObject *
libuser_admin_lookup_user_id(PyObject *self, PyObject *args,
			     PyObject *kwargs)
{
	PY_LONG_LONG arg;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	char *keywords[] = { "id", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* We expect a single string (no mapping shenanigans here). */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "L", keywords, &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
	if ((uid_t)arg != arg) {
		PyErr_SetString(PyExc_OverflowError, "UID out of range");
		DEBUG_EXIT;
		return NULL;
	}
	ent = lu_ent_new();
	if (lu_user_lookup_id(me->ctx, arg, ent, &error)) {
		/* Wrap it up, and return it. */
		DEBUG_EXIT;
		return libuser_wrap_ent(ent);
	} else {
		/* No such user.  Clean up and bug out. */
		if (error != NULL)
			lu_error_free(&error);
		lu_ent_free(ent);
		DEBUG_EXIT;
		Py_RETURN_NONE;
	}
}

/* Look up a group by name. */
static PyObject *
libuser_admin_lookup_group_name(PyObject *self, PyObject *args,
				PyObject *kwargs)
{
	char *arg;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	char *keywords[] = { "name", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* Expect a string. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", keywords, &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Try to look up this user. */
	ent = lu_ent_new();
	if (lu_group_lookup_name(me->ctx, arg, ent, &error)) {
		/* Got you!  Wrap and return. */
		DEBUG_EXIT;
		return libuser_wrap_ent(ent);
	} else {
		/* We've got nothing.  Return nothing. */
		if (error != NULL)
			lu_error_free(&error);
		lu_ent_free(ent);
		DEBUG_EXIT;
		Py_RETURN_NONE;
	}
}

/* Look up a group by ID. */
static PyObject *
libuser_admin_lookup_group_id(PyObject *self, PyObject *args,
			      PyObject *kwargs)
{
	PY_LONG_LONG arg;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	char *keywords[] = { "id", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* Expect a number. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "L", keywords, &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
	if ((gid_t)arg != arg) {
		PyErr_SetString(PyExc_OverflowError, "GID out of range");
		DEBUG_EXIT;
		return NULL;
	}
	/* Try to look up the group. */
	ent = lu_ent_new();
	if (lu_group_lookup_id(me->ctx, arg, ent, &error)) {
		/* Wrap the answer up. */
		DEBUG_EXIT;
		return libuser_wrap_ent(ent);
	} else {
		/* Clean up and exit, we have nothing to return. */
		if (error != NULL)
			lu_error_free(&error);
		lu_ent_free(ent);
		DEBUG_EXIT;
		Py_RETURN_NONE;
	}
}

/* Create a template user object. */
static PyObject *
libuser_admin_init_user(PyObject *self, PyObject *args,
			PyObject *kwargs)
{
	char *arg;
	int is_system = 0;
	struct lu_ent *ent;
	char *keywords[] = { "name", "is_system", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* We expect a string and an optional flag indicating that the
	 * user will be a system user. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|i", keywords,
					 &arg, &is_system)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Create a new user object for the user name, and return it. */
	ent = lu_ent_new();
	lu_user_default(me->ctx, arg, is_system, ent);
	DEBUG_EXIT;
	return libuser_wrap_ent(ent);
}

/* Create a group object. */
static PyObject *
libuser_admin_init_group(PyObject *self, PyObject *args,
			 PyObject *kwargs)
{
	char *arg;
	int is_system = 0;
	struct lu_ent *ent;
	char *keywords[] = { "name", "is_system", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* Expect a string and a flag indicating that the group is to be a
	 * system group. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|i", keywords,
					 &arg, &is_system)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Create a defaulted group by this name, and wrap it up. */
	ent = lu_ent_new();
	lu_group_default(me->ctx, arg, is_system, ent);
	DEBUG_EXIT;
	return libuser_wrap_ent(ent);
}

/* Run the given function. If the function fails, raise an error. */
static PyObject *
libuser_admin_do_wrap(PyObject *self, struct libuser_entity *ent,
		      gboolean (*fn) (struct lu_context *, struct lu_ent *,
				      struct lu_error ** error))
{
	struct lu_error *error = NULL;
	struct libuser_admin *me = (struct libuser_admin *)self;

	DEBUG_ENTRY;
	/* Try running the function. */
	if (fn(me->ctx, ent->ent, &error)) {
		/* It succeeded!  Return truth. */
		DEBUG_EXIT;
		return PYINTTYPE_FROMLONG(1);
	} else {
		/* It failed.  Build an exception and return an error. */
		PyErr_SetString(PyExc_RuntimeError, lu_strerror(error));
		if (error)
			lu_error_free(&error);
		DEBUG_EXIT;
		return NULL;
	}
}

/* Run the given function, using a Python entity passed in as the first
 * argument to the function.  If the function fails, raise an error. */
static PyObject *
libuser_admin_wrap(PyObject *self, PyObject *args, PyObject *kwargs,
		   gboolean(*fn) (struct lu_context *, struct lu_ent *,
				  struct lu_error ** error))
{
	PyObject *ent;
	char *keywords[] = { "entity", NULL };
	PyObject *ret;

	DEBUG_ENTRY;
	/* Expect a Python Entity object and maybe some other stuff we
	 * don't really care about. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!", keywords,
					 &EntityType, &ent)) {
		DEBUG_EXIT;
		return NULL;
	}
	ret = libuser_admin_do_wrap(self, (struct libuser_entity *)ent, fn);
	DEBUG_EXIT;
	return ret;
}

/* Run the given function, using a Python entity passed in as the first
 * argument to the function.  Return a 1 or 0 depending on the boolean
 * returned by the function. */
static PyObject *
libuser_admin_wrap_boolean(PyObject *self, PyObject *args, PyObject *kwargs,
			   gboolean(*fn) (struct lu_context *, struct lu_ent *,
				  	  struct lu_error ** error))
{
	struct libuser_entity *ent;
	struct lu_error *error = NULL;
	char *keywords[] = { "entity", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;
	gboolean ret;

	DEBUG_ENTRY;
	/* Expect a Python Entity object and maybe some other stuff we
	 * don't really care about. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!", keywords,
					 &EntityType, &ent)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Run the function. */
	ret = fn(me->ctx, ent->ent, &error);
	if (error != NULL)
		lu_error_free(&error);
	DEBUG_EXIT;
	return PYINTTYPE_FROMLONG(ret ? 1 : 0);
}

/* Wrap the setpass function for either type of entity. */
static PyObject *
libuser_admin_setpass(PyObject *self, PyObject *args, PyObject *kwargs,
		      gboolean(*fn) (struct lu_context *, struct lu_ent *,
				     const char *, gboolean,
				     struct lu_error **))
{
	struct libuser_entity *ent;
	struct lu_error *error = NULL;
	PyObject *is_crypted = NULL;
	const char *password = NULL;
	char *keywords[] = { "entity", "password", "is_crypted", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* We expect an entity object and a string. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!sO", keywords,
					 &EntityType, &ent, &password,
					 &is_crypted)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Call the appropriate setpass function for this entity. */
	if (fn(me->ctx, ent->ent, password,
	       ((is_crypted != NULL) && (PyObject_IsTrue(is_crypted))),
	       &error)) {
		/* The change succeeded.  Return a truth. */
		DEBUG_EXIT;
		return PYINTTYPE_FROMLONG(1);
	} else {
		/* The change failed.  Return an error. */
		PyErr_SetString(PyExc_SystemError, lu_strerror(error));
		if (error) {
			lu_error_free(&error);
		}
		DEBUG_EXIT;
		return NULL;
	}
}

/* Create a home directory for a user. */
static PyObject *
libuser_admin_create_home(PyObject *self, PyObject *args,
			  PyObject *kwargs)
{
	struct libuser_entity *ent = NULL;
	struct lu_context *context;
	const char *dir, *skeleton = NULL;
	char *keywords[] = { "home", "skeleton", NULL };
	uid_t uidNumber = 0;
	gid_t gidNumber = 0;
	struct lu_error *error = NULL;

	(void)self;
	DEBUG_ENTRY;

	context = ((struct libuser_admin *)self)->ctx;

	/* Expect an object and a string. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!|s", keywords,
					 &EntityType, &ent, &skeleton)) {
		DEBUG_EXIT;
		return NULL;
	}

	/* Get the user's home directory value. */
	dir = lu_ent_get_first_string(ent->ent, LU_HOMEDIRECTORY);
	if (dir == NULL) {
		PyErr_SetString(PyExc_KeyError,
				"user does not have a `" LU_HOMEDIRECTORY
				"' attribute");
		return NULL;
	}

	/* Get the user's UID. */
	uidNumber = lu_ent_get_first_id(ent->ent, LU_UIDNUMBER);
	if (uidNumber == LU_VALUE_INVALID_ID) {
		PyErr_SetString(PyExc_KeyError,
				"user does not have a `" LU_UIDNUMBER
				"' attribute");
		return NULL;
	}

	/* Get the user's GID. */
	gidNumber = lu_ent_get_first_id(ent->ent, LU_GIDNUMBER);
	if (gidNumber == LU_VALUE_INVALID_ID) {
		PyErr_SetString(PyExc_KeyError,
				"user does not have a `" LU_GIDNUMBER
				"' attribute");
		return NULL;
	}

	/* Attempt to populate the directory. */
	if (lu_homedir_populate(context, skeleton, dir, uidNumber, gidNumber,
				0700, &error)) {
		DEBUG_EXIT;
		return PYINTTYPE_FROMLONG(1);
	} else {
		/* Failure.  Mark the error. */
		PyErr_SetString(PyExc_RuntimeError,
				error ?
				error->string :
				_("error creating home directory for user"));
		if (error) {
			lu_error_free(&error);
		}
		DEBUG_EXIT;
		return NULL;
	}
}

/* Remove a user's home directory. */
static PyObject *
libuser_admin_remove_home(PyObject *self, PyObject *args,
			  PyObject *kwargs)
{
	struct libuser_entity *ent = NULL;
	char *keywords[] = { "home", NULL };
	struct lu_error *error = NULL;

	(void)self;
	DEBUG_ENTRY;

	/* We expect an object. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!", keywords,
					 &EntityType, &ent)) {
		DEBUG_EXIT;
		return NULL;
	}

	/* Remove the directory. */
	if (lu_homedir_remove_for_user(ent->ent, &error)) {
		/* Successfully removed. */
		DEBUG_EXIT;
		return PYINTTYPE_FROMLONG(1);
	} else {
		/* Removal failed.  You'll have to come back for repeated
		 * treatments. */
		PyErr_SetString(PyExc_RuntimeError,
				error ?
				error->string :
				_("error removing home directory for user"));
		if (error) {
			lu_error_free(&error);
		}
		DEBUG_EXIT;
		return NULL;
	}
}

/* Remove a user's home directory if it is owned by them. */
static PyObject *
libuser_admin_remove_home_if_owned(PyObject *self, PyObject *args,
				   PyObject *kwargs)
{
	struct libuser_entity *ent = NULL;
	char *keywords[] = { "user", NULL };
	struct lu_error *error = NULL;

	(void)self;
	DEBUG_ENTRY;

	/* We expect an object. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!", keywords,
					 &EntityType, &ent)) {
		DEBUG_EXIT;
		return NULL;
	}

	/* Remove the directory. */
	if (lu_homedir_remove_for_user_if_owned(ent->ent, &error)) {
		/* Successfully removed. */
		DEBUG_EXIT;
		return PYINTTYPE_FROMLONG(1);
	} else {
		/* Removal failed.  You'll have to come back for repeated
		 * treatments. */
		PyErr_SetString(PyExc_RuntimeError,
				error ?
				error->string :
				_("error removing home directory for user"));
		if (error) {
			lu_error_free(&error);
		}
		DEBUG_EXIT;
		return NULL;
	}
}

/* Move a user's home directory somewhere else. */
static PyObject *
libuser_admin_move_home(PyObject *self, PyObject *args,
			PyObject *kwargs)
{
	struct libuser_entity *ent = NULL;
	const char *olddir = NULL, *newdir = NULL;
	char *keywords[] = { "entity", "newhome", NULL };
	struct lu_error *error = NULL;

	(void)self;
	DEBUG_ENTRY;

	/* We expect an object and an optional string. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!|s", keywords,
					 &EntityType, &ent, &newdir)) {
		DEBUG_EXIT;
		return NULL;
	}

	if (newdir != NULL) {
		/* We were given a string, so move the user's home directory
		 * to the new location. */
		olddir = lu_ent_get_first_string(ent->ent, LU_HOMEDIRECTORY);
		if (olddir == NULL) {
			PyErr_SetString(PyExc_KeyError,
					"user does not have a current `"
					LU_HOMEDIRECTORY "' attribute");
			return NULL;
		}
	} else {
		/* We weren't given a string, so use the current and pending
		 * values, and move from one to the other. */
		olddir = lu_ent_get_first_string_current(ent->ent,
							 LU_HOMEDIRECTORY);
		if (olddir == NULL) {
			PyErr_SetString(PyExc_KeyError,
					"user does not have a current `"
					LU_HOMEDIRECTORY "' attribute");
			return NULL;
		}

		/* Now read the pending directory. */
		newdir = lu_ent_get_first_string(ent->ent, LU_HOMEDIRECTORY);
		if (newdir == NULL) {
			PyErr_SetString(PyExc_KeyError,
					"user does not have a pending `"
					LU_HOMEDIRECTORY "' attribute");
			return NULL;
		}
	}

	/* Attempt the move. */
	if (lu_homedir_move(olddir, newdir, &error)) {
		/* Success! */
		DEBUG_EXIT;
		return PYINTTYPE_FROMLONG(1);
	} else {
		/* Failure.  Set an error. */
		PyErr_SetString(PyExc_RuntimeError,
				error ?
				error->string :
				_("error moving home directory for user"));
		if (error) {
			lu_error_free(&error);
		}
		DEBUG_EXIT;
		return NULL;
	}
}

/* Create a user's mail spool. */
static PyObject *
libuser_admin_create_remove_mail(PyObject *self, PyObject *args,
				 PyObject *kwargs, gboolean action)
{
	struct libuser_entity *ent = NULL;

	char *keywords[] = { "entity", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;
	struct lu_error *error;
	gboolean res;

	DEBUG_ENTRY;

	/* We expect an Entity object. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!", keywords,
					 &EntityType, &ent)) {
		DEBUG_EXIT;
		return NULL;
	}

	/* Now just pass it to the internal function. */
	error = NULL;
	if (action)
		res = lu_mail_spool_create(me->ctx, ent->ent, &error);
	else
		res = lu_mail_spool_remove(me->ctx, ent->ent, &error);
	if (res) {
		return PYINTTYPE_FROMLONG(1);
	} else {
		PyErr_SetString(PyExc_RuntimeError, lu_strerror(error));
		if (error != NULL)
			lu_error_free(&error);
		return NULL;
	}
}

/* Create a user's mail spool. */
static PyObject *
libuser_admin_create_mail(PyObject *self, PyObject *args, PyObject *kwargs)
{
	return libuser_admin_create_remove_mail(self, args, kwargs, TRUE);
}

/* Destroy a user's mail spool. */
static PyObject *
libuser_admin_remove_mail(PyObject *self, PyObject *args, PyObject *kwargs)
{
	return libuser_admin_create_remove_mail(self, args, kwargs, FALSE);
}

/* Add a user. */
static PyObject *
libuser_admin_add_user(PyObject *self, PyObject *args, PyObject *kwargs)
{
	PyObject *ret = NULL;
	PyObject *mkhomedir = self;
	PyObject *mkmailspool = self;
	PyObject *skeleton = NULL;
	struct libuser_entity *ent = NULL;
	struct lu_context *context = NULL;
	char *keywords[] = {
		"entity", "mkhomedir", "mkmailspool", "skeleton", NULL
	};

	DEBUG_ENTRY;

	context = ((struct libuser_admin *)self)->ctx;

	/* Expect an entity and a flag to tell us if we need to create the
	 * user's home directory. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!|OOO", keywords,
					 &EntityType, &ent,
					 &mkhomedir, &mkmailspool,
					 &skeleton)) {
		DEBUG_EXIT;
		return NULL;
	}

	/* Pass the entity object to lu_user_add(). */
	ret = libuser_admin_do_wrap(self, ent, lu_user_add);
	if (ret != NULL && mkhomedir != NULL && PyObject_IsTrue(mkhomedir)) {
		PyObject *subargs, *subkwargs;

		Py_DECREF(ret);
		/* Create the user's home directory we need to pass the entity
		   structure in a tuple, so create a tuple * and add just that
		   object to it. */
		subargs = PyTuple_New(1);
		Py_INCREF(ent);
		PyTuple_SetItem(subargs, 0, (PyObject*) ent);
		/* Create a dictionary for keyword args. */
		subkwargs = PyDict_New();
		if (skeleton != NULL) {
			Py_INCREF(skeleton);
			PyDict_SetItemString(subkwargs, "skeleton", skeleton);
		}
		/* We'll return the result of the creation call. */
		ret = libuser_admin_create_home(self, subargs, subkwargs);
		Py_DECREF(subargs);
		Py_DECREF(subkwargs);
	}
	if (ret != NULL && mkmailspool != NULL
	    && PyObject_IsTrue(mkmailspool)) {
		struct lu_error *error;

		Py_DECREF(ret);
		error = NULL;
		if (lu_mail_spool_create(context, ent->ent, &error))
			ret = PYINTTYPE_FROMLONG(1);
		else {
			PyErr_SetString(PyExc_RuntimeError, lu_strerror(error));
			if (error != NULL)
				lu_error_free(&error);
			ret = NULL;
		}
	}

	DEBUG_EXIT;

	return ret;
}

/* Add a group.  Simple wrapper. */
static PyObject *
libuser_admin_add_group(PyObject *self, PyObject *args,
			PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_wrap(self, args, kwargs, lu_group_add);
}

static PyObject *
libuser_admin_modify_user(PyObject *self, PyObject *args,
			  PyObject *kwargs)
{
	PyObject *ent = NULL;
	PyObject *ret;
	PyObject *mvhomedir = NULL;
	struct lu_ent *copy = NULL;
	char *keywords[] = { "entity", "mvhomedir", NULL };

	DEBUG_ENTRY;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!|O", keywords,
					 &EntityType, &ent, &mvhomedir))
		return NULL;

	if (mvhomedir != NULL) {
		if (!PyObject_IsTrue(mvhomedir))
			/* Cache the PyObject_IsTrue() result */
			mvhomedir = NULL;
		else {
			copy = lu_ent_new();
			lu_ent_copy(((struct libuser_entity *)ent)->ent, copy);
		}
	}
	ret = libuser_admin_do_wrap(self, (struct libuser_entity *)ent,
				    lu_user_modify);
	if (ret != NULL && mvhomedir != NULL) {
		PyObject *subargs, *subkwargs, *wrapped;

		Py_DECREF(ret);
		subargs = PyTuple_New(1);
		wrapped = libuser_wrap_ent(copy);
		copy = NULL; /* Will be freed along with `wrapped' */
		PyTuple_SetItem(subargs, 0, wrapped);
		subkwargs = PyDict_New();
		ret = libuser_admin_move_home(self, subargs, subkwargs);
		Py_DECREF(subargs);
		Py_DECREF(subkwargs);
	}
	if (copy != NULL)
		lu_ent_free(copy);

	DEBUG_EXIT;

	return ret;
}

/* Modify a group.  Trivial wrapper. */
static PyObject *
libuser_admin_modify_group(PyObject *self, PyObject *args,
			   PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_wrap(self, args, kwargs, lu_group_modify);
}

static PyObject *
libuser_admin_delete_user(PyObject *self, PyObject *args,
			  PyObject *kwargs)
{
	PyObject *ent = NULL;
	PyObject *ret;
	PyObject *rmhomedir = NULL, *rmmailspool = NULL;
	struct lu_context *context;
	char *keywords[] = { "entity", "rmhomedir", "rmmailspool", NULL };

	DEBUG_ENTRY;

	context = ((struct libuser_admin *)self)->ctx;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!|OO", keywords,
					 &EntityType, &ent,
					 &rmhomedir, &rmmailspool)) {
		return NULL;
	}

	ret = libuser_admin_do_wrap(self, (struct libuser_entity *)ent,
				    lu_user_delete);
	if (ret != NULL && rmhomedir != NULL && PyObject_IsTrue(rmhomedir)) {
		PyObject *subargs, *subkwargs;

		Py_DECREF(ret);
		subargs = PyTuple_New(1);
		Py_INCREF(ent);
		PyTuple_SetItem(subargs, 0, ent);
		subkwargs = PyDict_New();
		ret = libuser_admin_remove_home(self, subargs, subkwargs);
		Py_DECREF(subargs);
		Py_DECREF(subkwargs);
	}
	if (ret != NULL && rmmailspool != NULL
	    && PyObject_IsTrue(rmmailspool)) {
		struct libuser_entity *entity;
		struct lu_error *error;

		Py_DECREF(ret);
		entity = (struct libuser_entity *)ent;
		error = NULL;
		if (lu_mail_spool_remove(context, entity->ent, &error))
			ret = PYINTTYPE_FROMLONG(1);
		else {
			PyErr_SetString(PyExc_RuntimeError, lu_strerror(error));
			if (error != NULL)
				lu_error_free(&error);
			ret = NULL;
		}
	}

	DEBUG_EXIT;

	return ret;
}

/* Delete a group.  Trivial wrapper. */
static PyObject *
libuser_admin_delete_group(PyObject *self, PyObject *args,
			   PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_wrap(self, args, kwargs, lu_group_delete);
}

/* Lock a user account.  Trivial wrapper. */
static PyObject *
libuser_admin_lock_user(PyObject *self, PyObject *args,
			PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_wrap(self, args, kwargs, lu_user_lock);
}

/* Lock a group account.  Trivial wrapper. */
static PyObject *
libuser_admin_lock_group(PyObject *self, PyObject *args, PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_wrap(self, args, kwargs, lu_group_lock);
}

/* Unlock a user account. */
static PyObject *
libuser_admin_unlock_user(PyObject *self, PyObject *args,
			  PyObject *kwargs)
{
	PyObject *ent, *nonempty = NULL;
	char *keywords[] = { "entity", "nonempty", NULL };
	gboolean (*fn) (struct lu_context *, struct lu_ent *,
			struct lu_error **);
	PyObject *ret;

	DEBUG_ENTRY;
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!|O", keywords,
					 &EntityType, &ent, &nonempty)) {
		DEBUG_EXIT;
		return NULL;
	}
	fn = (nonempty != NULL && PyObject_IsTrue (nonempty)
	      ? lu_user_unlock_nonempty : lu_user_unlock);
	ret = libuser_admin_do_wrap(self, (struct libuser_entity *)ent, fn);
	DEBUG_EXIT;
	return ret;
}

/* Unlock a group account. */
static PyObject *
libuser_admin_unlock_group(PyObject *self, PyObject *args,
			   PyObject *kwargs)
{
	PyObject *ent, *nonempty = NULL;
	char *keywords[] = { "entity", "nonempty", NULL };
	gboolean (*fn) (struct lu_context *, struct lu_ent *,
			struct lu_error **);
	PyObject *ret;

	DEBUG_ENTRY;
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!|O", keywords,
					 &EntityType, &ent, &nonempty)) {
		DEBUG_EXIT;
		return NULL;
	}
	fn = (nonempty != NULL && PyObject_IsTrue (nonempty)
	      ? lu_group_unlock_nonempty : lu_group_unlock);
	ret = libuser_admin_do_wrap(self, (struct libuser_entity *)ent, fn);
	DEBUG_EXIT;
	return ret;
}

/* Check if a user account is locked.  Trivial wrapper. */
static PyObject *
libuser_admin_user_islocked(PyObject *self, PyObject *args,
			    PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_wrap_boolean(self, args, kwargs, lu_user_islocked);
}

/* Check if a group account is locked.  Trivial wrapper. */
static PyObject *
libuser_admin_group_islocked(PyObject *self, PyObject *args,
			     PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_wrap_boolean(self, args, kwargs,
					  lu_group_islocked);
}

/* Remove a user's password.  Trivial wrapper to make sure the right function
 * gets called. */
static PyObject *
libuser_admin_removepass_user(PyObject *self, PyObject *args, PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_wrap(self, args, kwargs, lu_user_removepass);
}

/* Remove a group's password.  Trivial wrapper to make sure the right function
 * gets called. */
static PyObject *
libuser_admin_removepass_group(PyObject *self, PyObject *args, PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_wrap(self, args, kwargs, lu_group_removepass);
}

/* Set a user's password.  Trivial wrapper to make sure the right setpass
 * function gets called. */
static PyObject *
libuser_admin_setpass_user(PyObject *self, PyObject *args,
			   PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_setpass(self, args, kwargs, lu_user_setpass);
}

/* Set a group's password.  Trivial wrapper to make sure the right setpass
 * function gets called. */
static PyObject *
libuser_admin_setpass_group(PyObject *self, PyObject *args,
			    PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_setpass(self, args, kwargs, lu_group_setpass);
}

/* Get a list of all users who match a particular pattern. */
static PyObject *
libuser_admin_enumerate_users(PyObject *self, PyObject *args,
			      PyObject *kwargs)
{
	GValueArray *results;
	const char *pattern = NULL;
	PyObject *ret;
	struct lu_error *error = NULL;
	char *keywords[] = { "pattern", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* Expect a possible pattern. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|s", keywords,
					 &pattern)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Read the list of all users. */
	results = lu_users_enumerate(me->ctx, pattern, &error);
	if (error != NULL)
		lu_error_free(&error);
	/* Convert the list to a PyList. */
	ret = convert_value_array_pylist(results);
	if (results != NULL)
		g_value_array_free(results);
	DEBUG_EXIT;
	return ret;
}

/* Get a list of all groups. */
static PyObject *
libuser_admin_enumerate_groups(PyObject *self, PyObject *args,
			       PyObject *kwargs)
{
	GValueArray *results;
	const char *pattern = NULL;
	PyObject *ret;
	struct lu_error *error = NULL;
	char *keywords[] = { "pattern", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* Possibly expect a pattern. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|s", keywords,
					 &pattern)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Get the list of groups. */
	results = lu_groups_enumerate(me->ctx, pattern, &error);
	if (error != NULL)
		lu_error_free(&error);
	/* Convert the list to a PyList. */
	ret = convert_value_array_pylist(results);
	if (results != NULL)
		g_value_array_free(results);
	DEBUG_EXIT;
	return ret;
}

/* Get the list of users who belong to a group. */
static PyObject *
libuser_admin_enumerate_users_by_group(PyObject *self, PyObject *args,
				       PyObject *kwargs)
{
	GValueArray *results;
	char *group = NULL;
	PyObject *ret;
	struct lu_error *error = NULL;
	char *keywords[] = { "group", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* Expect the group's name. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", keywords, &group)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Get a list of the users in this group. */
	results = lu_users_enumerate_by_group(me->ctx, group, &error);
	if (error != NULL)
		lu_error_free(&error);
	ret = convert_value_array_pylist(results);
	if (results != NULL)
		g_value_array_free(results);
	DEBUG_EXIT;
	return ret;
}

/* Get a list of groups a user belongs to. */
static PyObject *
libuser_admin_enumerate_groups_by_user(PyObject *self, PyObject *args,
				       PyObject *kwargs)
{
	GValueArray *results;
	char *user = NULL;
	PyObject *ret;
	struct lu_error *error = NULL;
	char *keywords[] = { "user", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* Expect the user's name. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", keywords, &user)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Get the list. */
	results = lu_groups_enumerate_by_user(me->ctx, user, &error);
	if (error != NULL)
		lu_error_free(&error);
	ret = convert_value_array_pylist(results);
	if (results != NULL)
		g_value_array_free(results);
	DEBUG_EXIT;
	return ret;
}

/* Get a list of all users who match a particular pattern. */
static PyObject *
libuser_admin_enumerate_users_full(PyObject *self, PyObject *args,
				   PyObject *kwargs)
{
	GPtrArray *results;
	const char *pattern = NULL;
	PyObject *ret;
	struct lu_error *error = NULL;
	char *keywords[] = { "pattern", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* Expect a possible pattern. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|s", keywords,
					 &pattern)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Read the list of all users. */
	results = lu_users_enumerate_full(me->ctx, pattern, &error);
	if (error != NULL)
		lu_error_free(&error);
	/* Convert the list to a PyList. */
	ret = convert_ent_array_pylist(results);
	if (results != NULL)
		g_ptr_array_free(results, TRUE);
	DEBUG_EXIT;
	return ret;
}

/* Get a list of all groups. */
static PyObject *
libuser_admin_enumerate_groups_full(PyObject *self, PyObject *args,
				    PyObject *kwargs)
{
	GPtrArray *results;
	const char *pattern = NULL;
	PyObject *ret;
	struct lu_error *error = NULL;
	char *keywords[] = { "pattern", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* Possibly expect a pattern. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|s", keywords,
					 &pattern)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Get the list of groups. */
	results = lu_groups_enumerate_full(me->ctx, pattern, &error);
	if (error != NULL)
		lu_error_free(&error);
	/* Convert the list to a PyList. */
	ret = convert_ent_array_pylist(results);
	if (results != NULL)
		g_ptr_array_free(results, TRUE);
	DEBUG_EXIT;
	return ret;
}

/* Get the list of users who belong to a group. */
static PyObject *
libuser_admin_enumerate_users_by_group_full(PyObject *self, PyObject *args,
					    PyObject *kwargs)
{
	GPtrArray *results;
	char *group = NULL;
	PyObject *ret;
	struct lu_error *error = NULL;
	char *keywords[] = { "group", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* Expect the group's name. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", keywords, &group)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Get a list of the users in this group. */
	results = lu_users_enumerate_by_group_full(me->ctx, group, &error);
	if (error != NULL)
		lu_error_free(&error);
	ret = convert_ent_array_pylist(results);
	if (results != NULL)
		g_ptr_array_free(results, TRUE);
	DEBUG_EXIT;
	return ret;
}

/* Get a list of groups a user belongs to. */
static PyObject *
libuser_admin_enumerate_groups_by_user_full(PyObject *self, PyObject *args,
					    PyObject *kwargs)
{
	GPtrArray *results;
	char *user = NULL;
	PyObject *ret;
	struct lu_error *error = NULL;
	char *keywords[] = { "user", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* Expect the user's name. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", keywords, &user)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Get the list. */
	results = lu_groups_enumerate_by_user_full(me->ctx, user, &error);
	if (error != NULL)
		lu_error_free(&error);
	ret = convert_ent_array_pylist(results);
	if (results != NULL)
		g_ptr_array_free(results, TRUE);
	DEBUG_EXIT;
	return ret;
}

static PyObject *
libuser_admin_get_first_unused_id_type(struct libuser_admin *me,
				       PyObject * args, PyObject * kwargs,
				       enum lu_entity_type enttype)
{
	const char *key, *key_string, *val;
	char *keywords[] = { "start", NULL };
	PY_LONG_LONG start = 500;

	g_return_val_if_fail(me != NULL, NULL);

	DEBUG_ENTRY;

	switch (enttype) {
	case lu_user:
		key = "userdefaults/" LU_UIDNUMBER;
		key_string = "userdefaults/" G_STRINGIFY_ARG(LU_UIDNUMBER);
		break;
	case lu_group:
		key = "groupdefaults/" LU_GIDNUMBER;
		key_string = "groupdefaults/" G_STRINGIFY_ARG(LU_GIDNUMBER);
		break;
	default:
		g_assert_not_reached();
	}
	val = lu_cfg_read_single(me->ctx, key, NULL);
	if (val == NULL)
		val = lu_cfg_read_single(me->ctx, key_string, NULL);
	if (val != NULL) {
		intmax_t imax;
		char *end;

		errno = 0;
		imax = strtoimax(val, &end, 10);
		if (errno == 0 && *end == 0 && end != val && (id_t)imax == imax)
			start = imax;
	}

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|L", keywords,
					 &start)) {
		DEBUG_EXIT;
		return NULL;
	}
	if ((id_t)start != start) {
		PyErr_SetString(PyExc_OverflowError, "ID out of range");
		DEBUG_EXIT;
		return NULL;
	}

	return PyLong_FromLongLong(lu_get_first_unused_id(me->ctx, enttype,
							  start));
}

static PyObject *
libuser_admin_get_first_unused_uid(PyObject *self, PyObject * args,
				   PyObject *kwargs)
{
	return libuser_admin_get_first_unused_id_type
		((struct libuser_admin *)self, args, kwargs, lu_user);
}

static PyObject *
libuser_admin_get_first_unused_gid(PyObject *self, PyObject * args,
				   PyObject *kwargs)
{
	return libuser_admin_get_first_unused_id_type
		((struct libuser_admin *)self, args, kwargs, lu_group);
}

static struct PyMethodDef libuser_admin_methods[] = {
	{"lookupUserByName", (PyCFunction) libuser_admin_lookup_user_name,
	 METH_VARARGS | METH_KEYWORDS,
	 "search for a user with the given name"},
	{"lookupUserById", (PyCFunction) libuser_admin_lookup_user_id,
	 METH_VARARGS | METH_KEYWORDS,
	 "search for a user with the given uid"},
	{"lookupGroupByName",
	 (PyCFunction) libuser_admin_lookup_group_name,
	 METH_VARARGS | METH_KEYWORDS,
	 "search for a group with the given name"},
	{"lookupGroupById", (PyCFunction) libuser_admin_lookup_group_id,
	 METH_VARARGS | METH_KEYWORDS,
	 "search for a group with the given gid"},

	{"initUser", (PyCFunction) libuser_admin_init_user,
	 METH_VARARGS | METH_KEYWORDS,
	 "create an object with defaults set for creating a new user"},
	{"initGroup", (PyCFunction) libuser_admin_init_group,
	 METH_VARARGS | METH_KEYWORDS,
	 "create an object with defaults set for creating a new group"},

	{"addUser", (PyCFunction) libuser_admin_add_user,
	 METH_VARARGS | METH_KEYWORDS,
	 "add the user object to the system user database"},
	{"addGroup", (PyCFunction) libuser_admin_add_group,
	 METH_VARARGS | METH_KEYWORDS,
	 "add the group object to the system group database"},

	{"modifyUser", (PyCFunction) libuser_admin_modify_user,
	 METH_VARARGS | METH_KEYWORDS,
	 "modify an entry in the system user database to match the object"},
	{"modifyGroup", (PyCFunction) libuser_admin_modify_group,
	 METH_VARARGS | METH_KEYWORDS,
	 "modify an entry in the system group database to match the object"},

	{"deleteUser", (PyCFunction) libuser_admin_delete_user,
	 METH_VARARGS | METH_KEYWORDS,
	 "remove the entry from the system user database which matches the object"},
	{"deleteGroup", (PyCFunction) libuser_admin_delete_group,
	 METH_VARARGS | METH_KEYWORDS,
	 "remove the entry from the system group database which matches the object"},

	{"lockUser", (PyCFunction) libuser_admin_lock_user,
	 METH_VARARGS | METH_KEYWORDS,
	 "lock the user account associated with the object"},
	{"lockGroup", (PyCFunction) libuser_admin_lock_group,
	 METH_VARARGS | METH_KEYWORDS,
	 "lock the group account associated with the object"},
	{"unlockUser", (PyCFunction) libuser_admin_unlock_user,
	 METH_VARARGS | METH_KEYWORDS,
	 "unlock the user account associated with the object"},
	{"unlockGroup", (PyCFunction) libuser_admin_unlock_group,
	 METH_VARARGS | METH_KEYWORDS,
	 "unlock the group account associated with the object"},
	{"userIsLocked", (PyCFunction) libuser_admin_user_islocked,
	 METH_VARARGS | METH_KEYWORDS,
	 "check if the user account associated with the object is locked"},
	{"groupIsLocked", (PyCFunction) libuser_admin_group_islocked,
	 METH_VARARGS | METH_KEYWORDS,
	 "check if the group account associated with the object is locked"},

	{"setpassUser", (PyCFunction) libuser_admin_setpass_user,
	 METH_VARARGS | METH_KEYWORDS,
	 "set the password for the user account associated with the object"},
	{"setpassGroup", (PyCFunction) libuser_admin_setpass_group,
	 METH_VARARGS | METH_KEYWORDS,
	 "set the password for the group account associated with the object"},

	{"removepassUser", (PyCFunction) libuser_admin_removepass_user,
	 METH_VARARGS | METH_KEYWORDS,
	 "remove the password for the user account associated with the object"},
	{"removepassGroup", (PyCFunction) libuser_admin_removepass_group,
	 METH_VARARGS | METH_KEYWORDS,
	 "remove the password for the group account associated with the object"},

	{"enumerateUsers", (PyCFunction) libuser_admin_enumerate_users,
	 METH_VARARGS | METH_KEYWORDS,
	 "get a list of users matching a pattern, in listed databases"},
	{"enumerateGroups", (PyCFunction) libuser_admin_enumerate_groups,
	 METH_VARARGS | METH_KEYWORDS,
	 "get a list of groups matching a pattern, in listed databases"},
	{"enumerateUsersByGroup",
	 (PyCFunction) libuser_admin_enumerate_users_by_group,
	 METH_VARARGS | METH_KEYWORDS,
	 "get a list of users in a group"},
	{"enumerateGroupsByUser",
	 (PyCFunction) libuser_admin_enumerate_groups_by_user,
	 METH_VARARGS | METH_KEYWORDS,
	 "get a list of groups to which a user belongs"},

	{"enumerateUsersFull", (PyCFunction) libuser_admin_enumerate_users_full,
	 METH_VARARGS | METH_KEYWORDS,
	 "get a list of users matching a pattern, in listed databases"},
	{"enumerateGroupsFull", (PyCFunction) libuser_admin_enumerate_groups_full,
	 METH_VARARGS | METH_KEYWORDS,
	 "get a list of groups matching a pattern, in listed databases"},
	{"enumerateUsersByGroupFull",
	 (PyCFunction) libuser_admin_enumerate_users_by_group_full,
	 METH_VARARGS | METH_KEYWORDS,
	 "get a list of users in a group"},
	{"enumerateGroupsByUserFull",
	 (PyCFunction) libuser_admin_enumerate_groups_by_user_full,
	 METH_VARARGS | METH_KEYWORDS,
	 "get a list of groups to which a user belongs"},

	{"promptConsole", (PyCFunction) libuser_admin_prompt_console,
	 METH_VARARGS | METH_KEYWORDS,
	 "prompt the user for information using the console, and confirming defaults"},
	{"promptConsoleQuiet",
	 (PyCFunction) libuser_admin_prompt_console_quiet,
	 METH_VARARGS | METH_KEYWORDS,
	 "prompt the user for information using the console, silently accepting defaults"},

	{"createHome", (PyCFunction) libuser_admin_create_home,
	 METH_VARARGS | METH_KEYWORDS,
	 "create a home directory for a user"},
	{"moveHome", (PyCFunction) libuser_admin_move_home,
	 METH_VARARGS | METH_KEYWORDS,
	 "move a user's home directory"},
	{"removeHome", (PyCFunction) libuser_admin_remove_home,
	 METH_VARARGS | METH_KEYWORDS,
	 "remove a user's home directory"},
	{"removeHomeIfOwned", (PyCFunction) libuser_admin_remove_home_if_owned,
	 METH_VARARGS | METH_KEYWORDS,
	 "remove a user's home directory if it is owned by them"},

	{"createMail", (PyCFunction) libuser_admin_create_mail,
	 METH_VARARGS | METH_KEYWORDS,
	 "create a mail spool for a user"},
	{"removeMail", (PyCFunction) libuser_admin_remove_mail,
	 METH_VARARGS | METH_KEYWORDS,
	 "remove a mail spool for a user"},

	{"getUserShells", libuser_get_user_shells, METH_NOARGS,
	 "return a list of valid shells"},


	{"getFirstUnusedUid",
	 (PyCFunction) libuser_admin_get_first_unused_uid,
	 METH_VARARGS | METH_KEYWORDS,
	 "return the first available uid"},

	{"getFirstUnusedGid",
	 (PyCFunction) libuser_admin_get_first_unused_gid,
	 METH_VARARGS | METH_KEYWORDS,
	 "return the first available gid"},

	{NULL, NULL, 0, NULL},
};

static struct PyGetSetDef libuser_admin_getseters[] = {
	{"prompt", libuser_admin_get_prompt, libuser_admin_set_prompt,
	 "a function to call for getting information from the user", NULL},
	{"prompt_args", libuser_admin_get_prompt_args,
	 libuser_admin_set_prompt_args,
	 "additional arguments which should be passed to prompt", NULL},
	{NULL, NULL, NULL, NULL, NULL}
};

PyTypeObject AdminType = {
	PyVarObject_HEAD_INIT(&PyType_Type, 0)
	"libuser.Admin",	/* tp_name */
	sizeof(struct libuser_admin), /* tp_basicsize */
	0,			/* tp_itemsize */
	libuser_admin_destroy,	/* tp_dealloc */
	NULL,			/* tp_print */
	NULL,			/* tp_getattr */
	NULL,			/* tp_setattr */
	NULL,			/* tp_compare */
	NULL,			/* tp_repr */
	NULL,			/* tp_as_number */
	NULL,			/* tp_as_sequence */
	NULL,			/* tp_as_mapping */
	NULL,			/* tp_hash */
	NULL,			/* tp_call */
	NULL,			/* tp_str */
	NULL,			/* tp_getattro */
	NULL,			/* tp_setattro */
	NULL,			/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,	/* tp_flags */
	"A libuser context",	/* tp_doc */
	NULL,			/* tp_traverse */
	NULL,			/* tp_clear */
	NULL,			/* tp_richcompare */
	0,			/* tp_weaklistoffset */
	NULL,			/* tp_iter */
	NULL,			/* tp_iternext */
	libuser_admin_methods,	/* tp_methods */
	NULL,			/* tp_members */
	libuser_admin_getseters,	/* tp_getseters */
};

PyObject *
libuser_admin_new(PyObject *self, PyObject *args, PyObject *kwargs)
{
	char *name = getlogin(), *modules = NULL, *create = NULL, *p, *q;
	PyObject *prompt = NULL, *prompt_data = NULL;
	char *keywords[] = {
		"name",
		"type",
		"modules",
		"create_modules",
		"prompt",
		"prompt_data",
		NULL,
	};
	int type = lu_user;
	struct lu_context *context;
	struct lu_error *error = NULL;
	struct libuser_admin *ret;

	DEBUG_ENTRY;

	ret = PyObject_NEW(struct libuser_admin, &AdminType);
	if (ret == NULL) {
		return NULL;
	}
	self = (PyObject *) ret;
	p = ((char *) ret) + sizeof(PyObject);
	q = ((char *) ret) + sizeof(struct libuser_admin);
	memset(p, '\0', q - p);

	ret->ctx = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|sissOO", keywords,
					 &name, &type, &modules, &create,
					 &prompt, &prompt_data)) {
		Py_DECREF(ret);
		return NULL;
	}

	if ((type != lu_user) && (type != lu_group)) {
		PyErr_SetString(PyExc_ValueError, "invalid type");
		Py_DECREF(ret);
		return NULL;
	}

	if (PyCallable_Check(prompt)) {
		ret->prompt_data[0] = prompt;
		Py_INCREF(ret->prompt_data[0]);
	} else {
		ret->prompt_data[0] = PyObject_GetAttrString(self,
							     "promptConsole");
	}

	if (prompt_data != NULL)
		ret->prompt_data[1] = prompt_data;
	else
		ret->prompt_data[1] = Py_None;
	Py_INCREF(ret->prompt_data[1]);

#ifdef DEBUG_BINDING
	fprintf(stderr,
		"%sprompt at <%p>, self = <%p>, modules = <%p>, create = <%p>\n",
		getindent(), prompt, ret, modules, create);
#endif
	context =
	    lu_start(name, type, modules, create, libuser_admin_python_prompter,
		     ret->prompt_data, &error);

	if (context == NULL) {
		PyErr_SetString(PyExc_SystemError,
				error ? error->
				string : "error initializing " PACKAGE);
		if (error) {
			lu_error_free(&error);
		}
		Py_DECREF(ret);
		return NULL;
	}

	ret->ctx = context;

	DEBUG_EXIT;
	return self;
}
