/* Copyright (C) 2001, 2002, 2004 Red Hat, Inc.
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
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>
#include <unistd.h>
#include <glib.h>
#include "../lib/user.h"
#include "../lib/user_private.h"
#include "common.h"

/* Convert a g_value_array into a Python list of values.
   On error, raise a Python exception and return NULL. */
PyObject *
convert_value_array_pylist(GValueArray *array)
{
	PyObject *ret;
	size_t i;

	DEBUG_ENTRY;

	/* Create a new list. */
	ret = PyList_New(0);
	/* Iterate over the array. */
	for (i = 0; (array != NULL) && (i < array->n_values); i++) {
		GValue *value;

		value = g_value_array_get_nth(array, i);
		/* If the item is a G_TYPE_LONG, add it as a PyLong. */
		if (G_VALUE_HOLDS_LONG(value)) {
			PyObject *val;
			long l;

			l = g_value_get_long(value);
			val = PyLong_FromLong(l);
			PyList_Append(ret, val);
			Py_DECREF(val);
#ifdef DEBUG_BINDING
			fprintf(stderr, "adding %ld to list\n", l);
#endif
		} else if (G_VALUE_HOLDS_INT64(value)) {
			PyObject *val;
			long long ll;

			ll = g_value_get_int64(value);
			val = PyLong_FromLongLong(ll);
			PyList_Append(ret, val);
			Py_DECREF(val);
#ifdef DEBUG_BINDING
			fprintf(stderr, "adding %lld to list\n", ll);
#endif
		}
		/* If the item is a G_TYPE_STRING, add it as a PyString. */
		if (G_VALUE_HOLDS_STRING(value)) {
			PyObject *val;
			const char *s;

			s = g_value_get_string(value);
			val = PYSTRTYPE_FROMSTRING(s);
			if (val == NULL)
				goto err;
			PyList_Append(ret, val);
			Py_DECREF(val);
#ifdef DEBUG_BINDING
			fprintf(stderr, "adding `%s' to list\n", s);
#endif
		}
	}

	DEBUG_EXIT;
	return ret;

err:
	Py_DECREF(ret);
	DEBUG_EXIT;
	return NULL;
}

/* Convert a (potentially NULL) GPtrArray of entities into a Python list of
   values. */
PyObject *
convert_ent_array_pylist(GPtrArray *array)
{
	PyObject *ret;
	size_t i;

	DEBUG_ENTRY;

	ret = PyList_New(0);
	for (i = 0; array != NULL && i < array->len; i++) {
		PyObject *ent;

		ent = libuser_wrap_ent(g_ptr_array_index(array, i));
		PyList_Append(ret, ent);
		Py_DECREF(ent);
	}

	DEBUG_EXIT;
	return ret;
}

/* Wrap up an entity object in a pretty Python wrapper. */
PyObject *
libuser_wrap_ent(struct lu_ent *ent)
{
	struct libuser_entity *ret;

	DEBUG_ENTRY;

	/* No fair messing with me. */
	if (ent == NULL) {
		DEBUG_EXIT;
		g_return_val_if_fail(ent != NULL, NULL);
	}

	/* Create a new Python object suitable for holding a struct lu_ent. */
	ret = PyObject_NEW(struct libuser_entity, &EntityType);
	if (ret == NULL) {
		lu_ent_free(ent);
		DEBUG_EXIT;
		return NULL;
	}

	/* Keep track of the entity. */
	ret->ent = ent;

	DEBUG_EXIT;
	return (PyObject *) ret;
}

/* Destroy an entity Python object. */
static void
libuser_entity_destroy(PyObject *self)
{
	struct libuser_entity *me;

	DEBUG_ENTRY;
	me = (struct libuser_entity *)self;
	lu_ent_free(me->ent);
	me->ent = NULL;
	PyObject_DEL(me);
	DEBUG_EXIT;
}

/* A helper function to convert a PyObject to a GValue. */
static gboolean
libuser_convert_to_value(PyObject *item, GValue *value)
{
	DEBUG_ENTRY;

	/* If it's a PyLong, convert it. */
	if (PyLong_Check(item)) {
		PY_LONG_LONG ll;

		ll = PyLong_AsLongLong(item);
		if (PyErr_Occurred()) {
			DEBUG_EXIT;
			return FALSE;
		}
		if ((long)ll == ll) {
			g_value_init(value, G_TYPE_LONG);
			g_value_set_long(value, ll);
		} else if ((id_t)ll == ll && (id_t)ll != LU_VALUE_INVALID_ID)
			lu_value_init_set_id(value, ll);
		else {
			PyErr_SetString(PyExc_OverflowError,
					"Value out of range");
			DEBUG_EXIT;
			return FALSE;
		}
#ifdef DEBUG_BINDING
		fprintf(stderr, "%sAdding (%lld) to list.\n", getindent(),
			(long long)ll);
#endif
	} else
	/* If it's a PyString/PyUnicode, convert it. */
	if (PYSTRTYPE_CHECK(item)) {
		g_value_init(value, G_TYPE_STRING);
		g_value_set_string(value, PYSTRTYPE_ASSTRING(item));
#ifdef DEBUG_BINDING
		fprintf(stderr, "%sAdding (`%s') to list.\n",
			getindent(), PYSTRTYPE_ASSTRING(item));
#endif
	} else
#if PY_MAJOR_VERSION < 3 && defined(Py_USING_UNICODE)
	if (PyUnicode_Check(item)) {
		PyObject *tmp;

		g_value_init(value, G_TYPE_STRING);
		tmp = PyUnicode_AsUTF8String(item);
		g_value_set_string(value, PyString_AsString(tmp));
#ifdef DEBUG_BINDING
		fprintf(stderr, "%sAdding unicode (`%s') to list.\n",
			getindent(), PyString_AsString(tmp));
#endif
		Py_DECREF(tmp);
	} else
#endif
	if (PyNumber_Check(item)) {
		PyObject *tmp;
		PY_LONG_LONG ll;

		tmp = PyNumber_Long(item);
		ll = PyLong_AsLongLong(item);
		if (PyErr_Occurred()) {
			Py_DECREF(tmp);
			DEBUG_EXIT;
			return FALSE;
		}
		Py_DECREF(tmp);
		if ((long)ll == ll) {
			g_value_init(value, G_TYPE_LONG);
			g_value_set_long(value, ll);
		} else if ((id_t)ll == ll && (id_t)ll != LU_VALUE_INVALID_ID)
			lu_value_init_set_id(value, ll);
		else {
			PyErr_SetString(PyExc_OverflowError,
					"Value out of range");
			DEBUG_EXIT;
			return FALSE;
		}
#ifdef DEBUG_BINDING
		fprintf(stderr, "%sAdding (%lld) to list.\n",
			getindent(), ll);
#endif
	} else {
		PyErr_SetString(PyExc_TypeError,
				"expected a string or a number");
		DEBUG_EXIT;
		return FALSE;
	}
	DEBUG_EXIT;
	return TRUE;
}

/* The setattro function.  Sets an attribute to have the value of the given
 * Python object. */
static int
libuser_entity_setattro(PyObject *self, PyObject *attr_name, PyObject *value)
{
	char *name;
	struct libuser_entity *me;
	PyObject *list;
	struct lu_ent *copy;
	int ret;

	DEBUG_ENTRY;
	me = (struct libuser_entity *)self;

	if (!PYSTRTYPE_CHECK(attr_name)) {
		PyErr_SetString(PyExc_TypeError,
				"attribute name must be a string");
		DEBUG_EXIT;
		return -1;
	}
	name = PYSTRTYPE_ASSTRING(attr_name);
	if (name == NULL) {
		DEBUG_EXIT;
		return -1;
	}

	copy = lu_ent_new();
	lu_ent_copy(me->ent, copy);
	/* Parse out the arguments.  We expect a single object. */
	if (PyArg_ParseTuple(value, "O", &list)) {
		PyObject *item;
		GValue value;
		Py_ssize_t size, i;

		lu_ent_clear(me->ent, name);

		/* If the item is a tuple, scan it. */
		if (PyTuple_Check(list)) {
			/* We need the length of the tuple. */
			size = PyTuple_Size(list);
#ifdef DEBUG_BINDING
			fprintf(stderr, "%sTuple has %jd items.\n",
				getindent(), (intmax_t)size);
#endif
			/* Add each item in turn. */
			memset(&value, 0, sizeof(value));
			for (i = 0; i < size; i++) {
				item = PyTuple_GetItem(list, i);
				if (libuser_convert_to_value(item, &value)
				    == FALSE)
					goto err;
#ifdef DEBUG_BINDING
				fprintf(stderr, "%sAdding tuple item %s.\n",
					getindent(),
					g_value_get_string(&value));
#endif
				lu_ent_add(me->ent, name, &value);
				g_value_unset(&value);
			}
			ret = 0;
			goto end;
		} else
		/* If the object is a list, add it as a set of values. */
		if (PyList_Check(list)) {
			/* We need the length of the list. */
			size = PyList_Size(list);
#ifdef DEBUG_BINDING
			fprintf(stderr, "%sList has %jd items.\n",
				getindent(), (intmax_t)size);
#endif

			/* Add each item in turn. */
			memset(&value, 0, sizeof(value));
			for (i = 0; i < size; i++) {
				item = PyList_GetItem(list, i);
				if (libuser_convert_to_value(item, &value)
				    == FALSE)
					goto err;
#ifdef DEBUG_BINDING
				fprintf(stderr, "%sAdding list item %s.\n",
					getindent(),
					g_value_get_string(&value));
#endif
				lu_ent_add(me->ent, name, &value);
				g_value_unset(&value);
			}
			ret = 0;
			goto end;
		} else
		if (PYSTRTYPE_CHECK(list) ||
		    PyLong_Check(list) ||
		    PyNumber_Check(list)) {
			/* It's a single item, so just add it. */
			if (libuser_convert_to_value(list, &value) == FALSE)
				goto err;
#ifdef DEBUG_BINDING
			fprintf(stderr, "%sAdding single item %s.\n",
				getindent(), g_value_get_string(&value));
#endif
			lu_ent_add(me->ent, name, &value);
			g_value_unset(&value);
			ret = 0;
			goto end;
		}
	}

	PyErr_SetString(PyExc_SystemError,
			"expected Number, Long, String, Tuple, or List");

 err:
	lu_ent_copy(copy, me->ent);
	ret = -1;

 end:
	lu_ent_free(copy);
	DEBUG_EXIT;
	return ret;
}

/* Get the list of attributes, returning them as a PyList of PyStrings. */
static PyObject *
libuser_entity_getattrlist(PyObject *self, PyObject *ignore)
{
	struct libuser_entity *me;
	GList *list, *i;
	PyObject *ret;

	(void)ignore;
	DEBUG_ENTRY;
	me = (struct libuser_entity *)self;
	ret = PyList_New(0);
	list = lu_ent_get_attributes(me->ent);
	for (i = list; i != NULL; i = g_list_next(i)) {
		PyObject *str;

		str = PYSTRTYPE_FROMSTRING((char*)i->data);
		if (str == NULL)
			goto err;
		PyList_Append(ret, str);
		Py_DECREF(str);
	}
	g_list_free(list);
	DEBUG_EXIT;
	return ret;

err:
	g_list_free(list);
	Py_DECREF(ret);
	DEBUG_EXIT;
	return NULL;
}

/* Get the names of the modules which had something to do with this object. */
static PyObject *
libuser_entity_modules(PyObject *self, PyObject *ignore)
{
	struct libuser_entity *me;

	(void)ignore;
	DEBUG_CALL;
	me = (struct libuser_entity *)self;
	return convert_value_array_pylist(me->ent->modules);
}

/* Get the values for a particular attribute, or somesuch. */
static PyObject *
libuser_entity_get(PyObject *self, PyObject *args)
{
	char *arg;
	PyObject *default_value = NULL;
	struct libuser_entity *me;

	DEBUG_ENTRY;
	me = (struct libuser_entity *)self;
	/* The first argument should be the name of the attribute, and the
	 * optional argument is the default value. */
	if (!PyArg_ParseTuple(args, "s|O", &arg, &default_value)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* If we have this attribute, convert it to a list and hand it back. */
	if (lu_ent_has(me->ent, arg)) {
		DEBUG_EXIT;
		return convert_value_array_pylist(lu_ent_get(me->ent, arg));
	} else {
		/* If not, return a new reference for the default. */
		if (default_value != NULL) {
			Py_INCREF(default_value);
			DEBUG_EXIT;
			return default_value;
		} else {
			/* If we have no default, return an empty list. */
			DEBUG_EXIT;
			return PyList_New(0);
		}
	}
}

/* Add a value to the entity. */
static PyObject *
libuser_entity_add(PyObject *self, PyObject *args)
{
	struct libuser_entity *me;
	char *attr = NULL;
	PyObject *val;
	GValue value;

	DEBUG_ENTRY;
	me = (struct libuser_entity *)self;
	/* We expect a string and some kind of object. */
	if (!PyArg_ParseTuple(args, "sO", &attr, &val)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Convert the item to a value. */
	memset(&value, 0, sizeof(value));
	if (libuser_convert_to_value(val, &value) == FALSE) {
		DEBUG_EXIT;
		return NULL;
	}
	lu_ent_add(me->ent, attr, &value);
	g_value_unset(&value);
	DEBUG_EXIT;
	Py_RETURN_NONE;
}

/* Set the attribute to a given list of arguments. */
static PyObject *
libuser_entity_set(PyObject *self, PyObject *args)
{
	struct libuser_entity *me;
	char *attr = NULL;
	PyObject *list = NULL, *val = NULL, *ret;
	GValue value;
	struct lu_ent *copy;

	DEBUG_ENTRY;
	me = (struct libuser_entity *)self;

	copy = lu_ent_new();
	lu_ent_copy(me->ent, copy);
	/* We expect a string and some kind of object. */
	if (PyArg_ParseTuple(args, "sO!", &attr, &PyList_Type, &list)) {
		Py_ssize_t i, size;

		/* It's a list. */
		size = PyList_Size(list);
#ifdef DEBUG_BINDING
		fprintf(stderr, "%sList has %jd items.\n", getindent(),
			(intmax_t)size);
#endif

		/* Remove all current values. */
		lu_ent_clear(me->ent, attr);

		/* Add each of the list items in turn. */
		memset(&value, 0, sizeof(value));
		for (i = 0; i < size; i++) {
			PyObject *item;

			item = PyList_GetItem(list, i);
			if (libuser_convert_to_value(item, &value) == FALSE)
				goto err;
			lu_ent_add(me->ent, attr, &value);
			g_value_unset(&value);
		}
		Py_INCREF(Py_None);
		ret = Py_None;
		goto end;
	}
	PyErr_Clear (); /* PyArg_ParseTuple() above has raised an exception */

	/* It's an object of some kind. */
	if (PyArg_ParseTuple(args, "sO", &attr, &val)) {
		memset(&value, 0, sizeof(value));
		if (libuser_convert_to_value(val, &value) == FALSE)
			goto err;

		/* Remove all current values. */
		lu_ent_clear(me->ent, attr);

		/* Add this one value. */
		lu_ent_add(me->ent, attr, &value);
		g_value_unset(&value);
		Py_INCREF(Py_None);
		ret = Py_None;
		goto end;
	}

	PyErr_SetString(PyExc_SystemError,
			"expected value or list of values");
 err:
	lu_ent_copy(copy, me->ent);
	ret = NULL;
 end:
	lu_ent_free(copy);
	DEBUG_EXIT;
	return ret;
}

/* Clear out all values for an attribute. */
static PyObject *
libuser_entity_clear(PyObject *self, PyObject *args)
{
	struct libuser_entity *me;
	char *arg;

	DEBUG_ENTRY;
	me = (struct libuser_entity *)self;
	if (!PyArg_ParseTuple(args, "s", &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
	lu_ent_clear(me->ent, arg);
	Py_RETURN_NONE;
}

/* Clear out all values for all attributes. */
static PyObject *
libuser_entity_clear_all(PyObject *self, PyObject *ignore)
{
	struct libuser_entity *me;

	(void)ignore;
	DEBUG_ENTRY;
	me = (struct libuser_entity *)self;
	lu_ent_clear_all(me->ent);
	Py_RETURN_NONE;
}

/* Roll-back any changes we've made to the object since it was last read from or
 * saved to the information store. */
static PyObject *
libuser_entity_revert(PyObject *self, PyObject *ignore)
{
	struct libuser_entity *me;

	(void)ignore;
	DEBUG_ENTRY;
	me = (struct libuser_entity *)self;
	lu_ent_revert(me->ent);
	DEBUG_EXIT;
	Py_RETURN_NONE;
}

/* Get the length of the list of attributes. */
static Py_ssize_t
libuser_entity_length(PyObject *self)
{
	struct libuser_entity *me;
	GList *list;
	Py_ssize_t ret;

	DEBUG_CALL;
	me = (struct libuser_entity *)self;
	list = lu_ent_get_attributes(me->ent);
	ret = g_list_length(list);
	g_list_free(list);
	return ret;
}

/* Get the value for a particular item, dictionary style. */
static PyObject *
libuser_entity_get_item(PyObject *self, PyObject *item)
{
	struct libuser_entity *me;
	char *attr;

	DEBUG_ENTRY;
	me = (struct libuser_entity *)self;

	/* Our lone argument should be a string. */
	if (!PYSTRTYPE_CHECK(item)) {
		PyErr_SetString(PyExc_TypeError, "expected a string");
		DEBUG_EXIT;
		return NULL;
	}
	attr = PYSTRTYPE_ASSTRING(item);

	if (!lu_ent_has(me->ent, attr)) {
		PyErr_SetString(PyExc_KeyError,
				"no such attribute defined for this entity");
		DEBUG_EXIT;
		return NULL;
	}

	DEBUG_EXIT;
	return convert_value_array_pylist(lu_ent_get(me->ent, attr));
}

/* Check if an object has values for the given attribute. */
static PyObject *
libuser_entity_has_key(PyObject *self, PyObject *item)
{
	char *attr;
	struct libuser_entity *me;

	DEBUG_ENTRY;

	me = (struct libuser_entity *)self;
	if (!PyArg_ParseTuple(item, "s", &attr)) {
		PyErr_SetString(PyExc_TypeError,
				"expected a tuple or string");
		DEBUG_EXIT;
		return NULL;
	}
	return PYINTTYPE_FROMLONG(lu_ent_has(me->ent, attr) ? 1 : 0);
}

/* Set a value, dictionary style. */
static int
libuser_entity_set_item(PyObject *self, PyObject *item, PyObject *args)
{
	struct libuser_entity *me;
	char *attr = NULL;
	Py_ssize_t i, size;
	int ret;
	GValue value;
	struct lu_ent *copy;

	DEBUG_ENTRY;
	me = (struct libuser_entity *)self;

	/* The item should be a string. */
	if (!PYSTRTYPE_CHECK(item)) {
		PyErr_SetString(PyExc_TypeError, "expected a string");
		DEBUG_EXIT;
		return -1;
	}
	attr = PYSTRTYPE_ASSTRING(item);
#ifdef DEBUG_BINDING
	fprintf(stderr, "%sSetting item (`%s')...\n", getindent(), attr);
#endif

	copy = lu_ent_new();
	lu_ent_copy(me->ent, copy);
	/* If the new value is a list, convert each and add in turn. */
	if (PyList_Check(args)) {
		size = PyList_Size(args);
#ifdef DEBUG_BINDING
		fprintf(stderr, "%sList has %jd items.\n", getindent(),
			(intmax_t)size);
#endif
		lu_ent_clear(me->ent, attr);
		memset(&value, 0, sizeof(value));
		for (i = 0; i < size; i++) {
			item = PyList_GetItem(args, i);
			if (libuser_convert_to_value(item, &value) == FALSE)
				goto err;
#ifdef DEBUG_BINDING
			fprintf(stderr, "%sAdding (`%s') to `%s'.\n",
				getindent(),
				g_value_get_string(&value), attr);
#endif
			lu_ent_add(me->ent, attr, &value);
			g_value_unset(&value);
		}
		ret = 0;
		goto end;
	} else
	/* If the new value is a tuple, convert each and add in turn. */
	if (PyTuple_Check(args)) {
		size = PyTuple_Size(args);
#ifdef DEBUG_BINDING
		fprintf(stderr, "%sTuple has %jd items.\n", getindent(),
			(intmax_t)size);
#endif
		lu_ent_clear(me->ent, attr);
		memset(&value, 0, sizeof(value));
		for (i = 0; i < size; i++) {
			item = PyTuple_GetItem(args, i);
			if (libuser_convert_to_value(item, &value) == FALSE)
				goto err;
#ifdef DEBUG_BINDING
			fprintf(stderr, "%sAdding (`%s') to `%s'.\n",
				getindent(),
				g_value_get_string(&value), attr);
#endif
			lu_ent_add(me->ent, attr, &value);
			g_value_unset(&value);
		}
		ret = 0;
		goto end;
	} else
	/* If the new value is a value, convert it and add it. */
	if (PYSTRTYPE_CHECK(args) ||
	    PyNumber_Check(args) ||
	    PyLong_Check(args)) {
		lu_ent_clear(me->ent, attr);
		memset(&value, 0, sizeof(value));
		if (libuser_convert_to_value(args, &value) == FALSE)
			goto err;
#ifdef DEBUG_BINDING
		fprintf(stderr, "%sSetting (`%s') to `%s'.\n", getindent(),
			attr, g_value_get_string(value));
#endif
		lu_ent_add(me->ent, attr, &value);
		g_value_unset(&value);
		ret = 0;
		goto end;
	}

	PyErr_SetString(PyExc_TypeError,
			"expected values or list of values");
 err:
	lu_ent_copy(copy, me->ent);
	ret = -1;

 end:
	lu_ent_free(copy);
	DEBUG_EXIT;
	return ret;
}

static PyMappingMethods libuser_entity_mapping_methods = {
	libuser_entity_length,	/* mp_length */
	libuser_entity_get_item, /* mp_subscript */
	libuser_entity_set_item, /* mp_ass_subscript */
};

static PyMethodDef libuser_entity_methods[] = {
	{"getattrlist", libuser_entity_getattrlist, METH_NOARGS,
	 "get a list of the attributes this entity has"},
	{"has_key", libuser_entity_has_key, METH_VARARGS,
	 "check if the entity has a given attribute"},
	{"get", libuser_entity_get, METH_VARARGS,
	 "get a list of the values for a given attribute"},
	{"keys", libuser_entity_getattrlist, METH_NOARGS},
	{"clear", libuser_entity_clear, METH_VARARGS,
	 "clear the list of values for a given attribute"},
	{"set", libuser_entity_set, METH_VARARGS,
	 "set the list of values for a given attribute"},
	{"add", libuser_entity_add, METH_VARARGS,
	 "add a value to the current list of values for a given attribute"},
	{"clear_all", libuser_entity_clear_all, METH_NOARGS,
	 "clear all values for all attributes"},
	{"revert", libuser_entity_revert, METH_NOARGS,
	 "revert the list of values for a given attribute to the values which "
	 "were set when the entity was looked up"},
	{"modules", libuser_entity_modules, METH_NOARGS,
	 "get a list of the modules which generated or looked up this object"},
	{NULL, NULL, 0, NULL},
};

PyTypeObject EntityType = {
	PyVarObject_HEAD_INIT(&PyType_Type, 0)
	"libuser.Entity",	/* tp_name */
	sizeof(struct libuser_entity), /* tp_basicsize */
	0,			/* tp_itemsize */
	libuser_entity_destroy, /* tp_dealloc */
	NULL,			/* tp_print */
	NULL,			/* tp_getattr */
	NULL,			/* tp_setattr */
	NULL,			/* tp_compare */
	NULL,			/* tp_repr */
	NULL,			/* tp_as_number */
	NULL,			/* tp_as_sequence */
	&libuser_entity_mapping_methods, /* tp_as_mapping */
	NULL,			/* tp_hash */
	NULL,			/* tp_call */
	NULL,			/* tp_str */
	NULL,			/* tp_getattro */
	libuser_entity_setattro,	/* tp_setattro */
	NULL,			/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,	/* tp_flags */
	"Data about a particular user or group account",	/* tp_doc */
	NULL,			/* tp_traverse */
	NULL,			/* tp_clear */
	NULL,			/* tp_richcompare */
	0,			/* tp_weaklistoffset */
	NULL,			/* tp_iter */
	NULL,			/* tp_iternext */
	libuser_entity_methods,	/* tp_methods */
};
