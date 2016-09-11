/* Copyright (C) 2001,2002 Red Hat, Inc.
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
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>
#include <glib.h>
#include "../lib/user.h"
#include "../lib/user_private.h"
#include "common.h"

struct libuser_prompt {
	PyObject_HEAD
	struct lu_prompt prompt;
};

#define Prompt_Check(__x) ((__x)->ob_type == &PromptType)

gboolean
libuser_admin_python_prompter(struct lu_prompt *prompts, int count,
			      gpointer callback_data,
			      struct lu_error **error)
{
	PyObject **prompt_data = (PyObject **) callback_data;

	DEBUG_ENTRY;
	if (count > 0) {
		PyObject *list, *tuple, *ret;
		int i;

		if (!PyCallable_Check(prompt_data[0])) {
			lu_error_new(error, lu_error_generic, NULL);
			PyErr_SetString(PyExc_RuntimeError,
					"prompter is not callable");
			DEBUG_EXIT;
			return FALSE;
		}
		list = PyList_New(0);
		for (i = 0; i < count; i++) {
			struct libuser_prompt *prompt;

			prompt = (struct libuser_prompt *)
			  libuser_prompt_new(NULL, NULL);
			if (prompt == NULL) {
				Py_DECREF(list);
				DEBUG_EXIT;
				return FALSE;
			}
			prompt->prompt.key = g_strdup(prompts[i].key);
			prompt->prompt.prompt = g_strdup(prompts[i].prompt);
			prompt->prompt.domain = g_strdup(prompts[i].domain);
			prompt->prompt.visible = prompts[i].visible;
			prompt->prompt.default_value
			  = g_strdup(prompts[i].default_value);
			prompt->prompt.value = g_strdup(prompts[i].value);
			prompt->prompt.free_value = g_free;
			PyList_Append(list, (PyObject *) prompt);
			Py_DECREF(prompt);
		}
		tuple = PyTuple_New(PyTuple_Check(prompt_data[1]) ?
			            PyTuple_Size(prompt_data[1]) + 1 : 1);
		PyTuple_SetItem(tuple, 0, list);
		if (PyTuple_Check(prompt_data[1])) {
			Py_ssize_t j;

			for (j = 0; j < PyTuple_Size(prompt_data[1]); j++) {
				PyObject *obj;

				obj = PyTuple_GetItem(prompt_data[1], j);
				Py_INCREF(obj);
				PyTuple_SetItem(tuple, j + 1, obj);
			}
		}
		ret = PyObject_CallObject(prompt_data[0], tuple);
		if (PyErr_Occurred()) {
			PyErr_Print();
			Py_DECREF(tuple);
			DEBUG_EXIT;
			lu_error_new(error, lu_error_generic,
				     _
				     ("error while prompting for necessary information"));
			return FALSE;
		}
		for (i = 0; i < count; i++) {
			struct libuser_prompt *prompt;
			/* i doesn't have to be Py_ssize_t because count is int
			   as well. */
			prompt = (struct libuser_prompt *)PyList_GetItem(list,
									 i);
			prompts[i].value = g_strdup(prompt->prompt.value);
			prompts[i].free_value = g_free;
		}
		Py_DECREF(tuple);
		Py_DECREF(ret);
	}

	DEBUG_EXIT;
	return TRUE;
}

static PyObject *
libuser_admin_prompt(struct libuser_admin *self, PyObject * args,
		     PyObject * kwargs, lu_prompt_fn * prompter)
{
	Py_ssize_t count;
	int i;
	PyObject *list = NULL, *moreargs = NULL;
	struct lu_prompt *prompts;
	struct lu_error *error = NULL;
	char *keywords[] = { "prompt_list", "more_args", NULL };

	g_return_val_if_fail(self != NULL, NULL);

	DEBUG_ENTRY;
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!|O", keywords,
					 &PyList_Type, &list,
	     &moreargs)) {
		DEBUG_EXIT;
		return NULL;
	}
	count = PyList_Size(list);
	if (count > INT_MAX) {
		PyErr_SetString(PyExc_ValueError, "too many prompts");
		DEBUG_EXIT;
		return NULL;
	}
	/* i now may be int because count fits in int */
	for (i = 0; i < count; i++) {
		PyObject *item;

		item = PyList_GetItem(list, i);
		DEBUG_CALL;
		if (!Prompt_Check(item)) {
			PyErr_SetString(PyExc_TypeError,
					"expected list of Prompt objects");
			DEBUG_EXIT;
			return NULL;
		}
		DEBUG_CALL;
	}
	DEBUG_CALL;
	prompts = g_malloc0_n(count, sizeof(struct lu_prompt));
	DEBUG_CALL;

	for (i = 0; i < count; i++) {
		struct libuser_prompt *obj;
		obj = (struct libuser_prompt *) PyList_GetItem(list, i);
		Py_INCREF(obj);
		prompts[i].key = g_strdup(obj->prompt.key ? : "");
		prompts[i].domain = g_strdup(obj->prompt.domain ? : "");
		prompts[i].prompt = g_strdup(obj->prompt.prompt ? : "");
		prompts[i].default_value =
		    obj->prompt.default_value ? g_strdup(obj->prompt.default_value) :
		    NULL;
		prompts[i].visible = obj->prompt.visible;
		/* FIXME: free the values sometime? */
	}
#ifdef DEBUG_BINDING
	fprintf(stderr, "Prompter function promptConsole is at <%p>.\n",
		lu_prompt_console);
	fprintf(stderr,
		"Prompter function promptConsoleQuiet is at <%p>.\n",
		lu_prompt_console_quiet);
	fprintf(stderr, "Calling prompter function at <%p>.\n", prompter);
#endif
	if (prompter(prompts, count, self->prompt_data, &error) != FALSE) {
		for (i = 0; i < count; i++) {
			struct libuser_prompt *obj;
			obj = (struct libuser_prompt *)PyList_GetItem(list, i);
			obj->prompt.value = g_strdup(prompts[i].value ? : "");
			obj->prompt.free_value = g_free;
			if (prompts[i].value && prompts[i].free_value) {
				prompts[i].free_value(prompts[i].value);
				prompts[i].value = NULL;
				prompts[i].free_value = NULL;
			}
			Py_DECREF(obj);
		}
		DEBUG_EXIT;
		Py_RETURN_NONE;
	} else {
		if (error != NULL)
			lu_error_free(&error);
		for (i = 0; i < count; i++) {
			PyObject *obj;

			obj = PyList_GetItem(list, i);
			Py_DECREF(obj);
		}
		PyErr_SetString(PyExc_RuntimeError,
				"error prompting the user for information");
		DEBUG_EXIT;
		return NULL;
	}
}

PyObject *
libuser_admin_prompt_console(PyObject * self, PyObject * args,
			     PyObject * kwargs)
{
	DEBUG_CALL;
	return libuser_admin_prompt((struct libuser_admin *) self, args,
				    kwargs, lu_prompt_console);
}

PyObject *
libuser_admin_prompt_console_quiet(PyObject * self, PyObject * args,
				   PyObject * kwargs)
{
	DEBUG_CALL;
	return libuser_admin_prompt((struct libuser_admin *) self, args,
				    kwargs, lu_prompt_console_quiet);
}

static void
libuser_prompt_destroy(PyObject *self)
{
	struct libuser_prompt *me;

	DEBUG_ENTRY;
	me = (struct libuser_prompt *)self;
	if (me->prompt.value && me->prompt.free_value)
		me->prompt.free_value(me->prompt.value);
	g_free((void *)me->prompt.key);
	g_free((void *)me->prompt.prompt);
	g_free((void *)me->prompt.domain);
	g_free((void *)me->prompt.default_value);
	memset(&me->prompt, 0, sizeof(me->prompt));
	PyObject_DEL(me);
	DEBUG_EXIT;
}

/* "key" attribute getter */
static PyObject *
libuser_prompt_get_key(PyObject *self, void *unused)
{
	struct libuser_prompt *me = (struct libuser_prompt *)self;

	(void)unused;
	DEBUG_CALL;
	return PYSTRTYPE_FROMSTRING(me->prompt.key);
}

/* "key" attribute setter */
static int
libuser_prompt_set_key(PyObject *self, PyObject *value, void *unused)
{
	struct libuser_prompt *me = (struct libuser_prompt *)self;

	(void)unused;
	DEBUG_ENTRY;
	if (!PYSTRTYPE_CHECK(value)) {
		PyErr_SetString(PyExc_TypeError, "key must be a string");
		DEBUG_EXIT;
		return -1;
	}
	g_free((char *)me->prompt.key);
	me->prompt.key = g_strdup(PYSTRTYPE_ASSTRING(value));
	DEBUG_EXIT;
	return 0;
}


/* "prompt" attribute getter */
static PyObject *
libuser_prompt_get_prompt(PyObject *self, void *unused)
{
	struct libuser_prompt *me = (struct libuser_prompt *)self;

	(void)unused;
	DEBUG_CALL;
	return PYSTRTYPE_FROMSTRING(me->prompt.prompt);
}

/* "prompt" attribute setter */
static int
libuser_prompt_set_prompt(PyObject *self, PyObject *value, void *unused)
{
	struct libuser_prompt *me = (struct libuser_prompt *)self;

	(void)unused;
	DEBUG_ENTRY;
	if (!PYSTRTYPE_CHECK(value)) {
		PyErr_SetString(PyExc_TypeError, "prompt must be a string");
		DEBUG_EXIT;
		return -1;
	}
	g_free((char *)me->prompt.prompt);
	me->prompt.prompt = g_strdup(PYSTRTYPE_ASSTRING(value));
	DEBUG_EXIT;
	return 0;
}

/* "domain" attribute getter */
static PyObject *
libuser_prompt_get_domain(PyObject *self, void *unused)
{
	struct libuser_prompt *me = (struct libuser_prompt *)self;

	(void)unused;
	DEBUG_CALL;
	return PYSTRTYPE_FROMSTRING(me->prompt.domain ?: "");
}

/* "domain" attribute setter */
static int
libuser_prompt_set_domain(PyObject *self, PyObject *value, void *unused)
{
	struct libuser_prompt *me = (struct libuser_prompt *)self;

	(void)unused;
	DEBUG_ENTRY;
	if (!PYSTRTYPE_CHECK(value)) {
		PyErr_SetString(PyExc_TypeError, "domain must be a string");
		DEBUG_EXIT;
		return -1;
	}
	g_free((char *)me->prompt.domain);
	me->prompt.domain = g_strdup(PYSTRTYPE_ASSTRING(value));
	DEBUG_EXIT;
	return 0;
}

/* "visible" attribute getter */
static PyObject *
libuser_prompt_get_visible(PyObject *self, void *unused)
{
	struct libuser_prompt *me = (struct libuser_prompt *)self;

	(void)unused;
	DEBUG_CALL;
	return PYINTTYPE_FROMLONG(me->prompt.visible);
}

/* "visible" attribute setter */
static int
libuser_prompt_set_visible(PyObject *self, PyObject *value, void *unused)
{
	struct libuser_prompt *me = (struct libuser_prompt *)self;

	(void)unused;
	DEBUG_CALL;
	me->prompt.visible = PyObject_IsTrue(value);
	return 0;
}

/* "default_value"/"defaultValue" attribute getter */
static PyObject *
libuser_prompt_get_default_value(PyObject *self, void *unused)
{
	struct libuser_prompt *me = (struct libuser_prompt *)self;

	(void)unused;
	DEBUG_CALL;
	if (me->prompt.default_value != NULL)
		return PYSTRTYPE_FROMSTRING(me->prompt.default_value);
	else
		Py_RETURN_NONE;
}

/* "default_value"/"defaultValue" attribute setter */
static int
libuser_prompt_set_default_value(PyObject *self, PyObject *value, void *unused)
{
	struct libuser_prompt *me = (struct libuser_prompt *)self;

	(void)unused;
	DEBUG_ENTRY;
	if (!PYSTRTYPE_CHECK(value)) {
		PyErr_SetString(PyExc_TypeError,
				"default value must be a string");
		DEBUG_EXIT;
		return -1;
	}
	g_free((char *)me->prompt.default_value);
	me->prompt.default_value = (value == Py_None)
		? NULL : g_strdup(PYSTRTYPE_ASSTRING(value));
	DEBUG_EXIT;
	return 0;
}

/* "value" attribute getter */
static PyObject *
libuser_prompt_get_value(PyObject *self, void *unused)
{
	struct libuser_prompt *me = (struct libuser_prompt *)self;

	(void)unused;
	DEBUG_CALL;
	if (me->prompt.value != NULL)
		return PYSTRTYPE_FROMSTRING(me->prompt.value);
	else
		Py_RETURN_NONE;
}

/* "value" attribute setter */
static int
libuser_prompt_set_value(PyObject *self, PyObject *value, void *unused)
{
	struct libuser_prompt *me = (struct libuser_prompt *)self;

	(void)unused;
	DEBUG_ENTRY;
	if (!PYSTRTYPE_CHECK(value)) {
		PyErr_SetString(PyExc_TypeError, "value must be a string");
		DEBUG_EXIT;
		return -1;
	}
	if (me->prompt.value && me->prompt.free_value)
		me->prompt.free_value(me->prompt.value);
	me->prompt.value = g_strdup(PYSTRTYPE_ASSTRING(value));
	me->prompt.free_value = g_free;
	DEBUG_EXIT;
	return 0;
}

static PyObject *
libuser_prompt_str(PyObject *self)
{
	struct libuser_prompt *me;

	me = (struct libuser_prompt *)self;
	return PYSTRTYPE_FROMFORMAT("(key = \"%s\", prompt = \"%s\", "
		"domain = \"%s\", visible = %s, default_value = \"%s\", "
		"value = \"%s\")", me->prompt.key ? me->prompt.key : "",
		me->prompt.prompt ? me->prompt.prompt : "",
		me->prompt.domain ? me->prompt.domain : "",
		me->prompt.visible ? "true" : "false",
		me->prompt.default_value ? me->prompt.default_value : "",
		me->prompt.value ? me->prompt.value : "");
}

PyObject *
libuser_prompt_new(PyObject *ignored_self, PyObject *ignore)
{
	struct libuser_prompt *ret;

	(void)ignored_self;
	(void)ignore;
	DEBUG_ENTRY;
	ret = PyObject_NEW(struct libuser_prompt, &PromptType);
	if (ret != NULL) {
		memset(&ret->prompt, 0, sizeof(ret->prompt));
	}
	DEBUG_EXIT;
	return (PyObject *)ret;
}

static struct PyGetSetDef libuser_prompt_getseters[] = {
	{"key", libuser_prompt_get_key, libuser_prompt_set_key,
	 "What information to prompt for, format \"module/name\"", NULL},
	{"prompt", libuser_prompt_get_prompt, libuser_prompt_set_prompt,
	 "Text of a prompt, possibly translated", NULL},
	{"domain", libuser_prompt_get_domain, libuser_prompt_set_domain,
	 "Text domain which contains translation sof the prompt", NULL},
	{"visible", libuser_prompt_get_visible, libuser_prompt_set_visible,
	 "Whether the response should be echoed", NULL},
	{"default_value", libuser_prompt_get_default_value,
	 libuser_prompt_set_default_value, "Default response value", NULL},
	{"defaultValue", libuser_prompt_get_default_value,
	 libuser_prompt_set_default_value, "Default response value", NULL},
	{"value", libuser_prompt_get_value, libuser_prompt_set_value,
	 "User's response", NULL},
	{NULL, NULL, NULL, NULL, NULL}
};

PyTypeObject PromptType = {
	PyVarObject_HEAD_INIT(&PyType_Type, 0)
	"libuser.Prompt",	/* tp_name */
	sizeof(struct libuser_prompt), /* tp_basicsize */
	0,			/* tp_itemsize */
	libuser_prompt_destroy,	/* tp_dealloc */
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
	libuser_prompt_str,	/* tp_str */
	NULL,			/* tp_getattro */
	NULL,			/* tp_setattro */
	NULL,			/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,	/* tp_flags */
	"Data passed to a prompter function",	/* tp_doc */
	NULL,			/* tp_traverse */
	NULL,			/* tp_clear */
	NULL,			/* tp_richcompare */
	0,			/* tp_weaklistoffset */
	NULL,			/* tp_iter */
	NULL,			/* tp_iternext */
	NULL,			/* tp_methods */
	NULL,			/* tp_members */
	libuser_prompt_getseters,	/* tp_getseters */
};
