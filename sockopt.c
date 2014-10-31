#include <Python.h>
#include <sys/types.h>
#include <sys/socket.h> 

PyDoc_STRVAR(sockopt_get_doc, "Get a socket option, See the Unix manual for level and option"); 

static PyObject *
sockopt_get(PyObject *object, PyObject *args)
{
	int fd, level, optname, ret;
	socklen_t len;
	PyStringObject *buf;

	if (!PyArg_ParseTuple(args, "iiiS:sockopt.get", &fd, &level, &optname, &buf)) {
		return NULL;
	} 
	len = PyString_GET_SIZE(buf);
	ret = getsockopt(fd, level, optname,
			(void *)PyString_AS_STRING(buf), &len);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	} 
	return PyInt_FromLong(len); 
}

PyDoc_STRVAR(sockopt_set_doc, "Set a socket option, See the Unix manual for level and option");

static PyObject *
sockopt_set(PyObject *object, PyObject *args)
{
	int fd, level, optname, ret;	
	PyStringObject *buf;
	if (!PyArg_ParseTuple(args, "iiiS:sockopt.set", &fd, &level, &optname, &buf)) {
		return NULL;
	}
	ret = setsockopt(fd, level, optname,
			(void *)PyString_AS_STRING(buf), PyString_GET_SIZE(buf));
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	Py_INCREF(Py_None);
	return Py_None;
}

static PyMethodDef sockopt_methods[] = {
	{"get", sockopt_get, METH_VARARGS, sockopt_get_doc},
	{"set", sockopt_set, METH_VARARGS, sockopt_set_doc},
	{NULL, NULL},
}; 


PyMODINIT_FUNC
init_sockopt(void)
{
	PyObject *m;		
	m  = Py_InitModule("_sockopt", sockopt_methods);
	if (m == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "load module _sockopt failed");
	}
}
