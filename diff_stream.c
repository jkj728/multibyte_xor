#include <Python.h>


void calculate_difference_stream(unsigned char * stream, int stream_length, int key_length, unsigned char * diff_stream)
{
    for(int i = 0; i < (stream_length - key_length); i ++){
        diff_stream[i] = stream[i] ^ stream[i + key_length];
    }
}

static PyObject* diff_stream(PyObject* self, PyObject* args){
	//declaration of variables needed to call C function!
	PyByteArrayObject *diff_stream;
	int key_length;

	if(!PyArg_ParseTuple(args, "Oi", &diff_stream, &key_length)){
		printf("There was an error parsing the arguments!");
		return NULL;
	}

    Py_buffer pyBuf;
    PyObject_GetBuffer(diff_stream, &pyBuf, PyBUF_FULL_RO);
    
    unsigned char* bBuf = (unsigned char*)pyBuf.buf;

    unsigned char diff_stream_buff[pyBuf.len - key_length];

    calculate_difference_stream(bBuf, pyBuf.len, key_length, diff_stream_buff);

	return Py_BuildValue("y#", diff_stream_buff, (pyBuf.len - key_length));
}

static PyMethodDef myMethods[] = {
	{"diff_stream", diff_stream, METH_VARARGS, "this will calculate the difference stream using the C XOR bitwise operator ^"},
	{NULL, NULL, 0, NULL}
};

static struct PyModuleDef xordiffstream = {
	PyModuleDef_HEAD_INIT,
	"xordiffstream",
	"DIFF STREAM MODULE",
	-1,
	myMethods
};

PyMODINIT_FUNC PyInit_xordiffstream(void)
{
	return PyModule_Create(&xordiffstream);
}

