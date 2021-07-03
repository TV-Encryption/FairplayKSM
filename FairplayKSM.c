#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "PlatformTypes.h"
#include "SKDServer.h"
#include "SKDServerUtils.h"


enum {
    pyErr = -1
};

// Implementation

PyObject *keyFetchCallback = NULL;
UInt8* pKeyPem = NULL;
size_t pKeyPem_s = 0;
UInt8* ask = NULL;

static int setKeyFetchCallback(PyObject *callback)
{
    if (keyFetchCallback) {
        return 0;
    }

    printf("Setting callback\n");

    if (!PyCallable_Check(callback)) {
        PyErr_SetString(PyExc_TypeError, "parameter must be callable");
        return pyErr;
    }
    Py_XINCREF(callback);         /* Add a reference to new callback */
    keyFetchCallback = callback;       /* Remember new callback */
    return 0;
}

static int setASK(char* ask_data, Py_ssize_t ask_data_s) {
    if (ask) {
        return 0;
    }

    if (ask_data_s != PS_AES128_KEY_SZ) {
        PyErr_SetString(PyExc_ValueError, "ASK length is invalid!");
        return pyErr;
    }

    printf("Setting ask\n");

    char* tmp = malloc(PS_AES128_KEY_SZ);
    if (!tmp) {
        PyErr_NoMemory();
        return pyErr;
    }

    (void) memcpy(tmp, ask_data, ask_data_s);

    ask = tmp;

    return 0;
}

static int setpKeyPEM(char* private_key, Py_ssize_t private_key_s) {
    if (pKeyPem) {
        return 0;
    }

    printf("Setting private key\n");

    char* tmp = malloc(private_key_s);
    if (!tmp) {
        PyErr_NoMemory();
        return pyErr;
    }

    (void) memcpy(tmp, private_key, private_key_s);

    pKeyPem = tmp;
    pKeyPem_s = private_key_s;

    return 0;
}

OSStatus SKDServerFetchContentKeyAndIV(
    const UInt8 *assetId /* input  */, 
    UInt8  *ck           /* output */,
    UInt8  *iv           /* output */)
{
    OSStatus  status = noErr;
    
    (void) assetId;
    // sanity check inputs
    PS_RequireAction(ck != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(iv != NULL, return kDRMSKDServerParamErr;)

    PyObject* arglist = Py_BuildValue("(y)", assetId);
    if (!arglist) {
        PyErr_NoMemory();
        return pyErr;
    }

    PyObject* result = PyObject_CallObject(keyFetchCallback, arglist);
    Py_DECREF(arglist);
    if (NULL == result) {
        return pyErr;
    }

    char* tmp_iv;
    Py_ssize_t tmp_iv_s;
    char* tmp_key;
    Py_ssize_t tmp_key_s;
    if (!PyArg_ParseTuple(result, "y#y#:SKDServerFetchContentKeyAndIV", &tmp_iv, &tmp_iv_s, &tmp_key, &tmp_key_s)) {
        return pyErr;
    }

    if (tmp_iv_s != PS_AES128_IV_SZ) {
        PyErr_SetString(PyExc_ValueError, "IV length is invalid!");
        return pyErr;
    }
    
    if (tmp_key_s != PS_AES128_KEY_SZ) {
        PyErr_SetString(PyExc_ValueError, "IV length is invalid!");
        return pyErr;
    }

    memcpy(iv, tmp_iv, PS_AES128_IV_SZ);
    memcpy(ck, tmp_key, PS_AES128_KEY_SZ);

    Py_DECREF(result);

    return status;
}

OSStatus SKDServerGetASK(
    UInt8  ask_dest[PS_AES128_KEY_SZ])
{
    OSStatus  status = noErr;

    // sanity check inputs
    PS_RequireAction(ask_dest != NULL, return kDRMSKDServerParamErr;)

    memcpy(ask_dest, ask, PS_AES128_KEY_SZ);

    return status;
}


// Public interface

static PyObject* generateCKC(PyObject *self, PyObject *args, PyObject *keywds) {

    unsigned char* spc;
    Py_ssize_t spc_s;
    char* key_ref;
    unsigned char* ckc;
    uint32_t ckc_size;
    PyObject* callback;

    char* private_key;
    Py_ssize_t private_key_s;
    char* ask;
    Py_ssize_t ask_s;

    static char *kwlist[] = {"key_ref", "spc", "key_fetch_callback", "p_key_pem", "ask", NULL};

    // Memory for those varse is handled by python…
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "yy#Oy#y#:generateCKC", kwlist, &key_ref, &spc, &spc_s, &callback, &private_key, &private_key_s, &ask, &ask_s)) {
        return NULL;
    }

    // Store static stuff
    OSStatus status = setKeyFetchCallback(callback);
    if (status != noErr) {
        // Error has already been set.
        return NULL;
    }
    status = setpKeyPEM(private_key, private_key_s);
    if (status != noErr) {
        // Error has already been set.
        return NULL;
    }

    status = setASK(ask, ask_s);
    if (status != noErr) {
        // Error has already been set.
        return NULL;
    }

    // Generate CKC
    status = SKDServerGenCKC(spc, spc_s, key_ref, &ckc, &ckc_size);

    if (-1 == status) {
        return NULL;
    } else if (status != noErr) {
        PyErr_SetString(PyExc_RuntimeError, "An error occured");
        return NULL;
    }

    // Create return value
    PyObject* py_ckc = Py_BuildValue("y#", ckc, ckc_size);

    (void) SKDServerDisposeStorage(ckc);

    return py_ckc;
}

// Python Module Generation

static PyMethodDef FairplayKSMMethods[] = {
    {"generate_ckc",  (PyCFunction)(void(*)(void)) generateCKC, METH_VARARGS | METH_KEYWORDS, "Create ckc from spc."},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static PyModuleDef module_def = {
    .m_base = PyModuleDef_HEAD_INIT,
    .m_name = "FairplayKSM",
    .m_doc = NULL,
    .m_size = -1,
    .m_methods = FairplayKSMMethods
};

PyMODINIT_FUNC
PyInit_FairplayKSM(void) {
    return PyModule_Create(&module_def);
}