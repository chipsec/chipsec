/** CHIPSEC: Platform Security Assessment Framework
Copyright (c) 2019, Intel Corporation
 
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; Version 2.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

Contact information:
chipsec@intel.com

This file incorporates work covered by the following copyright and permission notice
**/


/** @file
Efi Compressor

Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Python.h>
#include <Decompress.h>
#include <Compress.h>
#include <Bra.h>

/*
 UefiDecompress(data_buffer)
*/
STATIC
PyObject*
UefiDecompress(
  PyObject    *Self,
  PyObject    *Args
  )
{
  Py_buffer SrcData;
  UINT32        DstDataSize;
  EFI_STATUS    Status;
  char         *DstBuf;

  DstBuf = NULL;
  DstDataSize = 0;

  Status = PyArg_ParseTuple(
            Args,
            "y*",
            &SrcData
            );
  if (Status == 0) {
    return NULL;
  }

  Status = Extract((VOID *)SrcData.buf, SrcData.len, (VOID **)&DstBuf, &DstDataSize, 1);
  if (Status != EFI_SUCCESS) {
     PyErr_SetString(PyExc_Exception, "Failed to decompress\n");
     goto ERROR;
  }

  PyBuffer_Release(&SrcData);
  return PyBytes_FromStringAndSize(DstBuf, DstDataSize);

ERROR:

  if (DstBuf != NULL) {
    free(DstBuf);
  }
  return NULL;
}


STATIC
PyObject*
FrameworkDecompress(
  PyObject    *Self,
  PyObject    *Args
  )
{
  Py_buffer SrcData;
  UINT32        DstDataSize;
  EFI_STATUS    Status;
  char         *DstBuf;

  DstBuf = NULL;
  DstDataSize = 0;

  Status = PyArg_ParseTuple(
            Args,
            "y*",
            &SrcData
            );
  if (Status == 0) {
    return NULL;
  }

  Status = Extract((VOID *)SrcData.buf, SrcData.len, (VOID **)&DstBuf, &DstDataSize, 2);
  if (Status != EFI_SUCCESS) {
     PyErr_SetString(PyExc_Exception, "Failed to decompress\n");
     goto ERROR;
  }

  PyBuffer_Release(&SrcData);
  return PyBytes_FromStringAndSize(DstBuf, DstDataSize);

ERROR:

  if (DstBuf != NULL) {
    free(DstBuf);
  }
  return NULL;
}


STATIC
PyObject*
UefiCompress(
  PyObject    *Self,
  PyObject    *Args
  )
{
  Py_buffer SrcData;
  UINT32        DstDataSize;
  EFI_STATUS    Status;
  char         *DstBuf;

  DstBuf = NULL;
  DstDataSize = 0;

  Status = PyArg_ParseTuple(
            Args,
            "y*",
            &SrcData
            );
  if (Status == 0) {
    return NULL;
  }

Status = Pack((VOID *)SrcData.buf, SrcData.len, (VOID **)&DstBuf, &DstDataSize, 1);
  if (Status != EFI_SUCCESS) {
     PyErr_SetString(PyExc_Exception, "Failed to compress\n");
     goto ERROR;
  }

  PyBuffer_Release(&SrcData);
  return PyBytes_FromStringAndSize(DstBuf, DstDataSize);

ERROR:

  if (DstBuf != NULL) {
    free(DstBuf);
  }
  return NULL;
}


STATIC
PyObject*
FrameworkCompress(
  PyObject    *Self,
  PyObject    *Args
  )
{
  Py_buffer SrcData;
  UINT32        DstDataSize;
  EFI_STATUS    Status;
  char         *DstBuf;

  DstBuf = NULL;
  DstDataSize = 0;

  Status = PyArg_ParseTuple(
            Args,
            "y*",
            &SrcData
            );
  if (Status == 0) {
    return NULL;
  }

  Status = Pack((VOID *)SrcData.buf, SrcData.len, (VOID **)&DstBuf, &DstDataSize, 2);

  if (Status != EFI_SUCCESS) {
     PyErr_SetString(PyExc_Exception, "Failed to compress\n");
     goto ERROR;
  }
  
  PyBuffer_Release(&SrcData);
  return PyBytes_FromStringAndSize(DstBuf, DstDataSize);

ERROR:

  if (DstBuf != NULL) {
    free(DstBuf);
  }
  return NULL;
}

STATIC
PyObject*
lzmaf86decompress(
  PyObject    *Self,
  PyObject    *Args
)
{
  Py_buffer SrcData;
  UINT32        DstDataSize;
  EFI_STATUS    Status;
  char         *DstBuf;
  UINT32       x86State;

  DstBuf = NULL;
  x86State = 0;

  Status = PyArg_ParseTuple(
            Args,
            "y*",
            &SrcData
            );
  if (Status == 0) {
    return NULL;
  }

  DstDataSize = SrcData.len;
  DstBuf = (VOID *)malloc(DstDataSize);
  if (DstBuf == NULL) {
    Py_INCREF(Py_None);
    return Py_None;
  }
  memcpy(DstBuf, SrcData.buf, DstDataSize);

  x86_Convert_Init(x86State);
  x86_Convert(DstBuf, (SizeT)DstDataSize, 0, &x86State, 0);

  PyBuffer_Release(&SrcData);
  return PyBytes_FromStringAndSize(DstBuf, DstDataSize);
}

STATIC
PyObject*
lzmaf86compress(
  PyObject    *Self,
  PyObject    *Args
)
{
  Py_buffer SrcData;
  UINT32        DstDataSize;
  EFI_STATUS    Status;
  char         *DstBuf;
  UINT32       x86State;

  DstBuf = NULL;
  x86State = 0;

  Status = PyArg_ParseTuple(
            Args,
            "y*",
            &SrcData
            );
  if (Status == 0) {
    return NULL;
  }

  DstDataSize = SrcData.len;
  DstBuf = (VOID *)malloc(DstDataSize);
  if (DstBuf == NULL) {
    Py_INCREF(Py_None);
    return Py_None;
  }
  memcpy(DstBuf, SrcData.buf, DstDataSize);

  x86_Convert_Init(x86State);
  x86_Convert(DstBuf, (SizeT)DstDataSize, 0, &x86State, 1);

  PyBuffer_Release(&SrcData);
  return PyBytes_FromStringAndSize(DstBuf, DstDataSize);
}

STATIC char TDecompressDocs[] = "TianoDecompress(): Decompress data using Tiano standard algorithm\n";
STATIC char UDecompressDocs[] = "UefiDecompress(): Decompress data using UEFI standard algorithm\n";
STATIC char TCompressDocs[] = "TianoCompress(): Compress data using Tiano standard algorithm\n";
STATIC char UCompressDocs[] = "UefiCompress(): Compress data using UEFI standard algorithm\n";
STATIC char f86DecompressDocs[] = "Lzmaf86Decompress(): Decompress data using LZMA f86 standard algorithm\n";
STATIC char f86CompressDocs[] = "Lzmaf86Compress(): Compress data using LZMA f86 standard algorithm\n";


static PyMethodDef module_methods[] = {
  {"UefiDecompress", (PyCFunction)UefiDecompress, METH_VARARGS, UDecompressDocs},
  {"UefiCompress", (PyCFunction)UefiCompress, METH_VARARGS, UCompressDocs},
  {"TianoDecompress", (PyCFunction)FrameworkDecompress, METH_VARARGS, TDecompressDocs},
  {"TianoCompress", (PyCFunction)FrameworkCompress, METH_VARARGS, TCompressDocs},
  {"LZMAf86Decompress", (PyCFunction)lzmaf86decompress, METH_VARARGS, f86DecompressDocs},
  {"LZMAf86Compress", (PyCFunction)lzmaf86compress, METH_VARARGS, f86DecompressDocs},
  {NULL, NULL, 0, NULL}
};

static struct PyModuleDef EfiCompressor =
{
  PyModuleDef_HEAD_INIT,
  "EfiCompressor",
  "UEFI (de)compression algorithm module extension\n",
  -1,
  module_methods,
};

PyMODINIT_FUNC
PyInit_EfiCompressor(VOID) {
  return PyModule_Create(&EfiCompressor);
};


