#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2019, Intel Corporation
# 
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; Version 2.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Contact information:
#chipsec@intel.com
#
#This file incorporates work covered by the following copyright and permission notice
#
## @file
# GNU/Linux makefile for 'Common' module build.
#
# Copyright (c) 2007 - 2018, Intel Corporation. All rights reserved.<BR>
# This program and the accompanying materials
# are licensed and made available under the terms and conditions of the BSD License
# which accompanies this distribution.  The full text of the license may be found at
# http://opensource.org/licenses/bsd-license.php
#
# THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
# WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
#
MAKEROOT ?= ..

LIBNAME = Common

OBJECTS = \
  CommonLib.o \
  Decompress.o \
  EfiCompress.o \
  EfiUtilityMsgs.o \
  MemoryFile.o \
  ParseInf.o \
  TianoCompress.o \

include $(MAKEROOT)/Makefiles/lib.makefile
