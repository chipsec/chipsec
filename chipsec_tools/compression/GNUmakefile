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

## @file
#  GNU/Linux makefile for C tools build.
#
#  Copyright (c) 2007 - 2017, Intel Corporation. All rights reserved.<BR>
#
#  This program and the accompanying materials
#  are licensed and made available under the terms and conditions of the BSD License
#  which accompanies this distribution.  The full text of the license may be found at
#  http://opensource.org/licenses/bsd-license.php
#
#  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
#  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
#

ifndef HOST_ARCH
  #
  # If HOST_ARCH is not defined, then we use 'uname -m' to attempt
  # try to figure out the appropriate HOST_ARCH.
  #
  uname_m = $(shell uname -m)
  $(info Attempting to detect HOST_ARCH from 'uname -m': $(uname_m))
  ifneq (,$(strip $(filter $(uname_m), x86_64 amd64)))
    HOST_ARCH=X64
  endif
  ifeq ($(patsubst i%86,IA32,$(uname_m)),IA32)
    HOST_ARCH=IA32
  endif
  ifneq (,$(findstring aarch64,$(uname_m)))
    HOST_ARCH=AARCH64
  endif
  ifneq (,$(findstring arm,$(uname_m)))
    HOST_ARCH=ARM
  endif
  ifndef HOST_ARCH
    $(info Could not detected HOST_ARCH from uname results)
    $(error HOST_ARCH is not defined!)
  endif
  $(info Detected HOST_ARCH of $(HOST_ARCH) using uname.)
endif

export HOST_ARCH

MAKEROOT = .

include Makefiles/header.makefile

all: makerootdir subdirs
	@echo Finished building BaseTools C Tools with HOST_ARCH=$(HOST_ARCH)

LIBRARIES = Common
VFRAUTOGEN = VfrCompile/VfrLexer.h
APPLICATIONS = \
  Brotli \
  LZMA \
  Tiano 

SUBDIRS := $(LIBRARIES) $(APPLICATIONS)

$(LIBRARIES): $(MAKEROOT)/libs
$(APPLICATIONS): $(LIBRARIES) $(MAKEROOT)/bin

.PHONY: outputdirs
makerootdir:
	-mkdir -p $(MAKEROOT)

.PHONY: subdirs $(SUBDIRS)
subdirs: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@

.PHONY: $(patsubst %,%-clean,$(sort $(SUBDIRS)))
$(patsubst %,%-clean,$(sort $(SUBDIRS))):
	-$(MAKE) -C $(@:-clean=) clean

clean:  $(patsubst %,%-clean,$(sort $(SUBDIRS)))

clean: localClean

localClean:
	rm -f $(MAKEROOT)/bin/*
	-rmdir $(MAKEROOT)/libs $(MAKEROOT)/bin

include Makefiles/footer.makefile
