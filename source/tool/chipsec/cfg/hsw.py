#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2014, Intel Corporation
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



# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
# (c) 2010 - 2012 Intel Corporation
#
# -------------------------------------------------------------------------------
## \addtogroup config
# __chipsec/cfg/hsw.py__ - configuration specific for Haswell Platforms
#
# Add configuration specific to Haswell based platform to this module
# On Haswell platforms, configuraion from this file will override configuration from cfg.common
#
__version__ = '1.0'


from chipsec.cfg.common import Cfg
class hsw(Cfg):
    def __init__(self):
        Cfg.__init__(self)

    ##############################################################################
    # CPU configuration
    ##############################################################################
    #Cfg.KEY = VALUE
    
    ##############################################################################
    # PCH configuration
    ##############################################################################
    #Cfg.KEY = VALUE
    
