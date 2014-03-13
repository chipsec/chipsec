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



import time
import sys
import traceback
import os
from os.path import basename

import xml.etree.ElementTree as ET
import platform
import xml.dom.minidom


class xmlAux:
    """Used to represent the variables to handle the xml output."""
    def __init__(self):
        """The Constructor."""
        self.test_cases = []
        self.useXML     = False
        self.testCase   = None
        self.class_name = None
        self.xmlFile    = None
        self.xmlStdout  = ""
        self.xmlStderr  = None
        self.properties = []

    def add_test_suite_property(self, name, value):
        """Adds a <property> child node to the <testsuite>."""
        if name is not None and value is not None:
            self.properties.append( ts_property( str(name).strip(), str(value).strip() ) )

    def set_xml_file(self, name):
        """Sets the filename used for the XML output."""
        if name != None:
            self.useXML = True
            self.xmlFile = name

    def append_stdout(self,msg):
        self.xmlStdout += str(msg) + "\n"

    def _check_testCase_exist(self):
        if self.testCase is None:
            if self.class_name is None:
                self.testCase = xmlTestCase( "test name", "class.name" )
            else:
                self.testCase = xmlTestCase( self.class_name, self.class_name )
                
    def _end_test(self):
        try:
            self.testCase.set_time()
            self.testCase.add_stdout_info( self.xmlStdout )
            self.test_cases.append( self.testCase )
            self.testCase = None
        except:
            print "Unexpected error:", sys.exc_info() [0]
            raise

    def passed_check(self):
        """Used when you want to mark a testcase as PASS and add it to the testsuite."""
        if self.useXML == True:
            self._check_testCase_exist()
            self._end_test()

    def failed_check(self, text):
        """Used when you want to mark a testcase as FAILURE and add it to the testsuite."""
        if self.useXML == True:
            self._check_testCase_exist()
            self.testCase.add_failure_info( text, None )
            self._end_test()

    def error_check(self, text):
        """Used when you want to mark a testcase as ERROR and add it to the testsuite."""
        if self.useXML == True:
            self._check_testCase_exist()
            self.testCase.add_error_info( text, None )
            self._end_test()

    def skipped_check(self, text):
        """Used when you want to mark a testcase as SKIPPED and add it to the testsuite."""
        if self.useXML == True:
            self._check_testCase_exist()
            self.testCase.add_skipped_info( text, None )
            self._end_test()

    def start_test(self, test_name):
        """Starts the test/testcase."""
        self.xmlStdout = ""
        if self.useXML == True:
            self.testCase = xmlTestCase( test_name, self.class_name )

    def start_module( self, module_name ):
        """Logs the start point of a Test, this is used for XML output.
           If XML file was not specified, it will just display a banner for the test name.
        """
        if self.useXML == True:
            self.class_name = module_name
            if self.testCase is not None:
                #If there's a test that did not send a status, so mark it as passed.
                self.passed_check( )
        self.xmlStdout = ""

    def end_module( self, module_name ):
        if self.useXML == True:
            self.class_name = ""
            if self.testCase is not None:
                #If there's a test that did not send a status, so mark it as passed.
                self.passed_check( )
        self.xmlStdout = ""

    def saveXML( self ):
        """Saves the XML info to a file in a JUnit style."""
        try:
            if self.useXML == True:
                if self.xmlFile is not None:
                    filename = self.xmlFile.replace("'", "")
                    filename2 = filename.replace(" ", "")
                    if filename2 in ["", " "]:
                        print "filename for XML received empty or invalid string. So skipping writing to a file."
                        return
                    ts = xmlTestSuite( basename( os.path.splitext(filename)[0] ) )
                    ts.test_cases = self.test_cases
                    if self.properties is not None and len( self.properties ) > 0:
                        ts.properties = self.properties
                else:
                    print "xmlFile is None. So skipping writing to a file."
                    return
                print "\nSaving XML to file : " + str( filename )
                ts.to_file( filename )
        except:
            print "Unexpected error : ", sys.exc_info() [0]
            print traceback.format_exc()
            raise

class testCaseType:
    """Used to represent the types of TestCase that can be assigned (FAILURE, ERROR, SKIPPED, PASS)"""
    FAILURE = 1
    ERROR   = 2
    SKIPPED = 3
    PASS    = 4

class xmlTestCase():
    """Represents a JUnit test case with a result and possibly some stdout or stderr"""

    def __init__(self, name, classname, pTime=None, stdout=None, stderr=None, tcType=None, message=None, output=None):
        """The Constructor"""
        self.name      = name
        self.time      = None
        self.startTime = time.time()
        self.endTime   = None
        if pTime is not None:
            self.time  = pTime
        self.stdout    = stdout
        self.stderr    = stderr
        self.classname = classname
        self.tcType    = tcType
        self.tcMessage = message
        self.tcOutput  = output
        #Just to be compatible with junit_xml
        self.error_message   = ""
        self.error_output    = ""
        self.failure_message = ""
        self.failure_output  = ""
        self.skipped_message = ""
        self.skipped_output  = ""

        if tcType == testCaseType.ERROR:
            self.error_message = message
            self.error_output  = output
        elif tcType == testCaseType.FAILURE:
            self.failure_message = message
            self.failure_output  = output
        elif tcType == testCaseType.SKIPPED:
            self.skipped_message = message
            self.skipped_output  = output
        else:
            #Then it should be PASSED.
            self.tcType = testCaseType.PASS

    def is_skipped(self):
        """Returns True if the testCase is of Type Skipped, if not returns False"""
        if self.tcType == testCaseType.SKIPPED:
            return True
        else:
            False

    def is_error(self):
        """Returns True if the testCase is of Type Error, if not returns False"""
        if self.tcType == testCaseType.ERROR:
            return True
        else:
            False

    def is_failure(self):
        """Returns True if the testCase is of Type Failure, if not returns False"""
        if self.tcType == testCaseType.FAILURE:
            return True
        else:
            False

    def is_pass(self):
        """Returns True if the testCase is of Type Pass, if not returns False."""
        if self.tcType not in [testCaseType.ERROR, testCaseType.FAILURE, testCaseType.SKIPPED] or self.tcType == testCaseType.PASS:
            return True
        else:
            False

    def add_failure_info(self, message=None, output=None):
        """Sets the values for the corresponding Type Failure."""
        self.tcType          = testCaseType.FAILURE
        self.tcMessage       = message
        self.tcOutput        = output
        #To be compatible with junit_xml
        self.failure_message = message
        self.failure_output  = output

    def add_error_info(self, message=None, output=None):
        """Sets the values for the corresponding Type Error."""
        self.tcType        = testCaseType.ERROR
        self.tcMessage     = message
        self.tcOutput      = output
        #To be compatible with junit_xml
        self.error_message = message
        self.error_output  = output

    def add_skipped_info(self, message=None, output=None):
        """Sets the values for the corresponding Type Skipped."""
        self.tcType          = testCaseType.SKIPPED
        self.tcMessage       = message
        self.tcOutput        = output
        #To be compatible with junit_xml
        self.skipped_message = message
        self.skipped_output  = output

    def add_stdout_info(self, text):
        """Adds the text that is going to be part of the stdout for the TestCase."""
        if self.stdout is not None:
            self.stdout += str(text)
        else:
            self.stdout = str(text)

    def add_stderr_info(self, text):
        """Adds the text that is going to be part of the stderr for the TestCase."""
        if self.stderr is not None:
            self.stderr += str(text)
        else:
            self.stderr = str(text)

    def set_time(self, pTime=None):
        """Sets the time"""
        if pTime is not None:
            self.time = pTime
        else:
            self.endTime = time.time()
            self.time = self.endTime - self.startTime


class xmlTestSuite(object):
    """Suite of test cases, it's the father node for TestCase."""

    def __init__(self, name, test_cases=None, hostname=None, ts_id=None, package=None, timestamp=None, properties=None):
        """The Constructor."""
        self.name       = name
        if not test_cases:
            test_cases  = []
        self.test_cases = test_cases
        self.hostname   = hostname
        self.ts_id      = ts_id
        self.package    = package
        self.timestamp  = timestamp
        self.properties = properties

    def to_xml_string(self):
        """Returns the string representation of the JUnit XML document."""
        try:
            iter( self.test_cases )
        except TypeError:
            raise Exception('test_suite has no test cases')

        strXML = TestSuite.to_xml_string( TestSuite(self.name,       self.test_cases, 
                                                     self.hostname,  self.ts_id, self.package, 
                                                     self.timestamp, self.properties) 
                                          )
        return strXML

    def to_file(self, file_name):
        """Writes the JUnit XML document to a file.
           In case of any error, it will print the exception information.
        """
        try:
            with open( file_name, 'w') as f :
                #f.write( '<?xml-stylesheet type="text/xsl" href="junit.xsl"?>' )
                f.write( self.to_xml_string() )
        except:
            print "Unexpected error : ", sys.exc_info() [0]
            print traceback.format_exc()


class ts_property(object):
    """Class to represent a TestSuite property."""
    def __init__(self, name, value):
        """The constructor."""
        self.name  = name
        self.value = value


class TestSuite(object):
    """Suite of test cases"""

    def __init__(self, name, test_cases, hostname, ts_id, package, timestamp, properties):
        self.name       = name
        if not test_cases:
            test_cases  = []
        try:
            iter( test_cases )
        except:
            pass
        self.test_cases = test_cases
        self.hostname   = hostname
        self.ts_id      = ts_id
        self.package    = package
        self.timestamp  = timestamp
        if not properties:
            self.properties = []
        else:
            self.properties = properties


    def build_xml(self):
        """Builds the XML elements."""
        ts_attributes                  = dict()
        if self.name:
            ts_attributes["name"]      = str( self.name )
        else:
            ts_attributes["name"]      = "name"
        if self.hostname:
            ts_attributes["hostname"]  = str( self.hostname )
        if self.ts_id:
            ts_attributes["id"]        = str( self.ts_id )
        if self.package:
            ts_attributes["package"]   = str( self.package )
        if self.timestamp:
            ts_attributes["timestamp"] = str( self.timestamp )

        ts_attributes['failures']      = str( len( [tc for tc in self.test_cases if tc.is_failure()] ) )
        ts_attributes['errors']        = str( len( [tc for tc in self.test_cases if tc.is_error()] ) )
        ts_attributes['skipped']       = str( len( [tc for tc in self.test_cases if tc.is_skipped()] ) )
        #ts_attributes["time"]          = str( sum( [tc.time for tc in self.test_cases if tc.time] ) )
        ts_attributes["time"]          = "%.5f" % sum( [tc.time for tc in self.test_cases if tc.time] )
        ts_attributes["tests"]         = str( len( self.test_cases ) )

        xml_element = ET.Element( "testsuite", ts_attributes )

        if len(self.properties) > 0:
            ps_element = ET.SubElement( xml_element, "properties" )
            temp = dict()
            for p in self.properties:
                temp["name"]  = p.name
                temp["value"] = p.value
                py_element = ET.SubElement( ps_element, "property", temp )

        for tc in self.test_cases:
            tc_attributes = dict()
            tc_attributes['name'] = str( tc.name )
            if tc.time:
                tc_attributes['time'] = "%.5f" % tc.time
            if tc.classname:
                tc_attributes['classname'] = str( tc.classname )

            tc_element = ET.SubElement( xml_element, "testcase", tc_attributes )

            #For the is_pass() case, there is nothing special, so we do nothing and process once.
            if tc.is_pass():
                pass
            elif tc.is_failure():
                failure_element = ET.SubElement( tc_element, "failure", {'type': 'failure'} )
                if tc.failure_message:
                    failure_element.set( 'message', tc.failure_message )
                if tc.failure_output:
                    failure_element.text = tc.failure_output
            elif tc.is_error():
                error_element = ET.SubElement( tc_element, "error", {'type': 'error'} )
                if tc.error_message:
                    error_element.set( 'message', tc.error_message )
                if tc.error_output:
                    error_element.text = tc.error_output
            elif tc.is_skipped():
                skipped_element = ET.SubElement( tc_element, "skipped", {'type': 'skipped'} )
                if tc.skipped_message:
                    skipped_element.set( 'message', tc.skipped_message )
                if tc.skipped_output:
                    skipped_element.text = tc.skipped_output

            #system-out and system-err are common for all, so here we go.
            if tc.stdout:
                stdout_element = ET.SubElement( tc_element, "system-out" )
                stdout_element.text = tc.stdout
            if tc.stderr:
                stderr_element = ET.SubElement( tc_element, "system-err" )
                stderr_element.text = tc.stderr

        return xml_element


    def to_xml_string(self):
        """Returns a string representation of the XML Tree for the TestSuite."""
        xml_element  = ET.Element("testsuites")
        xml_element2 = self.build_xml()
        xml_element.append( xml_element2 )
        xml_string = ET.tostring( xml_element, None, None )

        if platform.system().lower() in ["windows", "linux"]:
            xml_string = xml.dom.minidom.parseString(xml_string).toprettyxml()

        return xml_string

