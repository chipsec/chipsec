from lxml import etree
from typing import Any, Dict, List, Tuple

def parse_testsuite(tree: etree) -> Dict[Any, Any]:
    st = tree.xpath('//testsuites/testsuite')
    assert(len(st) == 1),"more than one test-suite in XML file"
    st = st[0]
    res = {}
    res.update(st.attrib)
    res.update(dict([(x.attrib['name'], x.attrib['value']) for x in st.iterfind('.//properties/property')]))
    return res

def parse_test_cases(tree: etree) -> List[Dict[Any, Any]]:
    st = tree.xpath('//testsuites/testsuite')[0]
    entries = []
    for case in st.iterfind('.//testcase'):
        res = {}
        res.update(case.attrib)
        res['pass'] = case.xpath('.//pass')[0].attrib['type']
        res['out'] = case.xpath('.//system-out')[0].text
        if res['out'] is not None:
            res['out'] = res['out']
        else:
            res['out'] = ""
        entries.append(res)
    return entries


def parse_chipsec_xml(fdlike: str) -> Tuple[Dict[Any, Any], List[Any]]:
    if isinstance(fdlike,str):
        fd = open(fdlike, 'rb')
    else:
        fd = fdlike

    tree = etree.parse(fd)
    suite_data = parse_testsuite(tree)
    cases_data = parse_test_cases(tree)
    return (suite_data, cases_data)


