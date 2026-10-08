#!/usr/bin/env python3
"""檢查 pom.xml 是否自行宣告了 <licenses>（project 的直接子元素），供發佈流程使用。

以 XML 解析，註解與其他元素中的文字不會被誤認為宣告；繼承自 parent 的授權條款不算。
有宣告且至少有一個 <license><name> 時以 0 結束，否則以 1 結束。
"""
import sys
import xml.etree.ElementTree as ET

NS = {'m': 'http://maven.apache.org/POM/4.0.0'}


def main(path):
    root = ET.parse(path).getroot()
    names = [n.text for n in root.findall('m:licenses/m:license/m:name', NS) if n.text and n.text.strip()]
    if names:
        print('declared licenses: ' + ', '.join(names))
        return 0
    print(f'{path}: no <licenses> declared in the project')
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else 'pom.xml'))
