#!/usr/bin/env python3
"""檢查 README.md 與 docs/ 下所有 Markdown 的相對連結、錨點與 YAML 範例。

以 GitHub 的錨點規則產生標題 slug；發現任何問題即以非 0 結束（供 CI 使用）。
"""
import os
import re
import sys
import unicodedata

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def slug(heading):
    heading = re.sub(r'`', '', heading.strip().lower())
    out = ''
    for ch in heading:
        category = unicodedata.category(ch)
        if ch in ' -_' or category[0] in 'LN' or category == 'Mn':
            out += ch
    return out.replace(' ', '-')


def strip_code(text):
    return re.sub(r'```.*?```', '', text, flags=re.S)


def markdown_files():
    files = [os.path.join(ROOT, 'README.md')]
    for dirpath, _, names in os.walk(os.path.join(ROOT, 'docs')):
        files += [os.path.join(dirpath, n) for n in names if n.endswith('.md')]
    return [os.path.normpath(f) for f in files]


def main():
    files = markdown_files()
    anchors = {}
    for f in files:
        text = strip_code(open(f, encoding='utf-8').read())
        anchors[f] = {slug(h) for h in re.findall(r'^#{1,6}\s+(.*)$', text, re.M)}

    problems = []
    for f in files:
        rel = os.path.relpath(f, ROOT)
        raw = open(f, encoding='utf-8').read()
        for match in re.finditer(r'\]\(([^)\s]+)\)', strip_code(raw)):
            link = match.group(1)
            if link.startswith(('http://', 'https://', 'mailto:')):
                continue
            path, _, anchor = link.partition('#')
            target = os.path.normpath(os.path.join(os.path.dirname(f), path)) if path else f
            if not os.path.exists(target):
                problems.append(f'{rel}: missing file {link}')
            elif anchor and target.endswith('.md') and anchor not in anchors.get(target, set()):
                problems.append(f'{rel}: missing anchor {link}')
        for block in re.findall(r'```yaml\n(.*?)```', raw, re.S):
            try:
                yaml.safe_load(block)
            except yaml.YAMLError as error:
                problems.append(f'{rel}: invalid YAML block: {error}'.splitlines()[0])

    for problem in problems:
        print(problem)
    print(f'checked {len(files)} files, {len(problems)} problem(s)')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
