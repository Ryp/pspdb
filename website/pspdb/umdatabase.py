"""Load disc SHA-1 matches from saved UMDatabase view pages (ID.html)."""
from html.parser import HTMLParser
from pathlib import Path
import re


class DiscPage(HTMLParser):
    def __init__(self):
        super().__init__()
        self.field = None
        self.capture = None
        self.parts = []
        self.sha1 = None
        self.name = ''

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'title' or (tag == 'p' and attrs.get('class') in ('text-subkey', 'text-value')):
            self.capture = 'title' if tag == 'title' else attrs['class']
            self.parts = []

    def handle_data(self, data):
        if self.capture:
            self.parts.append(data)

    def handle_endtag(self, tag):
        if not self.capture or tag not in ('title', 'p'):
            return
        value = ''.join(self.parts).strip()
        if self.capture == 'title':
            self.name = value
        elif self.capture == 'text-subkey':
            self.field = value
        elif self.field == 'SHA-1:':
            if self.sha1 is not None:
                raise ValueError('Multiple disc SHA-1 fields in UMDatabase page')
            if not re.fullmatch('[0-9a-fA-F]{40}', value):
                raise ValueError('Invalid UMDatabase disc SHA-1')
            self.sha1 = value.lower()
        if self.capture == 'text-value':
            self.field = None
        self.capture = None


def load_matches(source):
    source = Path(source)
    if not source.is_dir():
        raise ValueError('UMDatabase source must be a directory of ID.html pages')
    matches = {}
    for path in sorted(source.glob('*.html')):
        if not re.fullmatch('[0-9A-Fa-f]{8}', path.stem):
            raise ValueError(f'Invalid UMDatabase entry filename: {path.name}')
        page = DiscPage()
        page.feed(path.read_text(encoding='utf-8'))
        if page.sha1:
            match = dict(id=path.stem.upper(), name=page.name)
            group = matches.setdefault(page.sha1, [])
            if match not in group:
                group.append(match)
    return matches
