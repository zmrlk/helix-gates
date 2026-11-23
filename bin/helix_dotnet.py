"""Static .NET declarations; no MSBuild evaluation, SDK loading or target code."""
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

PROJECT_SUFFIXES = frozenset({'.csproj', '.fsproj', '.vbproj'})
SOURCE_SUFFIXES = frozenset({'.cs', '.fs', '.fsx', '.vb'})


def relevant(path):
    path = Path(path)
    return path.suffix.lower() in PROJECT_SUFFIXES or path.name == 'global.json'


def declarations(path, text):
    """Return version declarations plus explicit unknowns, not runtime proof."""
    rows, errors = [], []
    def error(reason):
        errors.append(dict(path=path, reason=reason))
    if Path(path).name == 'global.json':
        try:
            sdk = json.loads(text).get('sdk', {})
            version = sdk.get('version')
            if isinstance(version, str) and re.fullmatch(r'\d+\.\d+\.\d+(?:-[\w.-]+)?', version):
                rows.append(dict(component='dotnet-sdk', version=version, line=1, kind='sdk_pin'))
            else:
                error('Nieznana wersja SDK .NET w global.json')
        except (ValueError, AttributeError):
            error('Niepoprawny global.json')
        return rows, errors
    if Path(path).suffix.lower() not in PROJECT_SUFFIXES:
        return rows, errors
    try:
        if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
            raise ValueError('DTD not interpreted')
        root = ET.fromstring(text)
    except (ET.ParseError, ValueError):
        error('Niepoprawny lub niewspierany XML projektu .NET')
        return rows, errors
    found = False
    for node in root.iter():
        tag = node.tag.rsplit('}', 1)[-1]
        if tag not in {'TargetFramework', 'TargetFrameworks', 'TargetFrameworkVersion'}:
            continue
        found = True
        for raw in (node.text or '').split(';'):
            raw = raw.strip()
            component = version = None
            if tag == 'TargetFrameworkVersion' and re.fullmatch(r'v?\d+(?:\.\d+){1,2}', raw):
                component, version = 'dotnet-framework', raw.removeprefix('v')
            elif match := re.fullmatch(r'(netstandard|netcoreapp|net)(\d+\.\d+)(?:-[\w.]+)?', raw):
                component = 'dotnet-standard' if match[1] == 'netstandard' else 'dotnet-runtime'
                version = match[2]
            elif match := re.fullmatch(r'net([1-4]\d{1,2})', raw):
                component, version = 'dotnet-framework', '.'.join(match[1])
            if component:
                line = text[:text.find(raw)].count('\n') + 1
                rows.append(dict(component=component, version=version, line=line,
                                 kind='target_framework', selector=raw))
            else:
                error('Nierozpoznany TargetFramework; MSBuild nie był wykonywany')
    if not found:
        error('Brak lokalnej deklaracji TargetFramework; importy MSBuild nie były wykonywane')
    return rows, errors
