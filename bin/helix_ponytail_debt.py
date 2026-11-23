"""Deterministic comment debt from supplied text; no I/O, Git, models or clock."""
from bisect import bisect_right
from collections import Counter
import copy
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import PurePosixPath
import re
import tokenize

from helix_requirements import reject_secrets

RULES = {'version': '4.9.0', 'debt_sha256': 'c84fba75f0ca12bfe83f9a78ea02fd125c5dd3f1fbb18124105a489937f284e6'}
AREAS = ('active', 'docs', 'legacy', 'tests/examples', 'unknown')
EXECUTION = {'models': 0, 'application': False, 'credit': 0}
AGE_BASIS = 'last_changed_line_at_HEAD'
AGE_REASONS = frozenset(('NOT_PROVIDED', 'HEAD_LINE_CHANGED', 'SOURCE_DIRTY', 'UNTRACKED_OR_NONREGULAR',
    'SHALLOW_HISTORY', 'GIT_UNAVAILABLE', 'PARTIAL_CLONE', 'HEAD_CHANGED', 'BLOB_MISMATCH',
    'HISTORY_UNAVAILABLE', 'FUTURE_TIMESTAMP', 'BUDGET_EXHAUSTED', 'CONFIG_UNSUPPORTED'))
GAPS = frozenset(('READ_COVERAGE_INCOMPLETE', 'SOURCE_SNAPSHOT_EMPTY', 'SOURCE_HASH_MISMATCH', 'UNSUPPORTED_SOURCE_PATH',
    'SOURCE_NOT_SUPPLIED', 'SOURCE_NOT_IN_INVENTORY', 'PRIVACY_EXCLUDED', 'UNSUPPORTED_FILE_TYPE',
    'UNTERMINATED_STRING', 'UNTERMINATED_COMMENT', 'UNTERMINATED_REGEX', 'TEMPLATE_INTERPOLATION_UNSUPPORTED',
    'AMBIGUOUS_SLASH', 'JSX_UNSUPPORTED', 'PYTHON_TOKENIZATION_ERROR', 'UNTERMINATED_TAG',
    'UNTERMINATED_SCRIPT', 'MARKUP_EXPRESSION_UNSUPPORTED', 'SCRIPT_LANGUAGE_UNSUPPORTED', 'INVALID_JSON'))
ROW_FIELDS = {'id','file','line','end_line','source_area','source_sha256','comment_sha256','ceiling','upgrade_path',
              'tags','text_status','age_days','age_status','age_basis','last_changed_at','age_head','age_reason'}
COUNT_FIELDS = ('markers','no_trigger','no_ceiling','age_known','age_unknown','by_area')
PARSERS = {'python-tokenize','javascript-comments','css-comments','html-comments','component-comments','json-no-comments','unsupported','privacy-excluded','not-applicable','marker-absent'}
READ_GAPS = {'READ_COVERAGE_INCOMPLETE','SOURCE_SNAPSHOT_EMPTY','SOURCE_HASH_MISMATCH','SOURCE_NOT_SUPPLIED',
             'SOURCE_NOT_IN_INVENTORY','PRIVACY_EXCLUDED','UNSUPPORTED_SOURCE_PATH'}
MARKER = re.compile(r'(?<!\w)ponytail\s*:',re.I)
WORD = re.compile(r'[\w$]+')
NUMBER = re.compile(r'[\w.]+')
CSS_URL = re.compile(r'url\s*\(',re.I)


def _error():
    raise ValueError('ponytail debt: invalid or unbound report') from None


def _require(value):
    if not value: _error()


def _hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _digest(value):
    return _hash(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False))


def _path(value):
    return (isinstance(value,str) and 0 < len(value) <= 8192 and not any(c in value for c in '\\\x00\r\n')
            and not value.startswith('/') and '..' not in PurePosixPath(value).parts and str(PurePosixPath(value)) == value)


def _sha(value):
    return isinstance(value,str) and re.fullmatch(r'[0-9a-f]{64}',value) is not None


def _stamp(value):
    _require(isinstance(value,str))
    try: result = datetime.fromisoformat(value.replace('Z','+00:00'))
    except (ValueError,OverflowError): _error()
    _require(result.tzinfo is not None)
    return result.astimezone(timezone.utc)


def _area(file):
    from helix_owner_report import source_area
    return source_area(file)


def _privacy_path(file):
    from helix_audit_context import sensitive
    return any(sensitive(part) for part in PurePosixPath(file).parts)


def _sensitive(text):
    try: reject_secrets(text)
    except ValueError: return True
    # Short credentials and PII need not match the ledger's long-token rules.
    if '@' in text and re.search(r'(?i)(?<![\w.+-])[\w.+-]+@[\w.-]+\.[a-z]{2,}',text):return True
    return bool(re.search(r'(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)\s*[=:]|\bbearer\s+\S+|\bsk_(?:test|live)_\w+|https?://[^\s/]+:[^\s/]+@|(?:\+\d[\d ()-]{8,}\d)',text))


class _Comments:
    def __init__(self,text):
        self.text=text; self.newlines=[i for i,char in enumerate(text) if char=='\n']; self.tokens=[]; self.gaps=[]
    def line(self,offset): return 1+bisect_right(self.newlines,offset-1)
    def gap(self,offset,code): self.gaps.append({'line':self.line(offset),'code':code})
    def emit(self,start,end):
        text=self.text[start:end]
        if MARKER.search(text):self.tokens.append((start,end,text))
    def quoted(self,start,end,quote,allow_newlines=False):
        i=start+1
        while i<end:
            if self.text[i]=='\\': i+=2;continue
            if self.text[i]==quote:return i+1
            if not allow_newlines and quote!='`' and self.text[i] in '\r\n':self.gap(start,'UNTERMINATED_STRING');return end
            if quote=='`' and self.text.startswith('${',i):self.gap(start,'TEMPLATE_INTERPOLATION_UNSUPPORTED');return end
            i+=1
        self.gap(start,'UNTERMINATED_STRING');return end
    def block(self,i,end):
        close=self.text.find('*/',i+2,end)
        if close<0:self.gap(i,'UNTERMINATED_COMMENT');return end
        self.emit(i+2,close);return close+2
    def javascript(self,start=0,end=None):
        end=len(self.text) if end is None else end;i=start;regex_allowed=True;word=None;parens=[]
        while i<end:
            c=self.text[i]
            if c.isspace():i+=1;continue
            if self.text.startswith('//',i):
                close=self.text.find('\n',i+2,end);close=end if close<0 else close
                self.emit(i+2,close);i=close;continue
            if self.text.startswith('/*',i):i=self.block(i,end);continue
            if c in '\'"`':i=self.quoted(i,end,c);regex_allowed=False;word=None;continue
            if c=='/' and regex_allowed is None:self.gap(i,'AMBIGUOUS_SLASH');return
            if c=='/' and regex_allowed:
                origin=i;i+=1;char_class=False;closed=False
                while i<end:
                    if self.text[i]=='\\':i+=2;continue
                    if self.text[i] in '\r\n':break
                    if self.text[i]=='[':char_class=True
                    elif self.text[i]==']':char_class=False
                    elif self.text[i]=='/' and not char_class:
                        closed=True;i+=1
                        while i<end and self.text[i].isalpha():i+=1
                        break
                    i+=1
                if not closed:self.gap(origin,'UNTERMINATED_REGEX');return
                regex_allowed=False;word=None;continue
            if c=='<' and regex_allowed and i+1<end and (self.text[i+1].isalpha() or self.text[i+1] in '/>'):
                self.gap(i,'JSX_UNSUPPORTED');return
            if c.isalpha() or c in '_$':
                m=WORD.match(self.text,i,end);word=m[0];i=m.end()
                regex_allowed=word in {'return','throw','case','delete','void','typeof','yield','await','new','else','do','in','of'}
                continue
            if c.isdigit():
                m=NUMBER.match(self.text,i,end);i=m.end();regex_allowed=False;word=None;continue
            if c=='(':parens.append(word in {'if','while','for','with','switch','catch'});regex_allowed=True
            elif c==')':regex_allowed=parens.pop() if parens else None
            elif c=='}':regex_allowed=None
            elif c==']':regex_allowed=False
            elif c=='.':regex_allowed=False
            elif c in '+-' and i+1<end and self.text[i+1]==c:i+=1;regex_allowed=False
            else:regex_allowed=True
            word=None;i+=1
    def css(self,start=0,end=None):
        end=len(self.text) if end is None else end;i=start
        while i<end:
            if self.text.startswith('/*',i):i=self.block(i,end);continue
            if self.text[i] in '\'"':i=self.quoted(i,end,self.text[i]);continue
            match=CSS_URL.match(self.text,i,end) if self.text[i:i+3].lower()=='url' else None
            if match:
                origin=i;i+=len(match[0])
                while i<end and self.text[i]!=')':
                    if self.text[i] in '\'"':i=self.quoted(i,end,self.text[i])
                    else:i+=2 if self.text[i]=='\\' else 1
                if i>=end:self.gap(origin,'UNTERMINATED_STRING');return
            i+=1
    def markup(self,component=False):
        i=0;end=len(self.text)
        while i<end:
            if self.text.startswith('<!--',i):
                close=self.text.find('-->',i+4)
                if close<0:self.gap(i,'UNTERMINATED_COMMENT');return
                self.emit(i+4,close);i=close+3;continue
            if component and self.text[i]=='{':
                start=i;depth=1;i+=1
                while i<end and depth:
                    if self.text[i] in '\'"`':i=self.quoted(i,end,self.text[i]);continue
                    if self.text[i]=='{':depth+=1
                    elif self.text[i]=='}':depth-=1
                    i+=1
                self.gap(start,'MARKUP_EXPRESSION_UNSUPPORTED');continue
            if self.text[i]!='<':i+=1;continue
            start=i;i+=1
            while i<end and self.text[i]!='>':
                if self.text[i] in '\'"':i=self.quoted(i,end,self.text[i],True)
                else:i+=1
            if i>=end:self.gap(start,'UNTERMINATED_TAG');return
            head=self.text[start:i+1];i+=1
            tag=re.match(r'<(script|style|textarea|title|xmp|iframe|noembed|noframes|plaintext|noscript)\b',head,re.I)
            if not tag:continue
            if tag[1].lower()=='plaintext':return
            close=re.compile(r'</'+tag[1]+r'\s*>',re.I).search(self.text,i)
            if close is None:self.gap(start,'UNTERMINATED_SCRIPT');return
            stop=close.start()
            language=re.search(r'\b(?:lang|type)\s*=\s*[\'"]([^\'"]+)',head,re.I)
            if language and language[1].lower() not in {'ts','js','javascript','typescript','module','text/javascript','application/javascript','text/css','css'}:
                self.gap(start,'SCRIPT_LANGUAGE_UNSUPPORTED')
            elif tag[1].lower()=='script':self.javascript(i,stop)
            elif tag[1].lower()=='style':self.css(i,stop)
            elif tag[1].lower()=='noscript':self.gap(start,'SCRIPT_LANGUAGE_UNSUPPORTED')
            i=close.end()


def _comments(file,text):
    suffix=PurePosixPath(file).suffix.lower()
    if suffix in {'.md','.mdx','.rst','.txt','.json','.lock'} or PurePosixPath(file).name.endswith('-lock.json'):
        return _Comments(''),'not-applicable'
    if suffix in {'.py','.js','.ts','.mjs','.cjs','.jsx','.tsx','.css','.html','.htm','.svelte','.vue'} and not MARKER.search(text):
        return _Comments(''),'marker-absent'
    scanner=_Comments(text)
    if suffix=='.py':
        starts=[0]+[i+1 for i in scanner.newlines]
        try:
            for token in tokenize.generate_tokens(io.StringIO(text).readline):
                if token.type==tokenize.ERRORTOKEN and not token.string.isspace():
                    scanner.gap(starts[token.start[0]-1]+token.start[1],'PYTHON_TOKENIZATION_ERROR');break
                if token.type==tokenize.COMMENT:
                    scanner.emit(starts[token.start[0]-1]+token.start[1]+1,starts[token.end[0]-1]+token.end[1])
        except (tokenize.TokenError,IndentationError,SyntaxError):scanner.gap(0,'PYTHON_TOKENIZATION_ERROR')
        parser='python-tokenize'
    elif suffix in {'.js','.ts','.mjs','.cjs','.jsx','.tsx'}:scanner.javascript();parser='javascript-comments'
    elif suffix=='.css':scanner.css();parser='css-comments'
    elif suffix in {'.html','.htm','.svelte','.vue'}:
        scanner.markup(suffix in {'.svelte','.vue'});parser='component-comments' if suffix in {'.svelte','.vue'} else 'html-comments'
    elif suffix=='.json':
        try:json.loads(text)
        except (ValueError,RecursionError):scanner.gap(0,'INVALID_JSON')
        parser='json-no-comments'
    else:scanner.gap(0,'UNSUPPORTED_FILE_TYPE');parser='unsupported'
    return scanner,parser


def _fields(body):
    body=' '.join(re.sub(r'(?m)^\s*\* ?', '',body).strip().split())
    labels=list(re.finditer(r'(?:^|;)\s*(ceiling|upgrade)\s*:\s*',body,re.I))
    if labels:
        values={}
        for index,match in enumerate(labels):
            key=match[1].lower()
            if key in values:return None,None
            values[key]=body[match.end():labels[index+1].start() if index+1<len(labels) else len(body)].strip(' ;') or None
        return values.get('ceiling'),values.get('upgrade')
    ceiling,separator,upgrade=body.partition(',')
    return ceiling.strip() or None,upgrade.strip() or None if separator else None


def _unknown(row,reason='NOT_PROVIDED'):
    row.update(age_days=None,age_status='unknown',age_basis=AGE_BASIS,last_changed_at=None,age_head=None,age_reason=reason)


def _counts(rows):
    areas=Counter(row['source_area'] for row in rows)
    return dict(markers=len(rows),no_trigger=sum('no-trigger' in row['tags'] for row in rows),
                no_ceiling=sum('no-ceiling' in row['tags'] for row in rows),age_known=sum(row['age_status']=='known' for row in rows),
                age_unknown=sum(row['age_status']=='unknown' for row in rows),by_area={key:areas[key] for key in AREAS})


def debt(sources,coverage,*,observed_at,line_ages=None):
    try:
        _require(type(sources) is dict and all(isinstance(file,str) and isinstance(text,str) for file,text in sources.items()))
        observed=_stamp(observed_at).isoformat();rows=[];files=[];gaps=[];snapshot={}
        read_complete=type(coverage) is dict and coverage.get('status')=='COMPLETE'
        inventory=coverage.get('files',[]) if type(coverage) is dict else []
        _require(type(inventory) is list)
        supplied={}
        for item in inventory:
            _require(type(item) is dict)
            if not _path(item.get('file')):
                gaps.append(dict(file=None,line=None,code='UNSUPPORTED_SOURCE_PATH'));read_complete=False;continue
            _require(item['file'] not in supplied)
            supplied[item['file']]=item
        if not read_complete:gaps.append(dict(file=None,line=None,code='READ_COVERAGE_INCOMPLETE'))
        if not sources:gaps.append(dict(file=None,line=None,code='SOURCE_SNAPSHOT_EMPTY'));read_complete=False
        if type(coverage) is not dict or type(coverage.get('files_total')) is not int or type(coverage.get('files_read')) is not int or coverage.get('files_total')!=len(inventory) or coverage.get('files_read')!=len(sources):
            read_complete=False;gaps.append(dict(file=None,line=None,code='READ_COVERAGE_INCOMPLETE'))
        for file,item in supplied.items():
            if file not in sources:
                read_complete=False;gaps.append(dict(file=file,line=1,code='SOURCE_NOT_SUPPLIED'))
        for file,text in sorted(sources.items()):
            if not _path(file):
                gaps.append(dict(file=None,line=None,code='UNSUPPORTED_SOURCE_PATH'));read_complete=False;continue
            if _privacy_path(file):
                files.append(dict(file=file,source_sha256=None,source_area=_area(file),parser='privacy-excluded',status='INCOMPLETE'))
                gaps.append(dict(file=file,line=1,code='PRIVACY_EXCLUDED'));read_complete=False;continue
            digest=_hash(text);snapshot[file]=digest;item=supplied.get(file)
            if item is None:gaps.append(dict(file=file,line=1,code='SOURCE_NOT_IN_INVENTORY'));read_complete=False
            elif item.get('status')!='read' or item.get('sha256',digest)!=digest:
                gaps.append(dict(file=file,line=1,code='SOURCE_HASH_MISMATCH'));read_complete=False
            scanner,parser=_comments(file,text)
            files.append(dict(file=file,source_sha256=digest,source_area=_area(file),parser=parser,status='EXCLUDED' if parser=='not-applicable' else 'INCOMPLETE' if scanner.gaps else 'COMPLETE'))
            gaps.extend(dict(file=file,**gap) for gap in scanner.gaps)
            marker_index=0
            for start,end,comment in scanner.tokens:
                matches=list(MARKER.finditer(comment));hidden=_sensitive(comment)
                for index,match in enumerate(matches):
                    finish=matches[index+1].start() if index+1<len(matches) else len(comment)
                    raw=comment[match.start():finish];body=comment[match.end():finish];ceiling,upgrade=_fields(body)
                    line=scanner.line(start+match.start());end_line=scanner.line(start+finish-len(raw)+len(raw.rstrip()))
                    fingerprint=_hash(raw);marker_index+=1
                    tags=[]
                    if not ceiling:tags.append('no-ceiling')
                    if not upgrade:tags.append('no-trigger')
                    if hidden:ceiling=upgrade=None;tags.append('redacted')
                    row=dict(id='debt-'+_digest([file,marker_index,line,fingerprint])[:20],file=file,line=line,end_line=max(line,end_line),
                             source_area=_area(file),source_sha256=digest,comment_sha256=fingerprint,ceiling=ceiling,upgrade_path=upgrade,
                             tags=sorted(tags),text_status='redacted' if hidden else 'recorded')
                    _unknown(row);rows.append(row)
        gaps=sorted({(gap['file'],gap['line'],gap['code']) for gap in gaps},key=lambda v:(v[0] or '',v[1] or 0,v[2]))
        gaps=[dict(file=file,line=line,code=code) for file,line,code in gaps]
        comment_complete=all(row['status'] in ('COMPLETE','EXCLUDED') for row in files) and bool(files) and not any(gap['code']=='UNSUPPORTED_SOURCE_PATH' for gap in gaps)
        result=dict(schema_version=1,kind='ponytail-debt',status='COMPLETE' if read_complete and comment_complete else 'INCOMPLETE',
                    rules=dict(RULES),source_digest=_digest(snapshot),observed_at=observed,
                    coverage=dict(read_status='COMPLETE' if read_complete else 'INCOMPLETE',comment_status='COMPLETE' if comment_complete else 'INCOMPLETE',files=files,gaps=gaps),
                    counts=_counts(rows),rows=rows,execution=dict(EXECUTION))
        return with_line_ages(result,line_ages,observed_at=observed) if line_ages is not None else project_debt(result)
    except (KeyError,TypeError,ValueError,AttributeError,UnicodeError,RecursionError):_error()


def with_line_ages(report,line_ages,*,observed_at):
    try:
        result=project_debt(report);_require(result['status']!='NOT_RECORDED' and type(line_ages) is list)
        now=_stamp(observed_at);result['observed_at']=now.isoformat();records={}
        for item in line_ages:
            _require(type(item) is dict and set(item)=={'file','line','source_sha256','head','status','changed_at','reason'}
                     and _path(item['file']) and type(item['line']) is int and item['line']>0
                     and item['status'] in ('known','unknown') and item['reason'] in AGE_REASONS)
            key=(item['file'],item['line']);_require(key not in records);records[key]=item
        for row in result['rows']:
            _unknown(row);item=records.get((row['file'],row['line']))
            if item is None:continue
            if item['source_sha256']!=row['source_sha256']:_unknown(row,'BLOB_MISMATCH');continue
            if item['status']=='unknown':_unknown(row,item['reason']);continue
            if not isinstance(item['head'],str) or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}',item['head']):_unknown(row,'HISTORY_UNAVAILABLE');continue
            try:changed=_stamp(item['changed_at'])
            except ValueError:_unknown(row,'HISTORY_UNAVAILABLE');continue
            if changed>now:_unknown(row,'FUTURE_TIMESTAMP');continue
            if item['reason']!='HEAD_LINE_CHANGED':_unknown(row,'HISTORY_UNAVAILABLE');continue
            row.update(age_days=(now-changed).days,age_status='known',age_basis=AGE_BASIS,last_changed_at=changed.isoformat(),age_head=item['head'],age_reason='HEAD_LINE_CHANGED')
        result['counts']=_counts(result['rows']);return project_debt(result)
    except (KeyError,TypeError,ValueError,AttributeError,UnicodeError,OverflowError):_error()


def project_debt(report):
    """Idempotent, strict public projection; missing legacy data stays unknown."""
    legacy=dict(schema_version=1,kind='ponytail-debt',status='NOT_RECORDED',rules=dict(RULES),source_digest=None,observed_at=None,
                coverage=dict(read_status='NOT_RECORDED',comment_status='NOT_RECORDED',files=[],gaps=[]),
                counts={key:None for key in COUNT_FIELDS},rows=[],execution=dict(EXECUTION))
    if report is None:return legacy
    try:
        _require(type(report) is dict and set(report)==set(legacy))
        if report.get('status')=='NOT_RECORDED':_require(_digest(report)==_digest(legacy));return copy.deepcopy(legacy)
        _require(type(report['schema_version']) is int and report['schema_version']==1 and report['kind']=='ponytail-debt'
                 and report['rules']==RULES and _digest(report['execution'])==_digest(EXECUTION) and _sha(report['source_digest']))
        now=_stamp(report['observed_at']);coverage=report['coverage']
        _require(type(coverage) is dict and set(coverage)=={'read_status','comment_status','files','gaps'}
                 and all(coverage[key] in ('COMPLETE','INCOMPLETE') for key in ('read_status','comment_status'))
                 and type(coverage['files']) is list and type(coverage['gaps']) is list and type(report['rows']) is list)
        files={};snapshot={}
        for file in coverage['files']:
            _require(type(file) is dict and set(file)=={'file','source_sha256','source_area','parser','status'}
                     and _path(file['file']) and file['file'] not in files and file['source_area']==_area(file['file'])
                     and file['parser'] in PARSERS and file['status'] in ('COMPLETE','INCOMPLETE','EXCLUDED'))
            _require((file['status']=='EXCLUDED')==(file['parser']=='not-applicable'))
            _require(_sha(file['source_sha256']) or file['source_sha256'] is None and file['parser']=='privacy-excluded')
            files[file['file']]=file
            if file['source_sha256'] is not None:snapshot[file['file']]=file['source_sha256']
        _require(report['source_digest']==_digest(snapshot))
        for gap in coverage['gaps']:
            _require(type(gap) is dict and set(gap)=={'file','line','code'} and gap['code'] in GAPS
                     and (gap['file'] is None and gap['line'] is None or _path(gap['file']) and type(gap['line']) is int and gap['line']>0))
        codes={gap['code'] for gap in coverage['gaps']}
        _require(coverage['read_status']=='INCOMPLETE' if codes & READ_GAPS else coverage['read_status']=='COMPLETE')
        for file in files.values():
            lexical=any(gap['file']==file['file'] and (gap['code'] not in READ_GAPS or gap['code']=='PRIVACY_EXCLUDED') for gap in coverage['gaps'])
            _require((file['status']=='INCOMPLETE')==lexical)
        _require(coverage['comment_status']==('COMPLETE' if files and all(f['status'] in ('COMPLETE','EXCLUDED') for f in files.values()) and 'UNSUPPORTED_SOURCE_PATH' not in codes else 'INCOMPLETE'))
        _require(report['status']==('COMPLETE' if coverage['read_status']==coverage['comment_status']=='COMPLETE' else 'INCOMPLETE'))
        indexes=Counter();seen=set();last=None
        for row in report['rows']:
            _require(type(row) is dict and set(row)==ROW_FIELDS and row['file'] in files)
            file=files[row['file']];_require(row['source_area']==file['source_area'] and row['source_sha256']==file['source_sha256']
                and _sha(row['comment_sha256']) and type(row['line']) is int and row['line']>0 and type(row['end_line']) is int and row['end_line']>=row['line'])
            position=(row['file'],row['line']);_require(last is None or position>=last);last=position;indexes[row['file']]+=1
            _require(row['id']=='debt-'+_digest([row['file'],indexes[row['file']],row['line'],row['comment_sha256']])[:20] and row['id'] not in seen);seen.add(row['id'])
            _require(type(row['tags']) is list and row['tags']==sorted(set(row['tags'])) and set(row['tags']).issubset({'redacted','no-trigger','no-ceiling'}))
            if row['text_status']=='redacted':_require(row['ceiling'] is None and row['upgrade_path'] is None and 'redacted' in row['tags'])
            else:
                _require(row['text_status']=='recorded' and 'redacted' not in row['tags'])
                for key in ('ceiling','upgrade_path'):_require(row[key] is None or isinstance(row[key],str) and row[key].strip()==row[key] and bool(row[key]) and not _sensitive(row[key]))
                _require(('no-ceiling' in row['tags'])==(row['ceiling'] is None) and ('no-trigger' in row['tags'])==(row['upgrade_path'] is None))
            _require(row['age_basis']==AGE_BASIS and row['age_reason'] in AGE_REASONS)
            if row['age_status']=='known':
                changed=_stamp(row['last_changed_at'])
                _require(type(row['age_days']) is int and row['age_days']>=0 and changed<=now and row['age_days']==(now-changed).days
                         and isinstance(row['age_head'],str) and re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}',row['age_head']) and row['age_reason']=='HEAD_LINE_CHANGED')
            else:_require(row['age_status']=='unknown' and all(row[key] is None for key in ('age_days','last_changed_at','age_head')))
        _require(_digest(report['counts'])==_digest(_counts(report['rows'])))
        reject_secrets(report)
        return copy.deepcopy(report)
    except (KeyError,TypeError,ValueError,AttributeError,UnicodeError,RecursionError,OverflowError):_error()
