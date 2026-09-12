"""Independent structural/wording oracle for generated HTML, not authentication."""
from html.parser import HTMLParser


class Scan(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids=[];self.dimensions=[];self.decisions=[];self.records=[];self.evidence_links=[];self.withheld=0
        self.tags=[];self.text=[];self.scripts=[];self.styles=[];self.current=None;self.active=[];self.errors=[]
    def handle_starttag(self,tag,attrs):
        a=dict(attrs);self.tags.append((tag,a));self.active.append(tag)
        if 'id' in a:self.ids.append(a['id'])
        if 'data-dimension' in a:self.dimensions.append((a['data-dimension'],a.get('data-state'),a.get('data-basis')))
        if 'data-decision' in a:self.decisions.append(a['data-decision']);self.records.append(a.get('data-record'))
        if a.get('class')=='withheld':self.withheld+=1
        if tag=='a' and a.get('class')=='evidence-link':self.evidence_links.append(a.get('href'))
        if tag in ('script','style'):self.current=tag
        if tag in ('img','iframe','object','embed','base') or any(k.startswith('on') for k in a):self.errors.append('unsafe markup')
        if tag in ('script','link') and any(k in a for k in ('src','href')):self.errors.append('external resource')
    def handle_endtag(self,tag):
        if tag==self.current:self.current=None
    def handle_data(self,data):
        if self.current=='script':self.scripts.append(data)
        elif self.current=='style':self.styles.append(data)
        else:self.text.append(data)


def audit_html(payload,bundle):
    scan=Scan();scan.feed(payload.decode()); errors=list(scan.errors)
    dims=bundle['capsule']['dimensions'];expected=[(d['dimension_id'],d['status'],d['basis']) for d in dims]
    if scan.dimensions!=expected:errors.append('dimension states differ')
    if scan.withheld!=5:errors.append('withheld inventory differs')
    decisions=[];records=[]
    for d in dims:
        for i in d['items']:
            decisions.append(i['decision']['status'] if i['decision'] else 'descriptive' if i['applicability']['state']=='observed' else i['applicability']['state'])
            records.append(i['record_ref'])
    if scan.decisions!=decisions or scan.records!=records:errors.append('item inventory differs')
    if len(scan.ids)!=len(set(scan.ids)):errors.append('duplicate anchors')
    if any(not link or link[0]!='#' or link[1:] not in scan.ids for link in scan.evidence_links):errors.append('unresolved evidence')
    text=' '.join(scan.text)
    for phrase in ('No rule trigger is not evidence of quality','not an authenticated measurement','does not securely erase','not anonymised'):
        if phrase not in text:errors.append('missing safeguard: '+phrase)
    for phrase in ('Quality certified','Low-risk code','AI-generated likelihood','Misconduct confirmed','100% confidence','No defects found'):
        if phrase in text:errors.append('misleading favourable/unsupported label')
    if len(scan.scripts)!=1 or len(scan.styles)!=1:errors.append('runtime inventory differs')
    return errors
