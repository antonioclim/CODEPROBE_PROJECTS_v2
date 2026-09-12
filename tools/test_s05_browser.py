#!/usr/bin/env python3
"""Actual standalone Chromium journeys; no manual accessibility claim.

Author: Antonio Clim. Uses a fresh context, local files and recorded Playwright
and browser versions. No fixture code is executed. Network probes are deliberate
negative controls and are reported separately from normal application activity.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import sys
import traceback
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests/s05')]
import codeprobe_interpretation as i
import codeprobe_reporting as r
import fixtures

PROBE = '''(() => {
 window.__s05audit = {storageWrites:0, networkAPICalls:0, serviceWorkers:0, objectURLs:0};
 const oldSet = Storage.prototype.setItem;
 Storage.prototype.setItem = function(...args) { window.__s05audit.storageWrites++; return oldSet.apply(this,args); };
 const oldFetch = window.fetch;
 window.fetch = function(...args) { window.__s05audit.networkAPICalls++; return oldFetch.apply(this,args); };
 const oldOpen = XMLHttpRequest.prototype.open;
 XMLHttpRequest.prototype.open = function(...args) { window.__s05audit.networkAPICalls++; return oldOpen.apply(this,args); };
 const create = URL.createObjectURL; const revoke = URL.revokeObjectURL;
 const live = new Set();
 URL.createObjectURL = function(x) { const u=create.call(URL,x);live.add(u);window.__s05audit.objectURLs=live.size;return u; };
 URL.revokeObjectURL = function(u) { live.delete(u);window.__s05audit.objectURLs=live.size;return revoke.call(URL,u); };
 if (navigator.serviceWorker) {
  const register = navigator.serviceWorker.register.bind(navigator.serviceWorker);
  navigator.serviceWorker.register = function(...args) { window.__s05audit.serviceWorkers++;return register(...args); };
 }
})();'''


def contrast(a,b):
    def lum(s):
        numbers=[int(x)/255 for x in re.findall(r'\d+',s)[:3]]
        values=[v/12.92 if v<=0.04045 else ((v+0.055)/1.055)**2.4 for v in numbers]
        return sum(v*w for v,w in zip(values,[.2126,.7152,.0722]))
    x,y=lum(a),lum(b);return (max(x,y)+.05)/(min(x,y)+.05)


def run(evidence,out,executable=None,transport="file"):
    # Loopback is an explicitly reported test transport, not a product server.
    server = None
    origin = ""
    if transport == "loopback":
        allowed = {"/" + p.name: p.read_bytes() for p in (evidence / "html").glob("*.html")}
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = allowed.get(self.path)
                if body is None:
                    self.send_error(404); return
                self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store"); self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)
            def log_message(self, *args): pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        origin = "http://127.0.0.1:" + str(server.server_port)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    def document_url(cid):
        return origin + "/" + cid + ".html" if origin else (evidence / "html" / (cid + ".html")).resolve().as_uri()
    out=out.resolve();out.mkdir(parents=True,exist_ok=True)
    cases={x['case_id']:x for x in [json.loads(s) for s in (evidence/'cases.jsonl').read_text().splitlines()]}
    with gzip.open(evidence/'bundles.jsonl.gz','rt',encoding='utf-8') as f:bundles={x['case_id']:x['bundle'] for x in map(json.loads,f)}
    results=[];network=[];console=[];page_errors=[];downloads=[];browser=None
    def check(name,condition,detail=None):
        row={'check':name,'passed':bool(condition),'detail':detail};results.append(row)
        (out/'checks.json').write_text(json.dumps(results,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
        if not condition:raise AssertionError(name+': '+str(detail))
    with sync_playwright() as pw:
        try:
            browser=pw.chromium.launch(headless=True,executable_path=executable,args=['--disable-background-networking','--disable-component-update','--no-first-run'])
            version=browser.version
            context=browser.new_context(viewport={'width':1280,'height':900},accept_downloads=True)
            context.add_init_script(PROBE)
            context.on('request',lambda request: network.append({'url':request.url,'method':request.method,'resource_type':request.resource_type}))
            context.route('http://**/*',lambda route: route.continue_() if origin and route.request.url.startswith(origin + '/') else route.abort())
            context.route('https://**/*',lambda route: route.abort())
            page=context.new_page();page.on('console',lambda msg:console.append({'type':msg.type,'text':msg.text}));page.on('pageerror',lambda e:page_errors.append(str(e)))
            def load(name,profile='structural-review'):
                nonlocal page
                cid=name+'--'+profile
                if transport == 'dom':
                    page.close(); page=context.new_page()
                    page.on('console',lambda msg:console.append({'type':msg.type,'text':msg.text}))
                    page.on('pageerror',lambda e:page_errors.append(str(e)))
                    page.evaluate(PROBE)
                    page.set_content((evidence/'html'/(cid+'.html')).read_text(encoding='utf-8'),wait_until='load')
                else:
                    page.goto(document_url(cid),wait_until='load')
                page.wait_for_function('!document.getElementById("export-feedback").disabled')
                return cid
            cid=load('above');digest=page.locator('#report-digest').inner_text()
            check('J01-seven-dimensions-five-withheld',page.locator('.dimension').count()==7 and page.locator('.withheld').count()==5)
            check('J01-distinct-opportunity-not-certification','not a demonstrated defect' in page.locator('[data-decision="review_opportunity"] .decision').first.inner_text())
            page.screenshot(path=str(out/'desktop.png'))
            page.keyboard.press('Tab');check('J02-keyboard-skip-focus',page.locator('.skip').evaluate('(el)=>el===document.activeElement'))
            page.keyboard.press('Enter');check('J02-keyboard-skip-main',page.locator('#main').evaluate('(el)=>el===document.activeElement'))
            link=page.locator('.evidence-link').first;target=link.get_attribute('href')[1:];link.focus();page.keyboard.press('Enter')
            check('J02-evidence-navigation-focus',page.evaluate('(id)=>document.activeElement.id===id',target))
            check('J02-visible-focus',page.evaluate('getComputedStyle(document.activeElement).outlineStyle')!='none')
            page.locator('#'+target+' a[data-jump]').last.focus();page.keyboard.press('Enter')
            check('J02-return-focus',page.evaluate('document.activeElement.id')=='dimensions-title')
            check('J02-control-labels',page.locator('select, textarea').evaluate_all('(nodes)=>nodes.every(n=>n.labels && n.labels.length===1 && n.labels[0].textContent.trim())'))
            load('nominal-plus-one');check('J03-abstention-visible',page.locator('[data-decision="abstain"]').count()>0 and page.locator('fieldset').count()==0)
            load('below');check('J03-no-trigger-qualified','not a quality judgement' in page.locator('[data-decision="no_rule_trigger"] .decision').first.inner_text())
            load('above','structural-review-conservative');check('J03-profile-dependence-preserved',page.locator('#profile-id').inner_text()=='structural-review-conservative' and page.locator('fieldset').count()==0)
            cid=load('above');form=page.locator('fieldset').first
            form.locator('.response-state').select_option('declined');page.locator('#export-feedback').click()
            check('J04-error-announced-and-focused',page.locator('#feedback-error').inner_text().startswith('Select a response') and page.evaluate('document.activeElement.id')=='feedback-error')
            form.locator('.actor-role').select_option('reviewer')
            for label, expression in [('unpaired-surrogate', 'String.fromCharCode(0xd800)'), ('control', 'String.fromCharCode(1)'), ('overlength', '"😀".repeat(2001)')]:
                form.locator('.rationale').evaluate('(el)=>{el.value='+expression+'}')
                page.locator('#export-feedback').click()
                check('J04-reject-'+label, 'Nothing was exported' in page.locator('#feedback-error').inner_text())
            form.locator('.rationale').fill('Keep behaviour unchanged. <img src=x onerror=alert(1)>')
            with page.expect_download() as dl:page.locator('#export-feedback').click()
            file=out/'feedback-export.json';dl.value.save_as(file);downloads.append(str(file.name))
            journal=json.loads(file.read_text());check('J04-journal-binds-report',journal['report_digest']==digest and len(journal['responses'])==1)
            # Same source/build/runtime in the browser job: verify the exported journal natively.
            source=next(data for n,data,_ in fixtures.cases() if n=='above')
            r.validate_feedback(journal,bundles[cid],source,**cases[cid]['context'])
            check('J04-native-feedback-admission',True)
            check('J04-report-remains-immutable',page.locator('#report-digest').inner_text()==digest)
            page.locator('#clear-feedback').click()
            check('J05-clear-active-controls',form.locator('select,textarea').evaluate_all('(nodes)=>nodes.every(n=>n.value==="")'))
            check('J05-revoked-object-urls',page.evaluate('window.__s05audit.objectURLs')==0)
            check('J05-deletion-limits-and-download-survives',file.exists() and 'does not securely erase' in page.locator('#deletion-limits').inner_text())
            form.locator('.response-state').select_option('accepted')
            if transport == 'dom': load('above')
            else: page.reload()
            page.wait_for_function('!document.getElementById("export-feedback").disabled')
            check('J06-reload-clears-response',page.locator('.response-state').first.input_value()=='')
            check('J06-no-storage-or-network-api-use',page.evaluate('window.__s05audit.storageWrites===0 && window.__s05audit.networkAPICalls===0 && window.__s05audit.serviceWorkers===0'))
            check('J06-no-cookies',not context.cookies())
            load('hostile-markup');check('J07-source-markup-inert',page.locator('img,iframe,object,embed').count()==0 and page.evaluate('typeof globalThis.injected')=='undefined')
            load('unicode-bom-crlf');page.locator('a[href="#source-line-1"]').first.click();check('J07-source-line-focus',page.evaluate('document.activeElement.id')=='source-line-1')
            check('J07-unicode-source-preserved','gen_șir' in page.locator('#source-line-1').inner_text())
            load('directional');check('J07-directional-controls-escaped','\\u{202E}' in page.locator('.source').inner_text() and '\u202e' not in page.locator('.source').inner_text())
            load('above');page.set_viewport_size({'width':320,'height':800})
            page.locator('details').evaluate_all('(nodes)=>nodes.forEach(n=>n.open=true)')
            widths=page.evaluate('({scroll:document.documentElement.scrollWidth, viewport:innerWidth})')
            check('J08-reflow-at-320',widths['scroll']<=widths['viewport']+1,widths)
            page.screenshot(path=str(out/'mobile.png'))
            colors=page.evaluate('({text:getComputedStyle(document.body).color, background:getComputedStyle(document.documentElement).backgroundColor,link:getComputedStyle(document.querySelector("a.evidence-link")).color,error:getComputedStyle(document.getElementById("feedback-error")).color})')
            ratios={k:contrast(colors[k],colors['background']) for k in ('text','link','error')}
            check('J08-selected-text-contrast',all(v>=4.5 for v in ratios.values()),ratios)
            page.set_viewport_size({'width':1280,'height':900})
            form=page.locator('fieldset').first;form.locator('.response-state').select_option('deferred');form.locator('.actor-role').select_option('reviewer')
            page.evaluate('()=>{window.__oldCreate=URL.createObjectURL;URL.createObjectURL=()=>{throw new Error("injected export failure")};}')
            page.locator('#export-feedback').click();check('J09-export-error-recoverable','could not be prepared' in page.locator('#feedback-error').inner_text() and form.locator('.response-state').input_value()=='deferred')
            page.evaluate('()=>{URL.createObjectURL=window.__oldCreate;}')
            with page.expect_download() as dl:page.locator('#export-feedback').click()
            dl.value.save_as(out/'feedback-retry.json');check('J09-export-retry-succeeds',(out/'feedback-retry.json').is_file())
            nojs=browser.new_context(java_script_enabled=False,viewport={'width':320,'height':800});np=nojs.new_page()
            if transport == 'dom': np.set_content((evidence/'html'/'above--structural-review.html').read_text(encoding='utf-8'))
            else: np.goto(document_url('above--structural-review'))
            check('J10-no-javascript-readable',np.locator('.dimension').count()==7 and np.locator('#export-feedback').is_disabled() and np.locator('noscript').is_visible());nojs.close()
            for name,state in [('empty','insufficient_evidence'),('no-callable','insufficient_evidence'),('syntax-error','unavailable'),('plain-text','not_applicable')]:
                load(name);check('J11-'+name,page.locator('[data-dimension="structural_complexity_dispersion"]').get_attribute('data-state')==state)
            load('above');normal_network=[x for x in network if not x['url'].startswith(('file:','blob:')) and not (origin and x['url'].startswith(origin + '/') and x['resource_type']=='document')]
            check('J12-no-normal-external-requests',not normal_network,normal_network)
            # Deliberate network and script injections must be blocked by the document CSP.
            probes=page.evaluate('''async()=>{ window.__cspEvents=[];document.addEventListener('securitypolicyviolation',e=>window.__cspEvents.push(e.violatedDirective));const s=document.createElement('script');s.textContent='globalThis.UNTRUSTED_S05=1';document.body.appendChild(s);let blocked=false;try{await fetch('https://invalid.example/s05-probe')}catch(e){blocked=true}return {blocked,scriptExecuted:globalThis.UNTRUSTED_S05===1};}''')
            check('J12-csp-injected-network-and-script-rejected',probes['blocked'] and not probes['scriptExecuted'],probes)
            page.wait_for_timeout(50)
            check('J12-csp-violations-recorded',len(page.evaluate('window.__cspEvents'))>=2,page.evaluate('window.__cspEvents'))
            check('J12-no-unexpected-page-errors',not page_errors,page_errors)
            context.close()
        except Exception as exc:
            results.append({'check':'journey-execution','passed':False,'detail':str(exc),'traceback':traceback.format_exc()})
        finally:
            if browser:browser.close()
            if server:server.shutdown();server.server_close()
            report={'schema':'codeprobe-s05-browser-evidence/v1','browser':locals().get('version'),'playwright':importlib.metadata.version('playwright'),
                'python':sys.version.split()[0],'transport':transport,'navigation_qualification':'DOM injection and fresh-document replacement only; file loading and actual reload are not covered locally' if transport=='dom' else 'Actual document navigation and reload','checks':results,'failure_count':sum(not x['passed'] for x in results),
                'network_observations':network,'console':console,'page_errors':page_errors,'downloads':downloads,
                'scope':'Automated Chromium journeys on exact standalone HTML bytes; recorded transport; no manual screen-reader assessment, other-browser coverage or hosted Pyodide claim.'}
            (out/'browser-summary.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
            print(json.dumps({'failure_count':report['failure_count'],'checks':len(results),'browser':report['browser']},sort_keys=True))
    return 1 if report['failure_count'] else 0


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--evidence',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--executable');p.add_argument('--transport',choices=['file','loopback','dom'],default='file');a=p.parse_args()
    raise SystemExit(run(a.evidence,a.output,a.executable,a.transport))
