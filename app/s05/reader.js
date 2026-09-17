/* S05 standalone feedback controller. Author: Antonio Clim.
 * No source execution, network requests, app storage or HTML interpretation.
 * Native replay is not performed by this presentation snapshot.
 */
'use strict';
(() => {
  const digest = document.body.dataset.reportDigest;
  const forms = [...document.querySelectorAll('fieldset[data-opportunity]')];
  const error = document.getElementById('feedback-error');
  const status = document.getElementById('feedback-status');
  const exportButton = document.getElementById('export-feedback');
  const clearButton = document.getElementById('clear-feedback');
  const urls = new Set();
  const allowedStates = new Set(['accepted', 'declined', 'not_applicable', 'deferred']);
  const allowedRoles = new Set(['learner', 'educator', 'reviewer', 'other']);
  function revoke() { for (const url of urls) URL.revokeObjectURL(url); urls.clear(); }
  function clear(announce) {
    revoke();
    for (const form of forms) for (const input of form.querySelectorAll('select, textarea')) input.value = '';
    error.textContent = '';
    status.textContent = announce ? 'Active responses cleared. Downloaded files and the original report remain.' : '';
  }
  for (const link of document.querySelectorAll('a[data-jump], a.skip')) {
    link.addEventListener('click', event => {
      const target = document.getElementById(link.getAttribute('href').slice(1));
      if (!target) return;
      event.preventDefault();
      target.setAttribute('tabindex', '-1');
      target.focus(); target.scrollIntoView({block: 'start'});
    });
  }
  exportButton.addEventListener('click', () => {
    error.textContent = ''; status.textContent = '';
    const responses = [];
    for (const form of forms) {
      const state = form.querySelector('.response-state').value;
      const role = form.querySelector('.actor-role').value;
      const rationale = form.querySelector('.rationale').value;
      if (!state && !role && !rationale) continue;
      if (!allowedStates.has(state) || !allowedRoles.has(role) || [...rationale].length > 2000 || /[\u0000-\u0008\u000B-\u001F\u007F\uD800-\uDFFF]/u.test(rationale)) {
        error.textContent = 'Select a response and your role for each edited opportunity. Rationales allow at most 2000 characters and no control codes. Nothing was exported; correct the fields and retry.';
        error.focus(); return;
      }
      responses.push({opportunity_id: form.dataset.opportunity, state, actor_role: role, rationale: rationale || null});
    }
    const journal = {schema: 'codeprobe-feedback-journal/v1', report_digest: digest, responses};
    try {
      const blob = new Blob([JSON.stringify(journal, null, 2) + '\n'], {type: 'application/json'});
      const url = URL.createObjectURL(blob); urls.add(url);
      const link = document.createElement('a'); link.href = url; link.download = 'codeprobe-feedback.json';
      document.body.appendChild(link); link.click(); link.remove();
      setTimeout(() => { URL.revokeObjectURL(url); urls.delete(url); }, 1000);
      status.textContent = 'Response export requested. The immutable report is unchanged. Downloaded files remain until you manage them separately.';
    } catch (_) {
      revoke(); error.textContent = 'Export could not be prepared. Your active responses remain; retry or copy them manually.'; error.focus();
    }
  });
  clearButton.addEventListener('click', () => { clear(true); clearButton.focus(); });
  window.addEventListener('pagehide', () => clear(false));
  window.addEventListener('pageshow', event => { if (event.persisted) clear(false); });
  clear(false);
  for (const form of forms) form.disabled = false;
  exportButton.disabled = false; clearButton.disabled = false;
})();
