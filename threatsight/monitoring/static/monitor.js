'use strict';
const $ = id => document.getElementById(id);
const history = [];
const expanded = new Set();
const make = (tag, text, cls) => { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; };
const stamp = value => value ? new Date(value*1000).toLocaleTimeString() : 'not yet';
const labels = {application_errors:'Application errors',authentication_failures:'Repeated authentication failures',waf_blocks:'WAF blocks',suspicious_requests:'Suspicious request patterns',traffic_spike:'Traffic spike'};
const next = {application_errors:'Check application traces and recent deployments. A server error does not establish the cause.',authentication_failures:'Check failed login activity against expected clients. Authentication failures alone do not prove an attack.',waf_blocks:'Review blocked inputs against your API contract before changing rules.',suspicious_requests:'Inspect the source requests and reproduce safely in staging.',traffic_spike:'Compare traffic with expected campaigns, clients and service capacity.'};
async function refresh(){
 try {
  const response = await fetch('/api/monitor', {signal: AbortSignal.timeout(5000)});
  if(!response.ok) throw new Error(`Monitor returned ${response.status}`);
  const data = await response.json();
  const app = data.routes.reduce((n,r)=>n+r.requests,0), errors = data.routes.reduce((n,r)=>n+r.errors,0);
  const waf = data.routes.reduce((n,r)=>n+r.waf_requests,0);
  $('connection').textContent = `Connected · ${stamp(data.now)}`;
  $('warning').hidden = !data.collector_error;
  $('warning').textContent = data.collector_error || '';
  $('requests').textContent = app.toLocaleString();
  $('errors').textContent = app ? `${(errors/app*100).toFixed(1)}%` : 'No data';
  $('window').textContent = `Last ${data.window_seconds} seconds`;
  $('active').textContent = data.incidents.filter(i=>i.status==='active').length;
  $('blocks').textContent = waf ? data.routes.reduce((n,r)=>n+r.blocks,0) : 'No data';
  $('waf-note').textContent = waf ? `${waf} WAF requests in this window` : 'No WAF events in this window';
  $('model').textContent = data.model || 'AI off · rules monitoring active';
  history.push(app); if(history.length>60) history.shift();
  const max=Math.max(...history,1);
  $('line').setAttribute('points',history.map((n,i)=>`${i*900/Math.max(history.length-1,1)},${95-n/max*85}`).join(' '));
  $('sources').replaceChildren(...data.sources.map(s=>{
   const div=make('div',undefined,'source'); div.append(make('span',s.state,'badge '+s.state),make('span',s.path));
   div.append(make('small',`Last event: ${stamp(s.last_event)} · Malformed lines: ${s.malformed}`));
   if(s.error) div.append(make('small',s.error)); return div;
  }));
  if(!data.sources.length) $('sources').textContent='Waiting for the first collector poll…';
  $('routes').replaceChildren(...data.routes.map(r=>{const tr=make('tr');[r.path,r.requests,r.errors,r.blocks].forEach(v=>tr.append(make('td',v)));return tr;}));
  $('incidents').replaceChildren(...data.incidents.map(i=>{
   const details=make('details');details.open=expanded.has(i.id);
   details.addEventListener('toggle',()=>details.open?expanded.add(i.id):expanded.delete(i.id));
   const summary=make('summary');summary.append(make('span',i.status,'badge '+i.status),make('span',i.severity,'badge '+i.severity),make('strong',`${labels[i.kind] || i.kind} · ${i.route}`));
   summary.append(make('small',` First ${stamp(i.first_seen)} · Last ${stamp(i.last_seen)} · AI: ${i.ai_status}`)); details.append(summary);
   details.append(make('p',next[i.kind] || 'Inspect the evidence.'));
   if(i.ai_error) details.append(make('p',`AI unavailable: ${i.ai_error}`));
   if(i.ai_result){details.append(make('h3',`AI assessment · ${i.ai_result.assessment.disposition}`)); if(i.ai_revision!==i.revision)details.append(make('p','An updated investigation is pending; this assessment is from an earlier revision.'));details.append(make('pre',JSON.stringify(i.ai_result.assessment,null,2)));}
   details.append(make('h3','Source evidence'),make('pre',JSON.stringify(i.evidence,null,2)));
   const link=make('a','Export incident JSON');link.href=`/api/incidents/${encodeURIComponent(i.id)}/export`;details.append(link);return details;
  }));
  if(!data.incidents.length)$('incidents').textContent='No incidents detected. Monitoring continues as logs arrive.';
  $('timing').textContent=data.timing+' Sources retain one day of events; resolved incidents retain 30 days.';
 } catch(error){$('connection').textContent='Disconnected · data may be stale';$('warning').hidden=false;$('warning').textContent=error.message;}
 finally {setTimeout(refresh,2000);}
}
refresh();
