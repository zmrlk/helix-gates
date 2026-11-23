/* Admission control shared by UX and runtime. Reads only the parent's atomic decision file. */
const fs = require('fs'), path = require('path');
class ResourcePaused extends Error {
  constructor(message, decision = {}) { super(message); this.name = 'ResourcePaused'; this.decision = decision; }
}
function createGate(options = {}) {
  const requested = options.requestedJobs ?? 3;
  if (!Number.isInteger(requested) || requested < 1) throw Error('requestedJobs must be positive');
  const now = options.now || Date.now, sleep = options.sleep || (ms => new Promise(resolve => setTimeout(resolve, ms)));
  const read = options.readDecision || (() => {
    const file = path.resolve(options.path);
    for (let parent=path.dirname(file);;parent=path.dirname(parent)) {
      if(fs.lstatSync(parent).isSymbolicLink())throw Error('resource parent symlink');
      if(path.dirname(parent)===parent)break;
    }
    const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
    try {if(!fs.fstatSync(fd).isFile())throw Error('resource file is not regular');return JSON.parse(fs.readFileSync(fd,'utf8'));}
    finally {fs.closeSync(fd);}
  });
  let active = 0, lastSignature, lastNotice = -Infinity, stopped = null;
  const history = [];
  function decision() {
    let record;
    try { record = read(); } catch { return null; }
    if (!record || !['normal','high','critical','unknown'].includes(record.state) ||
        !Number.isInteger(record.effective_jobs) || record.effective_jobs < 0 ||
        (record.state === 'critical' && record.effective_jobs !== 0) ||
        (record.state !== 'critical' && record.effective_jobs === 0)) return null;
    for(const field of ['max_pause_s','poll_s','stale_after_s']) {
      if(record[field]!==undefined&&(!Number.isFinite(record[field])||record[field]<=0))return null;
    }
    const stamp = Date.parse(record.updated_at);
    const stale = (options.staleAfterMs ?? (record.stale_after_s || 15) * 1000);
    if (!Number.isFinite(stamp) || now() < stamp || now() - stamp > stale) return null;
    // Do not retain arbitrary fields from a replaced or damaged external file.
    const result = {schema_version:1,state:record.state,updated_at:new Date(stamp).toISOString(),requested_jobs:requested,
      effective_jobs:Math.min(requested,record.state==='unknown'?1:record.effective_jobs),reason:'Host resources: '+record.state};
    for(const field of ['max_pause_s','poll_s','stale_after_s'])if(record[field]!==undefined)result[field]=record[field];
    result.thresholds={};result.sample={};
    for(const field of ['high_load_ratio','critical_load_ratio','high_memory_available_ratio','critical_memory_available_ratio','critical_psi_full_avg10']) {
      if(Number.isFinite(record.thresholds?.[field])&&record.thresholds[field]>=0)result.thresholds[field]=record.thresholds[field];
    }
    for(const field of ['logical_cpus','load1','load_ratio','memory_available_bytes','memory_total_bytes','memory_available_ratio','psi_memory_full_avg10','psi_memory_some_avg10']) {
      const value=record.sample?.[field];result.sample[field]=Number.isFinite(value)&&value>=0?value:null;
    }
    const signature = JSON.stringify([result.state,result.effective_jobs]);
    if (signature !== lastSignature || now() - lastNotice >= 30000) {
      history.push(result); lastSignature = signature; lastNotice = now();
      if (options.onDecision) options.onDecision(result);
    }
    return result;
  }
  async function acquire() {
    let missingSince = null, blockedSince = null, latest = null;
    while (true) {
      if (stopped) throw stopped;
      const current = decision();
      if(current)latest=current;
      if (!current) {
        if (missingSince === null) missingSince = now();
        if (now() - missingSince >= (options.staleAfterMs ?? (latest?.stale_after_s || 15)*1000)) {
          stopped = new ResourcePaused('resource_paused: resource monitor missing, stale or invalid'); throw stopped;
        }
      } else {
        missingSince = null;
        if (active < current.effective_jobs) { active++; return current; }
      }
      const maximum = options.maxPauseMs ?? (latest?.max_pause_s || 300) * 1000;
      if (!current || current.effective_jobs === 0) { if (blockedSince === null) blockedSince = now(); }
      else blockedSince = null;
      if (blockedSince !== null && now() - blockedSince >= maximum) {
        stopped = new ResourcePaused('resource_paused: resources.max_pause_s exceeded', current || {}); throw stopped;
      }
      const poll = options.pollMs ?? (current?.poll_s || 5) * 1000;
      await sleep(Math.min(current && current.effective_jobs > 0 ? Math.min(poll,100) : poll,
        blockedSince === null ? Infinity : Math.max(1, maximum - (now() - blockedSince))));
    }
  }
  function release() { if (active > 0) active--; }
  async function run(fn) { await acquire(); try { return await fn(); } finally { release(); } }
  return {acquire,release,run,decision,history,get active() { return active; }};
}
module.exports = {createGate,ResourcePaused};
