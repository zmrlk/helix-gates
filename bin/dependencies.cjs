'use strict';
const path = require('path'), cp = require('child_process'), fs = require('fs');
function resolve(name) {
  const env = process.env[name === 'playwright' ? 'HELIX_PLAYWRIGHT' : name === 'axe-core' ? 'HELIX_AXE' : 'HELIX_JS_YAML'];
  if (env) { try { return require.resolve(env); } catch (_) {} }
  const roots = [process.cwd(), __dirname, path.join(__dirname, '..'), ...(process.env.NODE_PATH || '').split(path.delimiter).filter(Boolean)];
  const executable = (process.env.PATH || '').split(path.delimiter).map(p => path.join(p, name)).find(p => fs.existsSync(p));
  if (executable) roots.push(path.dirname(path.dirname(fs.realpathSync(executable))));
  try { roots.push(cp.execFileSync('npm', ['root', '-g'], {encoding:'utf8', timeout:10000}).trim()); } catch (_) {}
  for (const root of roots) {
    try { return require.resolve(name, {paths:[root]}); } catch (_) {}
    try { return require.resolve(path.join(root, name)); } catch (_) {}
  }
  throw new Error(`Missing ${name}: npm install ${name}, or configure HELIX_PLAYWRIGHT / HELIX_AXE / NODE_PATH. Dependent checks skipped.`);
}
module.exports = resolve;
if (require.main === module) { try { console.log(resolve(process.argv[2])); } catch (e) { console.error(e.message); process.exitCode = 1; } }
