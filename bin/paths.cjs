'use strict';
const fs = require('fs');
const path = require('path');
function normalize(value) { return fs.realpathSync(value); }
function relative(root, value) { return path.relative(normalize(root), normalize(value)); }
module.exports = { normalize, relative };
