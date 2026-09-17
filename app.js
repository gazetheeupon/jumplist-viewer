import { parseJumpList } from './jumplist-parser.js';

const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('fileInput');
const status = document.getElementById('status');
const results = document.getElementById('results');
const exportRow = document.getElementById('exportRow');

let lastResult = null;
let lastFileName = '';

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function fmtDate(d) {
  return d ? d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC') : '(not recorded)';
}

function row(label, value) {
  if (value === null || value === undefined || value === '') return '';
  return `<tr><td>${label}</td><td>${escapeHtml(value)}</td></tr>`;
}

function render(result) {
  let html = '';

  if (result.warnings.length) {
    html += '<div class="warn">' + result.warnings.map(escapeHtml).join('<br>') + '</div>';
  }

  if (result.destListHeader) {
    html += '<h2>Jump list summary</h2><table>';
    html += row('Entries recorded', result.destListHeader.numEntries);
    html += row('Pinned entries', result.destListHeader.numPinned);
    html += '</table>';
  }

  if (result.entries.length === 0) {
    html += '<p class="note">No shortcuts were found in this file.</p>';
  }

  result.entries.forEach((e, i) => {
    const lnk = e.lnk;
    const meta = e.meta;
    html += `<div class="entry"><h2>${i + 1}. ${escapeHtml((lnk && lnk.strings.name) || (meta && meta.path) || e.streamName)}${meta && meta.pinned ? ' <span class="badge">pinned</span>' : ''}</h2>`;
    html += '<table>';
    if (lnk) {
      html += row('Target', lnk.linkInfo && lnk.linkInfo.fullPath);
      html += row('Arguments', lnk.strings.commandLineArguments);
      html += row('Working directory', lnk.strings.workingDir);
      html += row('Icon location', lnk.strings.iconLocation);
    } else if (e.lnkError) {
      html += row('Shortcut data', 'Could not be parsed: ' + e.lnkError);
    }
    if (meta) {
      html += row('Recorded path', meta.path);
      html += row('Last modified', fmtDate(meta.lastModified));
      html += row('Pin order', meta.pinned ? meta.pinOrder : null);
      html += row('Access count', meta.accessCount);
      html += row('Recorded machine', meta.machine);
    }
    html += '</table></div>';
  });

  results.innerHTML = html;
}

function toPlainObject(result) {
  return {
    kind: result.kind,
    destListHeader: result.destListHeader,
    warnings: result.warnings,
    entries: result.entries.map((e) => ({
      streamName: e.streamName,
      target: e.lnk ? e.lnk.linkInfo && e.lnk.linkInfo.fullPath : null,
      name: e.lnk ? e.lnk.strings.name : null,
      arguments: e.lnk ? e.lnk.strings.commandLineArguments : null,
      workingDir: e.lnk ? e.lnk.strings.workingDir : null,
      lnkError: e.lnkError,
      recordedPath: e.meta ? e.meta.path : null,
      lastModified: e.meta ? e.meta.lastModified : null,
      pinned: e.meta ? e.meta.pinned : null,
      pinOrder: e.meta ? e.meta.pinOrder : null,
      accessCount: e.meta ? e.meta.accessCount : null,
      machine: e.meta ? e.meta.machine : null,
    })),
  };
}

function download(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

document.getElementById('exportJsonBtn').addEventListener('click', () => {
  if (!lastResult) return;
  download(lastFileName + '.json', JSON.stringify(toPlainObject(lastResult), null, 2), 'application/json');
});

document.getElementById('exportCsvBtn').addEventListener('click', () => {
  if (!lastResult) return;
  const obj = toPlainObject(lastResult);
  const rows = [['stream', 'name', 'target', 'arguments', 'recordedPath', 'lastModified', 'pinned', 'pinOrder', 'accessCount', 'machine']];
  for (const e of obj.entries) {
    rows.push([e.streamName, e.name, e.target, e.arguments, e.recordedPath, e.lastModified, e.pinned, e.pinOrder, e.accessCount, e.machine]);
  }
  const csv = rows.map((r) => r.map((c) => '"' + String(c ?? '').replace(/"/g, '""') + '"').join(',')).join('\n');
  download(lastFileName + '.csv', csv, 'text/csv');
});

async function handleFile(file) {
  if (!file) return;
  status.textContent = 'Parsing ' + file.name + '...';
  results.innerHTML = '';
  exportRow.style.display = 'none';
  try {
    const buf = await file.arrayBuffer();
    const result = parseJumpList(buf, file.name);
    lastResult = result;
    lastFileName = file.name.replace(/\.[^.]+$/, '');
    render(result);
    status.textContent = `Parsed ${file.name}: ${result.entries.length} shortcut(s) found.`;
    exportRow.style.display = 'flex';
  } catch (err) {
    status.textContent = 'Error: ' + err.message;
    console.error(err);
  }
}

dropzone.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', (e) => handleFile(e.target.files[0]));
['dragenter', 'dragover'].forEach((ev) =>
  dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.add('drag'); })
);
['dragleave', 'drop'].forEach((ev) =>
  dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.remove('drag'); })
);
dropzone.addEventListener('drop', (e) => handleFile(e.dataTransfer.files[0]));
