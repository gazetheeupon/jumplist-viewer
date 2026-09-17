import { parseCfb, CfbError } from './cfb-parser.js';
import { parseDestList, DestListError } from './destlist-parser.js';
import { parseLnk } from './lnk-parser.js';

const LNK_SIGNATURE = [0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00];

function looksLikeLnk(bytes) {
  if (bytes.length < 8) return false;
  for (let i = 0; i < 8; i++) if (bytes[i] !== LNK_SIGNATURE[i]) return false;
  return true;
}

// .automaticDestinations-ms: an OLE/CFB container. Numbered streams ("1", "2", ...)
// each hold one embedded Shell Link (LNK). A "DestList" stream holds supplementary,
// community-reverse-engineered metadata (pin order, access count, recorded path)
// keyed by that same number.
function parseAutomaticDestinations(arrayBuffer) {
  const cfb = parseCfb(arrayBuffer);
  const warnings = [];

  let destList = null;
  const destListStream = cfb.getStream('DestList');
  if (destListStream) {
    try {
      destList = parseDestList(destListStream);
      warnings.push(...destList.warnings.map((w) => `DestList: ${w}`));
    } catch (err) {
      warnings.push(
        `Could not parse the DestList stream (${err.message}). This part of the format is not ` +
        `officially documented, so this is best-effort; the shortcuts below were still read directly.`
      );
    }
  } else {
    warnings.push('No DestList stream found; showing shortcuts without pin/access-count metadata.');
  }

  const destListByStream = new Map();
  if (destList) {
    for (const e of destList.entries) destListByStream.set(e.streamName, e);
  }

  const entries = [];
  for (const streamName of cfb.streamNames) {
    if (streamName === 'DestList') continue;
    if (!/^\d+$/.test(streamName)) continue; // skip non-numbered streams (e.g. library watermark streams)
    const raw = cfb.getStream(streamName);
    if (!raw || !looksLikeLnk(raw)) continue;
    let lnk = null;
    let lnkError = null;
    try {
      lnk = parseLnk(raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength));
    } catch (err) {
      lnkError = err.message;
    }
    entries.push({
      streamName,
      meta: destListByStream.get(streamName) || null,
      lnk,
      lnkError,
    });
  }

  // Order by pin status (pinned first, by pin order), then by access count descending.
  entries.sort((a, b) => {
    const am = a.meta, bm = b.meta;
    if (am?.pinned && bm?.pinned) return (am.pinOrder ?? 0) - (bm.pinOrder ?? 0);
    if (am?.pinned && !bm?.pinned) return -1;
    if (!am?.pinned && bm?.pinned) return 1;
    return (bm?.accessCount ?? 0) - (am?.accessCount ?? 0);
  });

  return { kind: 'automatic', destListHeader: destList ? { version: destList.version, numEntries: destList.numEntries, numPinned: destList.numPinned } : null, entries, warnings };
}

// .customDestinations-ms: NOT an OLE/CFB container. It's a simpler, also
// undocumented format: raw LNK blobs (and small category-header records)
// concatenated together with a short footer. Rather than fully modelling the
// framing (which is less consistently reverse-engineered than DestList),
// this scans for the LNK signature directly and parses whatever it finds.
// This is explicitly a best-effort fallback: it recovers the shortcuts, but
// not category grouping.
function parseCustomDestinations(arrayBuffer) {
  const bytes = new Uint8Array(arrayBuffer);
  const entries = [];
  const warnings = [
    'The .customDestinations-ms container format is not modeled here (it is not a CFB file and ' +
    'its framing is only loosely documented). Shortcuts below were recovered by scanning the file ' +
    'for embedded Shell Link data directly, so category names and ordering are not available.',
  ];
  for (let i = 0; i + 8 <= bytes.length; i++) {
    let match = true;
    for (let j = 0; j < 8; j++) {
      if (bytes[i + j] !== LNK_SIGNATURE[j]) { match = false; break; }
    }
    if (!match) continue;
    try {
      const lnk = parseLnk(bytes.buffer.slice(i, bytes.length));
      entries.push({ streamName: `offset ${i}`, meta: null, lnk, lnkError: null });
    } catch (err) {
      // Not a real match (signature collision) or truncated; skip.
    }
  }
  return { kind: 'custom', destListHeader: null, entries, warnings };
}

export function parseJumpList(arrayBuffer, fileName) {
  const isCustom = /customDestinations-ms$/i.test(fileName || '');
  if (isCustom) {
    return parseCustomDestinations(arrayBuffer);
  }
  try {
    return parseAutomaticDestinations(arrayBuffer);
  } catch (err) {
    if (err instanceof CfbError) {
      // Fall back to scanning, in case this was actually a customDestinations-ms
      // file with an unexpected extension.
      const result = parseCustomDestinations(arrayBuffer);
      result.warnings.unshift(`This did not parse as an OLE/CFB container (${err.message}); falling back to signature scanning.`);
      return result;
    }
    throw err;
  }
}
