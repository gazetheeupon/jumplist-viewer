// Minimal, dependency-free parser for the Microsoft Compound File Binary (CFB / OLE2)
// container format ([MS-CFB]). Used here to open the numbered streams and the
// "DestList" stream inside a Windows .automaticDestinations-ms jump list file.
//
// This only implements what's needed to enumerate and read whole streams:
// header, DIFAT/FAT chain walking, directory entries, and mini-FAT for small
// streams. It does not implement writing, and it treats the directory as a
// flat set of entries reachable from the root rather than a full red-black
// tree (adequate for reading; ordering/coloring is irrelevant to us).

const HEADER_SIGNATURE = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const FREESECT = 0xffffffff;
const ENDOFCHAIN = 0xfffffffe;
const FATSECT = 0xfffffffd;
const DIFSECT = 0xfffffffc;
const NOSTREAM = 0xffffffff;

export class CfbError extends Error {}

export function parseCfb(arrayBuffer) {
  const buf = new DataView(arrayBuffer);
  const bytes = new Uint8Array(arrayBuffer);

  for (let i = 0; i < 8; i++) {
    if (bytes[i] !== HEADER_SIGNATURE[i]) {
      throw new CfbError('Not a Compound File Binary (OLE2) container: bad signature.');
    }
  }

  const minorVersion = buf.getUint16(24, true);
  const majorVersion = buf.getUint16(26, true);
  const sectorShift = buf.getUint16(30, true);
  const miniSectorShift = buf.getUint16(32, true);
  const numDirSectors = buf.getUint32(40, true);
  const numFatSectors = buf.getUint32(44, true);
  const firstDirSector = buf.getUint32(48, true);
  const miniStreamCutoff = buf.getUint32(56, true);
  const firstMiniFatSector = buf.getUint32(60, true);
  const numMiniFatSectors = buf.getUint32(64, true);
  const firstDifatSector = buf.getUint32(68, true);
  const numDifatSectors = buf.getUint32(72, true);

  const sectorSize = 1 << sectorShift;
  const miniSectorSize = 1 << miniSectorShift;

  function sectorOffset(sectorId) {
    return (sectorId + 1) * sectorSize;
  }

  function readSector(sectorId) {
    const off = sectorOffset(sectorId);
    return bytes.subarray(off, off + sectorSize);
  }

  // --- Build DIFAT (list of FAT sector locations) ---
  const difat = [];
  for (let i = 0; i < 109; i++) {
    const v = buf.getUint32(76 + i * 4, true);
    if (v !== FREESECT) difat.push(v);
  }
  let difatSector = firstDifatSector;
  let guard = 0;
  while (difatSector !== ENDOFCHAIN && difatSector !== FREESECT && guard++ < 100000) {
    const off = sectorOffset(difatSector);
    const entriesPerSector = sectorSize / 4 - 1;
    for (let i = 0; i < entriesPerSector; i++) {
      const v = buf.getUint32(off + i * 4, true);
      if (v !== FREESECT) difat.push(v);
    }
    difatSector = buf.getUint32(off + entriesPerSector * 4, true);
  }

  // --- Build FAT (sector -> next sector map) ---
  const fat = new Uint32Array((difat.length * sectorSize) / 4);
  for (let s = 0; s < difat.length; s++) {
    const sec = readSector(difat[s]);
    const dv = new DataView(sec.buffer, sec.byteOffset, sec.byteLength);
    for (let i = 0; i < sectorSize / 4; i++) {
      fat[s * (sectorSize / 4) + i] = dv.getUint32(i * 4, true);
    }
  }

  function readChain(startSector, byteLength) {
    const out = new Uint8Array(byteLength);
    let sec = startSector;
    let written = 0;
    let iter = 0;
    while (sec !== ENDOFCHAIN && written < byteLength && iter++ < 1000000) {
      const chunk = readSector(sec);
      const toCopy = Math.min(chunk.length, byteLength - written);
      out.set(chunk.subarray(0, toCopy), written);
      written += toCopy;
      sec = fat[sec];
      if (sec === undefined) break;
    }
    return out;
  }

  // --- Directory entries ---
  // numDirSectors can be 0 for major version 3 (the chain is self-terminating via FAT
  // ENDOFCHAIN), so walk the FAT chain directly rather than trusting that count.
  const dirEntries = [];
  {
    let sec = firstDirSector;
    let iter = 0;
    const all = [];
    while (sec !== ENDOFCHAIN && iter++ < 1000000) {
      all.push(readSector(sec));
      sec = fat[sec];
      if (sec === undefined) break;
    }
    const dirData = concatUint8(all);
    const perSector = sectorSize / 128;
    const count = dirData.length / 128;
    for (let i = 0; i < count; i++) {
      const off = i * 128;
      const dv = new DataView(dirData.buffer, dirData.byteOffset + off, 128);
      const nameLenBytes = dv.getUint16(64, true);
      if (nameLenBytes === 0) continue; // unused entry
      const nameChars = Math.max(0, nameLenBytes / 2 - 1);
      let name = '';
      for (let c = 0; c < nameChars; c++) {
        name += String.fromCharCode(dv.getUint16(c * 2, true));
      }
      const objectType = dv.getUint8(66);
      const leftSib = dv.getUint32(68, true);
      const rightSib = dv.getUint32(72, true);
      const childId = dv.getUint32(76, true);
      const startSector = dv.getUint32(116, true);
      const sizeLow = dv.getUint32(120, true);
      const sizeHigh = dv.getUint32(124, true);
      const size = sizeHigh * 0x100000000 + sizeLow;
      dirEntries.push({ index: i, name, objectType, leftSib, rightSib, childId, startSector, size });
    }
  }

  const root = dirEntries.find((e) => e.objectType === 5);
  if (!root) throw new CfbError('No root storage entry found.');

  // --- Mini-FAT + mini-stream (root's own stream, read via regular FAT) ---
  let miniStream = new Uint8Array(0);
  if (root.size > 0) {
    miniStream = readChain(root.startSector, root.size);
  }
  const miniFat = new Uint32Array((numMiniFatSectors * sectorSize) / 4);
  {
    let sec = firstMiniFatSector;
    let idx = 0;
    let iter = 0;
    while (sec !== ENDOFCHAIN && iter++ < 1000000) {
      const chunk = readSector(sec);
      const dv = new DataView(chunk.buffer, chunk.byteOffset, chunk.byteLength);
      for (let i = 0; i < sectorSize / 4; i++) miniFat[idx++] = dv.getUint32(i * 4, true);
      sec = fat[sec];
      if (sec === undefined) break;
    }
  }

  function readMiniChain(startSector, byteLength) {
    const out = new Uint8Array(byteLength);
    let sec = startSector;
    let written = 0;
    let iter = 0;
    while (sec !== ENDOFCHAIN && written < byteLength && iter++ < 1000000) {
      const off = sec * miniSectorSize;
      const toCopy = Math.min(miniSectorSize, byteLength - written);
      out.set(miniStream.subarray(off, off + toCopy), written);
      written += toCopy;
      sec = miniFat[sec];
      if (sec === undefined) break;
    }
    return out;
  }

  function readStream(entry) {
    if (entry === root) return miniStream;
    if (entry.size >= miniStreamCutoff) return readChain(entry.startSector, entry.size);
    return readMiniChain(entry.startSector, entry.size);
  }

  // --- Enumerate all stream entries reachable from root (simple tree walk) ---
  const streams = [];
  const visited = new Set();
  function visit(id) {
    if (id === NOSTREAM || id === undefined || id === null) return;
    if (visited.has(id)) return;
    visited.add(id);
    const e = dirEntries[id];
    if (!e) return;
    visit(e.leftSib);
    visit(e.rightSib);
    if (e.objectType === 2) {
      streams.push(e);
    } else if (e.objectType === 1 || e.objectType === 5) {
      visit(e.childId);
    }
  }
  visit(root.childId);

  return {
    majorVersion,
    minorVersion,
    sectorSize,
    getStream(name) {
      const e = streams.find((s) => s.name === name);
      if (!e) return null;
      return readStream(e);
    },
    streamNames: streams.map((s) => s.name),
    streams,
    readStream,
  };
}

function concatUint8(chunks) {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}
