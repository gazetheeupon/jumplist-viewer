// Parser for the "DestList" stream found inside .automaticDestinations-ms jump
// list files. Unlike the CFB container and the LNK format, this stream's
// layout is NOT publicly documented by Microsoft — everything here is based
// on community reverse-engineering (the format used by tools such as
// Eric Zimmerman's JLECmd). It is offered as best-effort supplementary data:
// if it doesn't parse cleanly, the caller should still be able to show the
// underlying shortcuts from the numbered streams on their own.

export class DestListError extends Error {}

function bytesToGuid(bytes, offset) {
  const b = bytes.subarray(offset, offset + 16);
  const hex = (i) => b[i].toString(16).padStart(2, '0');
  return (
    hex(3) + hex(2) + hex(1) + hex(0) + '-' +
    hex(5) + hex(4) + '-' +
    hex(7) + hex(6) + '-' +
    hex(8) + hex(9) + '-' +
    hex(10) + hex(11) + hex(12) + hex(13) + hex(14) + hex(15)
  );
}

function filetimeToDate(low, high) {
  const ticks = BigInt(high) * 0x100000000n + BigInt(low);
  if (ticks === 0n) return null;
  const ms = Number(ticks / 10000n) - 11644473600000;
  return new Date(ms);
}

export function parseDestList(bytes) {
  if (bytes.length < 32) {
    throw new DestListError('DestList stream is smaller than a valid header (32 bytes).');
  }
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const version = dv.getUint32(0, true);
  const numEntries = dv.getUint32(4, true);
  const numPinned = dv.getUint32(8, true);

  const entries = [];
  let off = 32;
  const warnings = [];
  if (version < 1 || version > 4) {
    warnings.push(`Unrecognized DestList version (${version}); entries below may be unreliable.`);
  }

  while (off + 130 <= bytes.length && entries.length < Math.max(numEntries, 0) + 1000) {
    const entryStart = off;
    try {
      off += 8; // checksum / unknown
      let machine = '';
      for (let i = 0; i < 16; i++) {
        const c = bytes[off + i];
        if (c === 0) break;
        machine += String.fromCharCode(c);
      }
      off += 16;
      const droidVolumeId = bytesToGuid(bytes, off); off += 16;
      const droidFileId = bytesToGuid(bytes, off); off += 16;
      const birthDroidVolumeId = bytesToGuid(bytes, off); off += 16;
      const birthDroidFileId = bytesToGuid(bytes, off); off += 16;
      const entryId = dv.getUint32(off, true); off += 4;
      const ftLow = dv.getUint32(off, true);
      const ftHigh = dv.getUint32(off + 4, true);
      off += 8;
      const pinStatus = dv.getInt32(off, true); off += 4;
      const accessCount = dv.getUint32(off, true); off += 4;
      off += 8; // unknown (version-dependent)
      if (off + 2 > bytes.length) break;
      const pathCharCount = dv.getUint16(off, true); off += 2;
      const pathByteLen = pathCharCount * 2;
      if (off + pathByteLen > bytes.length) {
        warnings.push(`Entry near offset ${entryStart}: path length runs past end of stream; stopping.`);
        break;
      }
      let path = '';
      for (let i = 0; i < pathCharCount; i++) {
        path += String.fromCharCode(dv.getUint16(off + i * 2, true));
      }
      off += pathByteLen;
      if (version >= 3) off += 4; // trailing unknown4

      entries.push({
        streamName: String(entryId),
        entryId,
        machine: machine || null,
        droidVolumeId,
        droidFileId,
        birthDroidVolumeId,
        birthDroidFileId,
        lastModified: filetimeToDate(ftLow, ftHigh),
        pinned: pinStatus !== -1,
        pinOrder: pinStatus !== -1 ? pinStatus : null,
        accessCount,
        path,
      });
      if (entries.length >= numEntries && numEntries > 0) break;
    } catch (err) {
      warnings.push(`Stopped parsing entries after offset ${entryStart}: ${err.message}`);
      break;
    }
  }

  return { version, numEntries, numPinned, entries, warnings };
}
