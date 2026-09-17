// Pure-JS parser for the Windows Shell Link Binary File Format ([MS-SHLLINK]).
// Read-only: never attempts to execute or resolve the target on this machine.

const FILE_ATTR_FLAGS = [
  [0x1, 'READONLY'], [0x2, 'HIDDEN'], [0x4, 'SYSTEM'], [0x10, 'DIRECTORY'],
  [0x20, 'ARCHIVE'], [0x80, 'NORMAL'], [0x100, 'TEMPORARY'], [0x200, 'SPARSE_FILE'],
  [0x400, 'REPARSE_POINT'], [0x800, 'COMPRESSED'], [0x1000, 'OFFLINE'],
  [0x2000, 'NOT_CONTENT_INDEXED'], [0x4000, 'ENCRYPTED'],
];

const DRIVE_TYPES = {
  0: 'Unknown', 1: 'No root directory', 2: 'Removable', 3: 'Fixed (hard disk)',
  4: 'Remote (network)', 5: 'CD-ROM', 6: 'RAM disk',
};

const SHOW_COMMANDS = { 1: 'Normal window', 3: 'Maximized', 7: 'Minimized (not active)' };

const KNOWN_FOLDER_NAMES = {
  '374de290-123f-4565-9164-39c4925e467b': 'Downloads',
  'fdd39ad0-238f-46af-adb4-6c85480369c7': 'Documents',
  '1cf1260c-4dd0-4ebb-811f-33c572699fde': 'Music (user)',
  '3dfdf296-dbec-4fb4-81d1-6a3438bcf4de': 'Pictures',
  '4c5c32ff-bb9d-43b0-b5b4-2d72e54eaaa4': 'Saved Games',
  'b4bfcc3a-db2c-424c-b029-7fe99a87c641': 'Desktop',
  '5e6c858f-0e22-4760-9afe-ea3317b67173': 'Profile (home)',
};

const EXTRA_BLOCK_NAMES = {
  0xa0000001: 'EnvironmentVariableDataBlock',
  0xa0000002: 'ConsoleDataBlock',
  0xa0000003: 'TrackerDataBlock',
  0xa0000004: 'ConsoleFEDataBlock',
  0xa0000005: 'SpecialFolderDataBlock',
  0xa0000006: 'DarwinDataBlock',
  0xa0000007: 'IconEnvironmentDataBlock',
  0xa0000008: 'ShimDataBlock',
  0xa0000009: 'PropertyStoreDataBlock',
  0xa000000a: 'KnownFolderLocation? (unused signature)',
  0xa000000b: 'KnownFolderDataBlock',
  0xa000000c: 'VistaAndAboveIDListDataBlock',
};

function bytesToGuid(bytes, offset) {
  // GUID stored as: 4 bytes LE, 2 bytes LE, 2 bytes LE, 8 bytes big-endian-ish (as-is)
  const d = (i) => bytes[offset + i];
  const hex = (n, len) => n.toString(16).padStart(len, '0');
  const p1 = (d(3) << 24 | d(2) << 16 | d(1) << 8 | d(0)) >>> 0;
  const p2 = (d(5) << 8 | d(4));
  const p3 = (d(7) << 8 | d(6));
  const p4 = Array.from(bytes.slice(offset + 8, offset + 16)).map((b) => hex(b, 2)).join('');
  return `${hex(p1, 8)}-${hex(p2, 4)}-${hex(p3, 4)}-${p4.slice(0, 4)}-${p4.slice(4)}`;
}

function filetimeToDate(low, high) {
  const ticks = (BigInt(high) << 32n) | BigInt(low >>> 0);
  if (ticks === 0n) return null;
  const EPOCH_DIFF = 116444736000000000n; // 100ns intervals between 1601-01-01 and 1970-01-01
  const ms = (ticks - EPOCH_DIFF) / 10000n;
  const msNum = Number(ms);
  if (!isFinite(msNum) || msNum < -8.64e15 || msNum > 8.64e15) return null;
  return new Date(msNum);
}

function readCString(view, offset, maxLen, encoding) {
  let end = offset;
  const limit = maxLen != null ? offset + maxLen : view.byteLength;
  if (encoding === 'utf16le') {
    while (end + 1 < limit && !(view.getUint8(end) === 0 && view.getUint8(end + 1) === 0)) end += 2;
    const bytes = new Uint8Array(view.buffer, view.byteOffset + offset, end - offset);
    return new TextDecoder('utf-16le').decode(bytes);
  }
  while (end < limit && view.getUint8(end) !== 0) end++;
  const bytes = new Uint8Array(view.buffer, view.byteOffset + offset, end - offset);
  return new TextDecoder('windows-1252').decode(bytes);
}

export function parseLnk(arrayBuffer) {
  const view = new DataView(arrayBuffer);
  const bytes = new Uint8Array(arrayBuffer);
  const result = { header: {}, linkInfo: null, strings: {}, extraBlocks: [], warnings: [] };

  if (arrayBuffer.byteLength < 76) throw new Error('File is too small to be a valid .lnk (needs at least 76 bytes)');

  const headerSize = view.getUint32(0, true);
  if (headerSize !== 0x4c) throw new Error('Not a Shell Link file (unexpected header size 0x' + headerSize.toString(16) + ', expected 0x4C)');

  const clsid = bytesToGuid(bytes, 4);
  if (clsid.toLowerCase() !== '00021401-0000-0000-c000-000000000046') {
    result.warnings.push('LinkCLSID does not match the standard Shell Link class ID — file may be corrupt or non-standard.');
  }

  const linkFlags = view.getUint32(20, true);
  const FLAGS = {
    HasLinkTargetIDList: 1 << 0, HasLinkInfo: 1 << 1, HasName: 1 << 2,
    HasRelativePath: 1 << 3, HasWorkingDir: 1 << 4, HasArguments: 1 << 5,
    HasIconLocation: 1 << 6, IsUnicode: 1 << 7, ForceNoLinkInfo: 1 << 8,
    RunAsUser: 1 << 13, HasExpIcon: 1 << 14,
  };
  const flag = (bit) => (linkFlags & bit) !== 0;

  const fileAttributes = view.getUint32(24, true);
  const attrNames = FILE_ATTR_FLAGS.filter(([bit]) => (fileAttributes & bit) !== 0).map(([, n]) => n);

  const creationTime = filetimeToDate(view.getUint32(28, true), view.getUint32(32, true));
  const accessTime = filetimeToDate(view.getUint32(36, true), view.getUint32(40, true));
  const writeTime = filetimeToDate(view.getUint32(44, true), view.getUint32(48, true));

  const fileSize = view.getUint32(52, true);
  const iconIndex = view.getInt32(56, true);
  const showCommand = view.getUint32(60, true);
  const hotkeyRaw = view.getUint16(64, true);
  const hotkeyVK = hotkeyRaw & 0xff;
  const hotkeyMods = (hotkeyRaw >> 8) & 0xff;
  const modNames = [];
  if (hotkeyMods & 0x1) modNames.push('Shift');
  if (hotkeyMods & 0x2) modNames.push('Ctrl');
  if (hotkeyMods & 0x4) modNames.push('Alt');

  result.header = {
    linkCLSID: clsid,
    fileAttributes: attrNames,
    creationTime, accessTime, writeTime,
    targetFileSize: fileSize,
    iconIndex,
    showCommand: SHOW_COMMANDS[showCommand] || `Unknown (${showCommand})`,
    hotkey: hotkeyVK ? [...modNames, 'VK 0x' + hotkeyVK.toString(16)].join('+') : null,
    isUnicode: flag(FLAGS.IsUnicode),
    runAsAdministrator: flag(FLAGS.RunAsUser),
  };

  let pos = 76;

  if (flag(FLAGS.HasLinkTargetIDList)) {
    const idListSize = view.getUint16(pos, true);
    pos += 2;
    const idListStart = pos;
    let itemCount = 0;
    let p = pos;
    while (p < idListStart + idListSize - 2) {
      const itemSize = view.getUint16(p, true);
      if (itemSize === 0) break;
      itemCount++;
      p += itemSize;
    }
    result.targetIdList = { byteSize: idListSize, itemCount };
    pos = idListStart + idListSize;
  }

  if (flag(FLAGS.HasLinkInfo)) {
    const linkInfoStart = pos;
    const linkInfoSize = view.getUint32(linkInfoStart, true);
    const liHeaderSize = view.getUint32(linkInfoStart + 4, true);
    const liFlags = view.getUint32(linkInfoStart + 8, true);
    const volumeIdOffset = view.getUint32(linkInfoStart + 12, true);
    const localBasePathOffset = view.getUint32(linkInfoStart + 16, true);
    const commonNetOffset = view.getUint32(linkInfoStart + 20, true);
    const commonPathSuffixOffset = view.getUint32(linkInfoStart + 24, true);
    let localBasePathOffsetUnicode = 0, commonPathSuffixOffsetUnicode = 0;
    if (liHeaderSize >= 0x24) {
      localBasePathOffsetUnicode = view.getUint32(linkInfoStart + 28, true);
      commonPathSuffixOffsetUnicode = view.getUint32(linkInfoStart + 32, true);
    }

    const li = { volume: null, localBasePath: null, network: null, commonPathSuffix: null, fullPath: null };

    if ((liFlags & 0x1) && volumeIdOffset) {
      const vs = linkInfoStart + volumeIdOffset;
      const driveType = view.getUint32(vs + 4, true);
      const driveSerial = view.getUint32(vs + 8, true);
      const volLabelOffset = view.getUint32(vs + 12, true);
      let volumeLabel;
      if (volLabelOffset === 0x14) {
        const volLabelOffsetUnicode = view.getUint32(vs + 16, true);
        volumeLabel = readCString(view, vs + volLabelOffsetUnicode, null, 'utf16le');
      } else {
        volumeLabel = readCString(view, vs + volLabelOffset, null, 'ansi');
      }
      li.volume = {
        driveType: DRIVE_TYPES[driveType] || `Unknown (${driveType})`,
        driveSerialNumber: '0x' + driveSerial.toString(16).toUpperCase().padStart(8, '0'),
        volumeLabel,
      };
    }

    if (localBasePathOffsetUnicode) {
      li.localBasePath = readCString(view, linkInfoStart + localBasePathOffsetUnicode, null, 'utf16le');
    } else if ((liFlags & 0x1) && localBasePathOffset) {
      li.localBasePath = readCString(view, linkInfoStart + localBasePathOffset, null, 'ansi');
    }

    if ((liFlags & 0x2) && commonNetOffset) {
      const cs = linkInfoStart + commonNetOffset;
      const netFlags = view.getUint32(cs + 4, true);
      const netNameOffset = view.getUint32(cs + 8, true);
      const deviceNameOffset = view.getUint32(cs + 12, true);
      let netName, deviceName = null;
      if (netNameOffset > 0x14) {
        const netNameOffsetUnicode = view.getUint32(cs + 16, true);
        const deviceNameOffsetUnicode = view.getUint32(cs + 20, true);
        netName = readCString(view, cs + netNameOffsetUnicode, null, 'utf16le');
        if (netFlags & 0x1) deviceName = readCString(view, cs + deviceNameOffsetUnicode, null, 'utf16le');
      } else {
        netName = readCString(view, cs + netNameOffset, null, 'ansi');
        if (netFlags & 0x1) deviceName = readCString(view, cs + deviceNameOffset, null, 'ansi');
      }
      li.network = { netName, deviceName };
    }

    if (commonPathSuffixOffsetUnicode) {
      li.commonPathSuffix = readCString(view, linkInfoStart + commonPathSuffixOffsetUnicode, null, 'utf16le');
    } else if (commonPathSuffixOffset) {
      li.commonPathSuffix = readCString(view, linkInfoStart + commonPathSuffixOffset, null, 'ansi');
    }

    const base = li.localBasePath || (li.network ? li.network.netName : null);
    if (base) {
      const suffix = li.commonPathSuffix || '';
      const sep = base.endsWith('\\') || suffix.startsWith('\\') || !suffix ? '' : '\\';
      li.fullPath = base + sep + suffix;
    }

    result.linkInfo = li;
    pos = linkInfoStart + linkInfoSize;
  }

  const stringEncoding = flag(FLAGS.IsUnicode) ? 'utf16le' : 'ansi';
  function readStringData(label) {
    const charCount = view.getUint16(pos, true);
    pos += 2;
    const byteLen = stringEncoding === 'utf16le' ? charCount * 2 : charCount;
    const bytesSlice = new Uint8Array(arrayBuffer, pos, byteLen);
    const text = stringEncoding === 'utf16le'
      ? new TextDecoder('utf-16le').decode(bytesSlice)
      : new TextDecoder('windows-1252').decode(bytesSlice);
    pos += byteLen;
    result.strings[label] = text;
  }

  if (flag(FLAGS.HasName)) readStringData('name');
  if (flag(FLAGS.HasRelativePath)) readStringData('relativePath');
  if (flag(FLAGS.HasWorkingDir)) readStringData('workingDir');
  if (flag(FLAGS.HasArguments)) readStringData('commandLineArguments');
  if (flag(FLAGS.HasIconLocation)) readStringData('iconLocation');

  // ExtraData blocks
  while (pos + 4 <= arrayBuffer.byteLength) {
    const blockSize = view.getUint32(pos, true);
    if (blockSize < 4) break; // terminal block or corrupt
    if (blockSize === 4) { pos += 4; break; }
    if (pos + blockSize > arrayBuffer.byteLength) {
      result.warnings.push('An ExtraData block claims a size larger than the remaining file — stopping extra-block parsing.');
      break;
    }
    const signature = view.getUint32(pos + 4, true);
    const blockName = EXTRA_BLOCK_NAMES[signature] || `Unknown block (signature 0x${signature.toString(16)})`;
    const block = { signature: '0x' + signature.toString(16), name: blockName, size: blockSize };

    try {
      if (signature === 0xa0000003 && blockSize >= 0x60) {
        // TrackerDataBlock
        const dataStart = pos + 16; // skip BlockSize+Signature+Length+Version
        const machineId = readCString(view, dataStart, 16, 'ansi');
        const droidVolume = bytesToGuid(bytes, dataStart + 16);
        const droidFile = bytesToGuid(bytes, dataStart + 32);
        const droidBirthVolume = bytesToGuid(bytes, dataStart + 48);
        const droidBirthFile = bytesToGuid(bytes, dataStart + 64);
        block.machineId = machineId;
        block.droidVolumeId = droidVolume;
        block.droidFileId = droidFile;
        block.droidBirthVolumeId = droidBirthVolume;
        block.droidBirthFileId = droidBirthFile;
      } else if ((signature === 0xa0000001 || signature === 0xa0000007) && blockSize >= 8 + 260 + 520) {
        // EnvironmentVariableDataBlock / IconEnvironmentDataBlock
        const ansi = readCString(view, pos + 8, 260, 'ansi');
        const unicode = readCString(view, pos + 8 + 260, 520, 'utf16le');
        block.targetAnsi = ansi;
        block.targetUnicode = unicode || ansi;
      } else if (signature === 0xa0000006 && blockSize >= 8 + 260 + 520 + 8) {
        const darwinAnsi = readCString(view, pos + 8, 260, 'ansi');
        const darwinUnicode = readCString(view, pos + 8 + 260, 520, 'utf16le');
        block.darwinApplicationId = darwinUnicode || darwinAnsi;
      } else if (signature === 0xa0000005 && blockSize >= 16) {
        block.specialFolderId = view.getUint32(pos + 8, true);
      } else if (signature === 0xa000000b && blockSize >= 24) {
        block.knownFolderId = bytesToGuid(bytes, pos + 8);
        block.knownFolderName = KNOWN_FOLDER_NAMES[block.knownFolderId.toLowerCase()] || null;
      } else if (signature === 0xa0000008 && blockSize > 8) {
        block.layerName = readCString(view, pos + 8, blockSize - 8, 'utf16le');
      } else if (signature === 0xa0000004 && blockSize >= 12) {
        block.codePage = view.getUint32(pos + 8, true);
      }
    } catch (e) {
      block.decodeError = e.message;
    }

    result.extraBlocks.push(block);
    pos += blockSize;
  }

  return result;
}
