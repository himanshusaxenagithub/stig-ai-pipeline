/* Minimal ZIP reader/writer. STORE only — no compression, no extra dependency.
   packaging/build_site.py writes scanner-src.zip uncompressed so this file
   can unpack it in the browser and add the person's selection. */

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[i] = c >>> 0;
  }
  return t;
})();

function crc32(u8) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < u8.length; i++) c = CRC_TABLE[(c ^ u8[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}

function unzipStore(buf) {
  const view = new DataView(buf);
  const bytes = new Uint8Array(buf);
  let eocd = buf.byteLength - 22;
  while (eocd >= 0 && view.getUint32(eocd, true) !== 0x06054b50) eocd--;
  if (eocd < 0) throw new Error("not a zip file");
  const n = view.getUint16(eocd + 10, true);
  let cd = view.getUint32(eocd + 16, true);
  const files = {};
  for (let i = 0; i < n; i++) {
    if (view.getUint32(cd, true) !== 0x02014b50) throw new Error("bad zip directory");
    const method = view.getUint16(cd + 10, true);
    const comp = view.getUint32(cd + 20, true);
    const nameLen = view.getUint16(cd + 28, true);
    const extraLen = view.getUint16(cd + 30, true);
    const commentLen = view.getUint16(cd + 32, true);
    const localOff = view.getUint32(cd + 42, true);
    const name = new TextDecoder().decode(bytes.subarray(cd + 46, cd + 46 + nameLen));
    const locName = view.getUint16(localOff + 26, true);
    const locExtra = view.getUint16(localOff + 28, true);
    const dataStart = localOff + 30 + locName + locExtra;
    cd += 46 + nameLen + extraLen + commentLen;
    if (name.endsWith("/")) continue;
    if (method !== 0) throw new Error("compressed zip not supported: " + name);
    files[name] = bytes.slice(dataStart, dataStart + comp);
  }
  return files;
}

function zipStore(files, prefix) {
  const enc = new TextEncoder();
  const locals = [];
  const centrals = [];
  let offset = 0;
  const names = Object.keys(files).sort();
  for (const rel of names) {
    const name = prefix ? prefix + rel : rel;
    const data = files[rel] instanceof Uint8Array ? files[rel] : enc.encode(String(files[rel]));
    const nameBytes = enc.encode(name);
    const crc = crc32(data);
    const exec = /\.(command|sh)$/.test(name);
    const mode = exec ? 0o100755 : 0o100644;
    const local = new Uint8Array(30 + nameBytes.length + data.length);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, 20, true);
    lv.setUint16(8, 0, true);
    lv.setUint32(14, crc, true);
    lv.setUint32(18, data.length, true);
    lv.setUint32(22, data.length, true);
    lv.setUint16(26, nameBytes.length, true);
    local.set(nameBytes, 30);
    local.set(data, 30 + nameBytes.length);
    locals.push(local);

    const central = new Uint8Array(46 + nameBytes.length);
    const cv = new DataView(central.buffer);
    cv.setUint32(0, 0x02014b50, true);
    // "version made by": high byte 3 = Unix. Without it, Archive Utility and
    // unzip treat the entry as MS-DOS and ignore the mode below, so the
    // .command files come out non-executable and macOS refuses to run them.
    cv.setUint16(4, (3 << 8) | 20, true);
    cv.setUint16(6, 20, true);
    cv.setUint32(16, crc, true);
    cv.setUint32(20, data.length, true);
    cv.setUint32(24, data.length, true);
    cv.setUint16(28, nameBytes.length, true);
    cv.setUint32(38, (mode << 16) >>> 0, true);
    cv.setUint32(42, offset, true);
    central.set(nameBytes, 46);
    centrals.push(central);
    offset += local.length;
  }
  const cdSize = centrals.reduce((n, c) => n + c.length, 0);
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, names.length, true);
  ev.setUint16(10, names.length, true);
  ev.setUint32(12, cdSize, true);
  ev.setUint32(16, offset, true);
  return new Blob([...locals, ...centrals, eocd], {type: "application/zip"});
}
