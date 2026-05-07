function dataLengthError(actual, required) {
    throw new Error(`Invalid data length! Required: ${required}, actual: ${actual}`);
}

function assertDataLength(actual, required) {
  if (actual !== required) {
    dataLengthError(actual, required);
  }
}

function assertArrayBuffer(reader) {
  if (reader instanceof Object && reader.toArrayBuffer instanceof Function) {
    reader = reader.toArrayBuffer();
  }
  if (!(reader instanceof ArrayBuffer)) {
    throw new Error("Provided value must be an ArrayBuffer or can be transformed into ArrayBuffer!");
  }
  return reader;
}

function verifyAndExtractOffsets(view, expectedFieldCount, compatible) {
  if (view.byteLength < 4) {
    dataLengthError(view.byteLength, ">4");
  }
  const requiredByteLength = view.getUint32(0, true);
  assertDataLength(view.byteLength, requiredByteLength);
  if (requiredByteLength === 4) {
    return [requiredByteLength];
  }
  if (requiredByteLength < 8) {
    dataLengthError(view.byteLength, ">8");
  }
  const firstOffset = view.getUint32(4, true);
  if (firstOffset % 4 !== 0 || firstOffset < 8) {
    throw new Error(`Invalid first offset: ${firstOffset}`);
  }
  const itemCount = firstOffset / 4 - 1;
  if (itemCount < expectedFieldCount) {
    throw new Error(`Item count not enough! Required: ${expectedFieldCount}, actual: ${itemCount}`);
  } else if ((!compatible) && itemCount > expectedFieldCount) {
    throw new Error(`Item count is more than required! Required: ${expectedFieldCount}, actual: ${itemCount}`);
  }
  if (requiredByteLength < firstOffset) {
    throw new Error(`First offset is larger than byte length: ${firstOffset}`);
  }
  const offsets = [];
  for (let i = 0; i < itemCount; i++) {
    const start = 4 + i * 4;
    offsets.push(view.getUint32(start, true));
  }
  offsets.push(requiredByteLength);
  for (let i = 0; i < offsets.length - 1; i++) {
    if (offsets[i] > offsets[i + 1]) {
      throw new Error(`Offset index ${i}: ${offsets[i]} is larger than offset index ${i + 1}: ${offsets[i + 1]}`);
    }
  }
  return offsets;
}

function serializeTable(buffers) {
  const itemCount = buffers.length;
  let totalSize = 4 * (itemCount + 1);
  const offsets = [];

  for (let i = 0; i < itemCount; i++) {
    offsets.push(totalSize);
    totalSize += buffers[i].byteLength;
  }

  const buffer = new ArrayBuffer(totalSize);
  const array = new Uint8Array(buffer);
  const view = new DataView(buffer);

  view.setUint32(0, totalSize, true);
  for (let i = 0; i < itemCount; i++) {
    view.setUint32(4 + i * 4, offsets[i], true);
    array.set(new Uint8Array(buffers[i]), offsets[i]);
  }
  return buffer;
}

export class Uint16 {
  constructor(reader, { validate = true } = {}) {
    this.view = new DataView(assertArrayBuffer(reader));
    if (validate) {
      this.validate();
    }
  }

  validate(compatible = false) {
    assertDataLength(this.view.byteLength, 2);
  }

  indexAt(i) {
    return this.view.getUint8(i);
  }

  raw() {
    return this.view.buffer;
  }

  toBigEndianUint16() {
    return this.view.getUint16(0, false);
  }

  toLittleEndianUint16() {
    return this.view.getUint16(0, true);
  }

  static size() {
    return 2;
  }
}

export function SerializeUint16(value) {
  const buffer = assertArrayBuffer(value);
  assertDataLength(buffer.byteLength, 2);
  return buffer;
}

export class G1Compressed {
  constructor(reader, { validate = true } = {}) {
    this.view = new DataView(assertArrayBuffer(reader));
    if (validate) {
      this.validate();
    }
  }

  validate(compatible = false) {
    assertDataLength(this.view.byteLength, 32);
  }

  indexAt(i) {
    return this.view.getUint8(i);
  }

  raw() {
    return this.view.buffer;
  }

  static size() {
    return 32;
  }
}

export function SerializeG1Compressed(value) {
  const buffer = assertArrayBuffer(value);
  assertDataLength(buffer.byteLength, 32);
  return buffer;
}

export class G2Compressed {
  constructor(reader, { validate = true } = {}) {
    this.view = new DataView(assertArrayBuffer(reader));
    if (validate) {
      this.validate();
    }
  }

  validate(compatible = false) {
    assertDataLength(this.view.byteLength, 64);
  }

  indexAt(i) {
    return this.view.getUint8(i);
  }

  raw() {
    return this.view.buffer;
  }

  static size() {
    return 64;
  }
}

export function SerializeG2Compressed(value) {
  const buffer = assertArrayBuffer(value);
  assertDataLength(buffer.byteLength, 64);
  return buffer;
}

export class Byte32 {
  constructor(reader, { validate = true } = {}) {
    this.view = new DataView(assertArrayBuffer(reader));
    if (validate) {
      this.validate();
    }
  }

  validate(compatible = false) {
    assertDataLength(this.view.byteLength, 32);
  }

  indexAt(i) {
    return this.view.getUint8(i);
  }

  raw() {
    return this.view.buffer;
  }

  static size() {
    return 32;
  }
}

export function SerializeByte32(value) {
  const buffer = assertArrayBuffer(value);
  assertDataLength(buffer.byteLength, 32);
  return buffer;
}

export class G1Vec {
  constructor(reader, { validate = true } = {}) {
    this.view = new DataView(assertArrayBuffer(reader));
    if (validate) {
      this.validate();
    }
  }

  validate(compatible = false) {
    if (this.view.byteLength < 4) {
      dataLengthError(this.view.byteLength, ">4");
    }
    const requiredByteLength = this.length() * G1Compressed.size() + 4;
    assertDataLength(this.view.byteLength, requiredByteLength);
    for (let i = 0; i < 0; i++) {
      const item = this.indexAt(i);
      item.validate(compatible);
    }
  }

  indexAt(i) {
    return new G1Compressed(this.view.buffer.slice(4 + i * G1Compressed.size(), 4 + (i + 1) * G1Compressed.size()), { validate: false });
  }

  length() {
    return this.view.getUint32(0, true);
  }
}

export function SerializeG1Vec(value) {
  const array = new Uint8Array(4 + G1Compressed.size() * value.length);
  (new DataView(array.buffer)).setUint32(0, value.length, true);
  for (let i = 0; i < value.length; i++) {
    const itemBuffer = SerializeG1Compressed(value[i]);
    array.set(new Uint8Array(itemBuffer), 4 + i * G1Compressed.size());
  }
  return array.buffer;
}

export class FrVec {
  constructor(reader, { validate = true } = {}) {
    this.view = new DataView(assertArrayBuffer(reader));
    if (validate) {
      this.validate();
    }
  }

  validate(compatible = false) {
    if (this.view.byteLength < 4) {
      dataLengthError(this.view.byteLength, ">4");
    }
    const requiredByteLength = this.length() * Byte32.size() + 4;
    assertDataLength(this.view.byteLength, requiredByteLength);
    for (let i = 0; i < 0; i++) {
      const item = this.indexAt(i);
      item.validate(compatible);
    }
  }

  indexAt(i) {
    return new Byte32(this.view.buffer.slice(4 + i * Byte32.size(), 4 + (i + 1) * Byte32.size()), { validate: false });
  }

  length() {
    return this.view.getUint32(0, true);
  }
}

export function SerializeFrVec(value) {
  const array = new Uint8Array(4 + Byte32.size() * value.length);
  (new DataView(array.buffer)).setUint32(0, value.length, true);
  for (let i = 0; i < value.length; i++) {
    const itemBuffer = SerializeByte32(value[i]);
    array.set(new Uint8Array(itemBuffer), 4 + i * Byte32.size());
  }
  return array.buffer;
}

export class ProofBn254 {
  constructor(reader, { validate = true } = {}) {
    this.view = new DataView(assertArrayBuffer(reader));
    if (validate) {
      this.validate();
    }
  }

  getA() {
    return new G1Compressed(this.view.buffer.slice(0, 0 + G1Compressed.size()), { validate: false });
  }

  getB() {
    return new G2Compressed(this.view.buffer.slice(0 + G1Compressed.size(), 0 + G1Compressed.size() + G2Compressed.size()), { validate: false });
  }

  getC() {
    return new G1Compressed(this.view.buffer.slice(0 + G1Compressed.size() + G2Compressed.size(), 0 + G1Compressed.size() + G2Compressed.size() + G1Compressed.size()), { validate: false });
  }

  validate(compatible = false) {
    assertDataLength(this.view.byteLength, ProofBn254.size());
    this.getA().validate(compatible);
    this.getB().validate(compatible);
    this.getC().validate(compatible);
  }
  static size() {
    return 0 + G1Compressed.size() + G2Compressed.size() + G1Compressed.size();
  }
}

export function SerializeProofBn254(value) {
  const array = new Uint8Array(0 + G1Compressed.size() + G2Compressed.size() + G1Compressed.size());
  const view = new DataView(array.buffer);
  array.set(new Uint8Array(SerializeG1Compressed(value.a)), 0);
  array.set(new Uint8Array(SerializeG2Compressed(value.b)), 0 + G1Compressed.size());
  array.set(new Uint8Array(SerializeG1Compressed(value.c)), 0 + G1Compressed.size() + G2Compressed.size());
  return array.buffer;
}

export class VerifyingKeyBn254 {
  constructor(reader, { validate = true } = {}) {
    this.view = new DataView(assertArrayBuffer(reader));
    if (validate) {
      this.validate();
    }
  }

  validate(compatible = false) {
    const offsets = verifyAndExtractOffsets(this.view, 0, true);
    new G1Compressed(this.view.buffer.slice(offsets[0], offsets[1]), { validate: false }).validate();
    new G2Compressed(this.view.buffer.slice(offsets[1], offsets[2]), { validate: false }).validate();
    new G2Compressed(this.view.buffer.slice(offsets[2], offsets[3]), { validate: false }).validate();
    new G2Compressed(this.view.buffer.slice(offsets[3], offsets[4]), { validate: false }).validate();
    new G1Vec(this.view.buffer.slice(offsets[4], offsets[5]), { validate: false }).validate();
  }

  getAlphaG1() {
    const start = 4;
    const offset = this.view.getUint32(start, true);
    const offset_end = this.view.getUint32(start + 4, true);
    return new G1Compressed(this.view.buffer.slice(offset, offset_end), { validate: false });
  }

  getBetaG2() {
    const start = 8;
    const offset = this.view.getUint32(start, true);
    const offset_end = this.view.getUint32(start + 4, true);
    return new G2Compressed(this.view.buffer.slice(offset, offset_end), { validate: false });
  }

  getGammaG2() {
    const start = 12;
    const offset = this.view.getUint32(start, true);
    const offset_end = this.view.getUint32(start + 4, true);
    return new G2Compressed(this.view.buffer.slice(offset, offset_end), { validate: false });
  }

  getDeltaG2() {
    const start = 16;
    const offset = this.view.getUint32(start, true);
    const offset_end = this.view.getUint32(start + 4, true);
    return new G2Compressed(this.view.buffer.slice(offset, offset_end), { validate: false });
  }

  getGammaAbcG1() {
    const start = 20;
    const offset = this.view.getUint32(start, true);
    const offset_end = this.view.byteLength;
    return new G1Vec(this.view.buffer.slice(offset, offset_end), { validate: false });
  }
}

export function SerializeVerifyingKeyBn254(value) {
  const buffers = [];
  buffers.push(SerializeG1Compressed(value.alpha_g1));
  buffers.push(SerializeG2Compressed(value.beta_g2));
  buffers.push(SerializeG2Compressed(value.gamma_g2));
  buffers.push(SerializeG2Compressed(value.delta_g2));
  buffers.push(SerializeG1Vec(value.gamma_abc_g1));
  return serializeTable(buffers);
}

export class Bn254Witness {
  constructor(reader, { validate = true } = {}) {
    this.view = new DataView(assertArrayBuffer(reader));
    if (validate) {
      this.validate();
    }
  }

  validate(compatible = false) {
    const offsets = verifyAndExtractOffsets(this.view, 0, true);
    new ProofBn254(this.view.buffer.slice(offsets[0], offsets[1]), { validate: false }).validate();
    new FrVec(this.view.buffer.slice(offsets[1], offsets[2]), { validate: false }).validate();
  }

  getProof() {
    const start = 4;
    const offset = this.view.getUint32(start, true);
    const offset_end = this.view.getUint32(start + 4, true);
    return new ProofBn254(this.view.buffer.slice(offset, offset_end), { validate: false });
  }

  getPublicInputs() {
    const start = 8;
    const offset = this.view.getUint32(start, true);
    const offset_end = this.view.byteLength;
    return new FrVec(this.view.buffer.slice(offset, offset_end), { validate: false });
  }
}

export function SerializeBn254Witness(value) {
  const buffers = [];
  buffers.push(SerializeProofBn254(value.proof));
  buffers.push(SerializeFrVec(value.public_inputs));
  return serializeTable(buffers);
}

export class VerifyingKeyContent {
  constructor(reader, { validate = true } = {}) {
    this.view = new DataView(assertArrayBuffer(reader));
    if (validate) {
      this.validate();
    }
  }

  validate(compatible = false) {
    if (this.view.byteLength < 4) {
      assertDataLength(this.view.byteLength, ">4");
    }
    const t = this.view.getUint32(0, true);
    switch (t) {
    case 0:
      new VerifyingKeyBn254(this.view.buffer.slice(4), { validate: false }).validate();
      break;
    default:
      throw new Error(`Invalid type: ${t}`);
    }
  }

  unionType() {
    const t = this.view.getUint32(0, true);
    switch (t) {
    case 0:
      return "VerifyingKeyBn254";
    default:
      throw new Error(`Invalid type: ${t}`);
    }
  }

  value() {
    const t = this.view.getUint32(0, true);
    switch (t) {
    case 0:
      return new VerifyingKeyBn254(this.view.buffer.slice(4), { validate: false });
    default:
      throw new Error(`Invalid type: ${t}`);
    }
  }
}

export function SerializeVerifyingKeyContent(value) {
  switch (value.type) {
  case "VerifyingKeyBn254":
    {
      const itemBuffer = SerializeVerifyingKeyBn254(value.value);
      const array = new Uint8Array(4 + itemBuffer.byteLength);
      const view = new DataView(array.buffer);
      view.setUint32(0, 0, true);
      array.set(new Uint8Array(itemBuffer), 4);
      return array.buffer;
    }
  default:
    throw new Error(`Invalid type: ${value.type}`);
  }
}

export class WitnessContent {
  constructor(reader, { validate = true } = {}) {
    this.view = new DataView(assertArrayBuffer(reader));
    if (validate) {
      this.validate();
    }
  }

  validate(compatible = false) {
    if (this.view.byteLength < 4) {
      assertDataLength(this.view.byteLength, ">4");
    }
    const t = this.view.getUint32(0, true);
    switch (t) {
    case 0:
      new Bn254Witness(this.view.buffer.slice(4), { validate: false }).validate();
      break;
    default:
      throw new Error(`Invalid type: ${t}`);
    }
  }

  unionType() {
    const t = this.view.getUint32(0, true);
    switch (t) {
    case 0:
      return "Bn254Witness";
    default:
      throw new Error(`Invalid type: ${t}`);
    }
  }

  value() {
    const t = this.view.getUint32(0, true);
    switch (t) {
    case 0:
      return new Bn254Witness(this.view.buffer.slice(4), { validate: false });
    default:
      throw new Error(`Invalid type: ${t}`);
    }
  }
}

export function SerializeWitnessContent(value) {
  switch (value.type) {
  case "Bn254Witness":
    {
      const itemBuffer = SerializeBn254Witness(value.value);
      const array = new Uint8Array(4 + itemBuffer.byteLength);
      const view = new DataView(array.buffer);
      view.setUint32(0, 0, true);
      array.set(new Uint8Array(itemBuffer), 4);
      return array.buffer;
    }
  default:
    throw new Error(`Invalid type: ${value.type}`);
  }
}

export class Groth16VerifyingKey {
  constructor(reader, { validate = true } = {}) {
    this.view = new DataView(assertArrayBuffer(reader));
    if (validate) {
      this.validate();
    }
  }

  validate(compatible = false) {
    const offsets = verifyAndExtractOffsets(this.view, 0, true);
    new Uint16(this.view.buffer.slice(offsets[0], offsets[1]), { validate: false }).validate();
    new VerifyingKeyContent(this.view.buffer.slice(offsets[1], offsets[2]), { validate: false }).validate();
  }

  getVersion() {
    const start = 4;
    const offset = this.view.getUint32(start, true);
    const offset_end = this.view.getUint32(start + 4, true);
    return new Uint16(this.view.buffer.slice(offset, offset_end), { validate: false });
  }

  getContent() {
    const start = 8;
    const offset = this.view.getUint32(start, true);
    const offset_end = this.view.byteLength;
    return new VerifyingKeyContent(this.view.buffer.slice(offset, offset_end), { validate: false });
  }
}

export function SerializeGroth16VerifyingKey(value) {
  const buffers = [];
  buffers.push(SerializeUint16(value.version));
  buffers.push(SerializeVerifyingKeyContent(value.content));
  return serializeTable(buffers);
}

export class Groth16Witness {
  constructor(reader, { validate = true } = {}) {
    this.view = new DataView(assertArrayBuffer(reader));
    if (validate) {
      this.validate();
    }
  }

  validate(compatible = false) {
    const offsets = verifyAndExtractOffsets(this.view, 0, true);
    new Uint16(this.view.buffer.slice(offsets[0], offsets[1]), { validate: false }).validate();
    new WitnessContent(this.view.buffer.slice(offsets[1], offsets[2]), { validate: false }).validate();
  }

  getVersion() {
    const start = 4;
    const offset = this.view.getUint32(start, true);
    const offset_end = this.view.getUint32(start + 4, true);
    return new Uint16(this.view.buffer.slice(offset, offset_end), { validate: false });
  }

  getContent() {
    const start = 8;
    const offset = this.view.getUint32(start, true);
    const offset_end = this.view.byteLength;
    return new WitnessContent(this.view.buffer.slice(offset, offset_end), { validate: false });
  }
}

export function SerializeGroth16Witness(value) {
  const buffers = [];
  buffers.push(SerializeUint16(value.version));
  buffers.push(SerializeWitnessContent(value.content));
  return serializeTable(buffers);
}

