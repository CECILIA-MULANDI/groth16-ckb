export interface CastToArrayBuffer {
  toArrayBuffer(): ArrayBuffer;
}

export type CanCastToArrayBuffer = ArrayBuffer | CastToArrayBuffer;

export interface CreateOptions {
  validate?: boolean;
}

export interface UnionType {
  type: string;
  value: any;
}

export type Uint16Type = CanCastToArrayBuffer;

export type G1CompressedType = CanCastToArrayBuffer;

export type G2CompressedType = CanCastToArrayBuffer;

export type Byte32Type = CanCastToArrayBuffer;

export type G1VecType = G1CompressedType[];

export type FrVecType = Byte32Type[];

export interface ProofBn254Type {
  a: G1CompressedType;
  b: G2CompressedType;
  c: G1CompressedType;
}

export interface VerifyingKeyBn254Type {
  alpha_g1: G1CompressedType;
  beta_g2: G2CompressedType;
  gamma_g2: G2CompressedType;
  delta_g2: G2CompressedType;
  gamma_abc_g1: G1VecType;
}

export interface Bn254WitnessType {
  proof: ProofBn254Type;
  public_inputs: FrVecType;
}

export type VerifyingKeyContentType =
	|{ type: "VerifyingKeyBn254", value: VerifyingKeyBn254Type };

export type WitnessContentType =
	|{ type: "Bn254Witness", value: Bn254WitnessType };

export interface Groth16VerifyingKeyType {
  version: Uint16Type;
  content: VerifyingKeyContentType;
}

export interface Groth16WitnessType {
  version: Uint16Type;
  content: WitnessContentType;
}

export function SerializeUint16(value: CanCastToArrayBuffer): ArrayBuffer;
export class Uint16 {
  constructor(reader: CanCastToArrayBuffer, options?: CreateOptions);
  validate(compatible?: boolean): void;
  indexAt(i: number): number;
  raw(): ArrayBuffer;
  toBigEndianUint16(): number;
  toLittleEndianUint16(): number;
  static size(): Number;
}

export function SerializeG1Compressed(value: CanCastToArrayBuffer): ArrayBuffer;
export class G1Compressed {
  constructor(reader: CanCastToArrayBuffer, options?: CreateOptions);
  validate(compatible?: boolean): void;
  indexAt(i: number): number;
  raw(): ArrayBuffer;
  static size(): Number;
}

export function SerializeG2Compressed(value: CanCastToArrayBuffer): ArrayBuffer;
export class G2Compressed {
  constructor(reader: CanCastToArrayBuffer, options?: CreateOptions);
  validate(compatible?: boolean): void;
  indexAt(i: number): number;
  raw(): ArrayBuffer;
  static size(): Number;
}

export function SerializeByte32(value: CanCastToArrayBuffer): ArrayBuffer;
export class Byte32 {
  constructor(reader: CanCastToArrayBuffer, options?: CreateOptions);
  validate(compatible?: boolean): void;
  indexAt(i: number): number;
  raw(): ArrayBuffer;
  static size(): Number;
}

export function SerializeG1Vec(value: Array<G1CompressedType>): ArrayBuffer;
export class G1Vec {
  constructor(reader: CanCastToArrayBuffer, options?: CreateOptions);
  validate(compatible?: boolean): void;
  indexAt(i: number): G1Compressed;
  length(): number;
}

export function SerializeFrVec(value: Array<Byte32Type>): ArrayBuffer;
export class FrVec {
  constructor(reader: CanCastToArrayBuffer, options?: CreateOptions);
  validate(compatible?: boolean): void;
  indexAt(i: number): Byte32;
  length(): number;
}

export function SerializeProofBn254(value: ProofBn254Type): ArrayBuffer;
export class ProofBn254 {
  constructor(reader: CanCastToArrayBuffer, options?: CreateOptions);
  validate(compatible?: boolean): void;
  static size(): Number;
  getA(): G1Compressed;
  getB(): G2Compressed;
  getC(): G1Compressed;
}

export function SerializeVerifyingKeyBn254(value: VerifyingKeyBn254Type): ArrayBuffer;
export class VerifyingKeyBn254 {
  constructor(reader: CanCastToArrayBuffer, options?: CreateOptions);
  validate(compatible?: boolean): void;
  getAlphaG1(): G1Compressed;
  getBetaG2(): G2Compressed;
  getGammaG2(): G2Compressed;
  getDeltaG2(): G2Compressed;
  getGammaAbcG1(): G1Vec;
}

export function SerializeBn254Witness(value: Bn254WitnessType): ArrayBuffer;
export class Bn254Witness {
  constructor(reader: CanCastToArrayBuffer, options?: CreateOptions);
  validate(compatible?: boolean): void;
  getProof(): ProofBn254;
  getPublicInputs(): FrVec;
}

export function SerializeVerifyingKeyContent(value: VerifyingKeyContentType): ArrayBuffer;
export class VerifyingKeyContent {
  constructor(reader: CanCastToArrayBuffer, options?: CreateOptions);
  validate(compatible?: boolean): void;
  unionType(): string;
  value(): any;
}

export function SerializeWitnessContent(value: WitnessContentType): ArrayBuffer;
export class WitnessContent {
  constructor(reader: CanCastToArrayBuffer, options?: CreateOptions);
  validate(compatible?: boolean): void;
  unionType(): string;
  value(): any;
}

export function SerializeGroth16VerifyingKey(value: Groth16VerifyingKeyType): ArrayBuffer;
export class Groth16VerifyingKey {
  constructor(reader: CanCastToArrayBuffer, options?: CreateOptions);
  validate(compatible?: boolean): void;
  getVersion(): Uint16;
  getContent(): VerifyingKeyContent;
}

export function SerializeGroth16Witness(value: Groth16WitnessType): ArrayBuffer;
export class Groth16Witness {
  constructor(reader: CanCastToArrayBuffer, options?: CreateOptions);
  validate(compatible?: boolean): void;
  getVersion(): Uint16;
  getContent(): WitnessContent;
}

