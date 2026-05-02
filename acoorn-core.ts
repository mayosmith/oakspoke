/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 MSP LLC
 * See the LICENSE file at the repository root for the full MIT License text.
 */
import { createHash } from 'crypto';


// =============================================================================
// TYPES
// =============================================================================

export interface LocationParts {
  north: number;
  northHash: string;
  northSuffix: string;
  east: number;
  eastHash: string;
  eastSuffix: string;
}

export interface GeoKey {
  location: string;
  publicKey: string;
  privateKey: string;
}
export interface BalanceProof {
  balance: number;
  depth: number;
  emptyBits: string;
  siblings: string[];
}

export interface CompressedProof {
  depth: number;
  emptyBits: string;
  siblings: string[];
}

export interface Transaction {
  type: string;
  from: string;
  to: string;
  amount: number;
  fee: number;
  memo?: string;
  balanceProof: BalanceProof;
  signature: string;
  destinationOak?: string;
  interOakTransferProof?: InterOakTransferProof;
}

export interface InterOakTransferProof {
  sourceOak: string;
  amount: number;
  location: string;
  blockNumber: number;
  signature: string;
}



export interface ForagerSignature {
  forager: string;
  pubkey: string;
  signature: string;
}

export interface Reward {
  oakPrimeReward: number;       // minted oakReward (goes to oakPrime)
  oakPrimeFees: number;         // fee share to oakPrime: (100 - feeShare)%
  oakPrimeDust: number;         // rounding dust from forager distribution (added later)
  oakPrimeTotal: number;        // oakPrimeReward + oakPrimeFees (dust added after distribution)
  foragerPool: number;          // total pool for foragers before proportional distribution
  foragerFees: number;          // fee share to foragers: feeShare%
  totalMinted: number;          // oakReward + foragePool (new supply created)
  cycleFees: number;            // total transaction fees in the ending cycle
  isCycleBoundary: boolean;
  rewardCycle: number;
}

export interface ForagerRewards {
  [foragerLocation: string]: number;
}

export interface BlockCreationResult {
  create: boolean;
  reason: 'heartbeat' | 'transactions' | null;
}

/*

export interface Oak {
  chainId: string;
  genesis: string;
  seedValue: number;
  initialDaily: number;
  mastingCycleDays: number;
  depth: number;
  centralAuthority: string;
  foundingValidators: Validator[];
  recognizedOaks: string[];
}

export interface Validator {
  pubkey: string;
  location: string;
  stake: number;
  founding: boolean;
}
*/
export interface BalanceResponse {
  location: string;
  balance: number;
  proof: BalanceProof;
  stateRoot: string;
}

export interface TransactionResult {
  success: boolean;
  blockNumber?: number;
  error?: string;
  newLocation?: string; // If nudged due to collision
}


export interface BalanceSummary {
  count: number;
  total: number;
  lastBlock: number;
  checksum: string;
}

export interface BalancesFile {
  summary: BalanceSummary;
  balances: { [location: string]: number };
}

export interface BalanceResult {
  location: string;
  balance: number;
}

export interface AvailableBalance {
  location: string;
  provedBalance: number;
  pendingOut: number;
  pendingIn: number;
  available: number;
  stateRoot: string;
}


export interface Rewards {
  oakPrimeReward: number;
  oakPrimeFees: number;
  oakPrimeDust: number;
  oakPrimeTotal: number;
  foragerPool: number;
  foragerFees: number;
  totalMinted: number;
  cycleFees: number;
  isCycleBoundary: boolean;
  rewardCycle: number;
}

export interface ForagerSignatureEntry {
  signature: string;
  type: 'leader' | 'backup';
}

export interface Forager {
  forager: string;
  pubkey: string;
  signatures: ForagerSignatureEntry[];
}

export interface Block {
  block: number;
  created: string;
  prevBlockHash: string;
  prevStateRoot: string;
  stateRoot: string;
  finalized: string | null;
  transactions: Transaction[];
  rewards: Rewards;
  oakPrime: {
    location: string;
  };
  foragers: Forager[];
}


export interface ValidationResult {
  valid: boolean;
  error?: string;
  errors?: string[];
}

// =============================================================================
// CONSTANTS
// =============================================================================

export const TREE_DEPTH = 24;

// ---------------------------------------------------------------------------
// DEFAULTS — these are fallbacks. The canonical source of truth is block 0
// governance. The CA reads governance first and falls back to these values.
// If you change a value here, also update block 0 governance (and its hash).
// ---------------------------------------------------------------------------


// Block timing (not in governance — core only)
export const HEARTBEAT_INTERVAL = 24 * 60 * 60 * 1000;   // 24 hours

// Map and staking constants (not in governance)
export const MAP_WIDTH = 256;
export const MAP_HEIGHT = 256;

// =============================================================================
// CANONICAL FIELD ORDERS (alphabetical, for deterministic hashing)
// Must match forager.ino constants
// =============================================================================

// Block fields (alphabetical, blockHash is always null when computing hash)
// Flattened: rewards fields are at block level, oakPrime is just the location string
export const BLOCK_FIELDS = [
  'block', 'blockHash', 'created', 'fees', 'finalized', 'foragerReward',
  'foragers', 'governanceHash', 'lastRewardCycle', 'oakPrime', 'oakPrimeReward', 'prevBlockHash',
  'prevStateRoot', 'rewardCycle', 'stateRoot', 'transactions'
] as const;

// Forager fields (alphabetical)
export const FORAGER_FIELDS = [
  'count', 'forager', 'lastActive', 'pubkey', 'signature'
] as const;

// Transaction fields (alphabetical)
export const TRANSACTION_FIELDS = [
  'amount', 'fee', 'from', 'memo', 'pubkey', 'signature', 'to'
] as const;

// =============================================================================
// CRYPTO FUNCTIONS
// =============================================================================

/**
 * SHA-256 hash of a string, returned as hex
 */
export function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Create canonical JSON string with alphabetically sorted keys (recursive)
 */
function canonicalJSON(obj: any): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalJSON).join(',') + ']';
  }
  const sortedKeys = Object.keys(obj).sort();
  const pairs = sortedKeys.map(key => `"${key}":${canonicalJSON(obj[key])}`);
  return '{' + pairs.join(',') + '}';
}

/**
 * Stringify an object using specific canonical field order
 */
function canonicalStringifyWithFields(obj: any, fields: readonly string[]): string {
  if (obj === null || obj === undefined) {
    return 'null';
  }
  const pairs: string[] = [];
  for (const field of fields) {
    const value = obj[field] !== undefined ? canonicalJSON(obj[field]) : 'null';
    pairs.push(`"${field}":${value}`);
  }
  return '{' + pairs.join(',') + '}';
}

/**
 * Stringify an array of objects using specific canonical field order
 */
function canonicalStringifyArray(arr: any[], fields: readonly string[]): string {
  if (!arr || !Array.isArray(arr)) {
    return 'null';
  }
  const items = arr.map(item => canonicalStringifyWithFields(item, fields));
  return '[' + items.join(',') + ']';
}

/**
 * Calculate SHA256 hash of a block using canonical field order
 * Rule: blockHash is always null when computing the hash
 */
export function computeBlockHash(block: any): string {
  const pairs: string[] = [];
  
  for (const field of BLOCK_FIELDS) {
    let value: string;
    
    // blockHash and foragers are always null (JSON null value, not the string "null")
    if (field === 'blockHash' || field === 'foragers') {
      value = 'null';
    }
    // Transactions: canonical sub-field order, array stays in received order
    else if (field === 'transactions') {
      value = canonicalStringifyArray(block.transactions, TRANSACTION_FIELDS);
    }
    // Simple fields
    else {
      value = block[field] !== undefined ? canonicalJSON(block[field]) : 'null';
    }
    
    pairs.push(`"${field}":${value}`);
  }
  
  const blockString = '{' + pairs.join(',') + '}';
  return sha256(blockString);
}

/**
 * Build the canonical signing data for a block (excludes foragers).
 * Uses the same canonical field/array ordering as computeBlockHash,
 * so a forager can produce the identical string from raw JSON.
 */
export function computeBlockSigningData(block: any): string {
  const pairs: string[] = [];
  
  for (const field of BLOCK_FIELDS) {
    let value: string;
    
    // blockHash and foragers are always null (JSON null value, not the string "null")
    if (field === 'blockHash' || field === 'foragers') {
      value = 'null';
    }
    // Transactions: canonical sub-field order, array stays in received order
    else if (field === 'transactions') {
      value = canonicalStringifyArray(block.transactions, TRANSACTION_FIELDS);
    }
    // Simple fields
    else {
      value = block[field] !== undefined ? canonicalJSON(block[field]) : 'null';
    }
    
    pairs.push(`"${field}":${value}`);
  }
  
  return '{' + pairs.join(',') + '}';
}

/**
 * Return a block as a canonical JSON string with actual values.
 * Fields in BLOCK_FIELDS order, transaction sub-fields in TRANSACTION_FIELDS order,
 * forager sub-fields in FORAGER_FIELDS order. All values preserved as-is.
 * Used by /block/c/{n} so the forager receives pre-canonicalized JSON.
 */
export function canonicalStringifyBlock(block: any): string {
  const pairs: string[] = [];

  for (const field of BLOCK_FIELDS) {
    let value: string;

    if (field === 'foragers') {
      value = canonicalStringifyArray(block.foragers, FORAGER_FIELDS);
    } else if (field === 'transactions') {
      value = canonicalStringifyArray(block.transactions, TRANSACTION_FIELDS);
    } else {
      value = block[field] !== undefined ? canonicalJSON(block[field]) : 'null';
    }

    pairs.push(`"${field}":${value}`);
  }

  return '{' + pairs.join(',') + '}';
}

/**
 * Hash two sibling nodes together
 * Concatenates left + right and hashes the result
 */
export function hashPair(left: string, right: string): string {
  return sha256(left + right);
}

/**
 * Precompute empty hashes for all levels of the tree
 * EMPTY[0] = hash of empty leaf
 * EMPTY[n] = hash(EMPTY[n-1] + EMPTY[n-1])
 */
let emptyHashesCache: string[] | null = null;

export function getEmptyHashes(): string[] {
  if (emptyHashesCache) {
    return emptyHashesCache;
  }

  const empties: string[] = new Array(TREE_DEPTH + 1);
  empties[0] = sha256(''); // Empty leaf
  
  for (let i = 1; i <= TREE_DEPTH; i++) {
    empties[i] = hashPair(empties[i - 1], empties[i - 1]);
  }
  
  emptyHashesCache = empties;
  return empties;
}

/**
 * Compute leaf hash from location and balance
 */
export function computeLeafHash(location: string, balance: number): string {
  if (balance === 0) {
    return getEmptyHashes()[0];
  }
  return sha256(location + balance.toString());
}

/**
 * Derive slot position from location string
 * Takes first TREE_DEPTH bits of SHA-256 hash
 */
export function getPosition(location: string, depth: number = TREE_DEPTH): number {
  const hash = createHash('sha256').update(location).digest();
  let position = 0;

  for (let i = 0; i < depth; i++) {
    const byteIndex = Math.floor(i / 8);
    const bitIndex = 7 - (i % 8);
    const bit = (hash[byteIndex] >> bitIndex) & 1;
    position = (position << 1) | bit;
  }

  return position;
}



// =============================================================================
// PROOF FUNCTIONS
// =============================================================================

/**
 * Compress a full proof by removing empty siblings
 * Returns only non-empty siblings plus a bitmask
 */
export function compressProof(fullProof: string[], depth: number = TREE_DEPTH): CompressedProof {
  const empties = getEmptyHashes();
  let emptyBits = '';
  const siblings: string[] = [];

  for (let i = 0; i < depth; i++) {
    if (fullProof[i] === empties[i]) {
      emptyBits += '1';
    } else {
      emptyBits += '0';
      siblings.push(fullProof[i]);
    }
  }

  return {
    depth,
    emptyBits,
    siblings
  };
}

/**
 * Decompress a proof by restoring empty siblings
 */
export function decompressProof(compressed: CompressedProof): string[] {
  const empties = getEmptyHashes();
  const fullProof: string[] = [];
  let siblingIndex = 0;

  for (let i = 0; i < compressed.depth; i++) {
    if (compressed.emptyBits[i] === '1') {
      fullProof.push(empties[i]);
    } else {
      fullProof.push(compressed.siblings[siblingIndex++]);
    }
  }

  return fullProof;
}

/**
 * Verify a balance proof against a state root
 */
export function verifyProof(
  location: string,
  proof: BalanceProof,
  stateRoot: string
): boolean {
  // Decompress if needed
  const siblings = proof.emptyBits 
    ? decompressProof({ depth: proof.depth, emptyBits: proof.emptyBits, siblings: proof.siblings })
    : proof.siblings;

  // Compute leaf hash
  let hash = computeLeafHash(location, proof.balance);
  
  // Get position
  const position = getPosition(location, proof.depth);

  // Walk up the tree
  for (let level = 0; level < proof.depth; level++) {
    const sibling = siblings[level];
    const bit = (position >> level) & 1;

    if (bit === 0) {
      // Current node is left child
      hash = hashPair(hash, sibling);
    } else {
      // Current node is right child
      hash = hashPair(sibling, hash);
    }
  }

  const valid = hash === stateRoot;
  if (!valid) {
    console.log('[verifyProof] MISMATCH:');
    console.log('  computed root:', hash);
    console.log('  expected root:', stateRoot);
    console.log('  location:', location);
    console.log('  balance:', proof.balance);
  }
  return valid;
}

// =============================================================================
// PRODUCTION & REWARD FUNCTIONS
// =============================================================================

/**
 * Calculate reward pools for a cycle boundary.
 *
 * Returns the total pools — proportional per-forager distribution is done
 * by the caller (finalizeBlock) based on endorsement counts across the cycle.
 *
 * Rewards are only minted at cycle boundaries (when rewardCycle > prevRewardCycle).
 * Non-boundary blocks: no minting, no fee distribution — returns all zeros.
 *
 * At a cycle boundary:
 *   - oakPrime receives: oakReward (minted) + (100 - feeShare)% of cycleFees + dust
 *   - foragers receive:  foragePool (minted) + feeShare% of cycleFees
 *     (distributed proportionally by endorsement count; dust goes to oakPrime)
 *
 * @param isCycleBoundary  true if this block's rewardCycle > previous block's rewardCycle
 * @param cycleFees        total transaction fees across all blocks in the ending cycle
 * @param gov              governance params: oakReward, foragePool, feeShare (0–100)
 * @param rewardCycle      the reward cycle number for this block
 */
export function calculateReward(
  isCycleBoundary: boolean,
  cycleFees: number,
  gov: { oakReward: number; foragePool: number; feeShare: number },
  rewardCycle: number
) {
  if (!isCycleBoundary) {
      // Non-boundary block: no minting, no fee distribution
      return {
          oakPrimeReward: 0,
          oakPrimeFees: 0,
          oakPrimeDust: 0,
          oakPrimeTotal: 0,
          foragerPool: 0,
          foragerFees: 0,
          totalMinted: 0,
          cycleFees: 0,
          isCycleBoundary: false,
          rewardCycle
      };
  }

  // --- Fee split (floor forager share, remainder to oakPrime) ---
  const foragerFeePool = Math.floor(cycleFees * gov.feeShare / 100);
  const oakPrimeFees = cycleFees - foragerFeePool;

  // --- Forager pool: minting + fee share (proportional distribution done by caller) ---
  const foragerTotal = gov.foragePool + foragerFeePool;

  // --- OakPrime: minted reward + fees (dust added after proportional distribution) ---
  const oakPrimeTotal = gov.oakReward + oakPrimeFees;  // dust added later

  const totalMinted = gov.oakReward + gov.foragePool;

  return {
      oakPrimeReward: gov.oakReward,
      oakPrimeFees,
      oakPrimeDust: 0,            // set by caller after proportional distribution
      oakPrimeTotal,              // updated by caller after adding dust
      foragerPool: foragerTotal,
      foragerFees: foragerFeePool,
      totalMinted,
      cycleFees,
      isCycleBoundary: true,
      rewardCycle
  };
}

/**
 * Compute the reward cycle number for a given timestamp.
 * rewardCycle = floor((timestamp - genesisCreated) / rewardInterval)
 */
export function computeRewardCycle(timestamp: string, genesisCreated: string, rewardInterval: number): number {
  const t = new Date(timestamp).getTime();
  const g = new Date(genesisCreated).getTime();
  if (t <= g || rewardInterval <= 0) return 0;
  return Math.floor((t - g) / rewardInterval);
}

// Leader/backup functions removed — new reward model uses proportional distribution
// based on endorsement counts across the reward cycle.

// shouldCreateBlock removed — sealing logic moved to CA's checkShouldSeal()
// which uses rewardInterval instead of minBlockInterval.
// =============================================================================
// VALIDATION HELPERS
// =============================================================================

/**
 * Check if balance is sufficient for transaction
 */
export function isBalanceSufficient(balance: number, amount: number, fee: number): boolean {
  return balance >= amount + fee;
}

/**
 * Validate transaction structure
 */
export function isValidTransactionStructure(tx: Transaction, minFee: number = 1): boolean {
  if (!tx.from || !tx.to || !tx.signature) {
    return false;
  }
  
  if (tx.amount < 1 || tx.fee < minFee) {
    return false;
  }

  if (!tx.balanceProof || !tx.balanceProof.siblings || tx.balanceProof.siblings.length === 0) {
    return false;
  }

  return true;
}

/**
 * Validate block structure
 */
export function isValidBlockStructure(block: Block): boolean {
  // Check required primitives
  if (block.block < 0 || !block.prevBlockHash || !block.stateRoot || !block.prevStateRoot) {
    return false;
  }

  // Check created timestamp
  if (!block.created) {
    return false;
  }

  // Check transactions array exists
  if (!Array.isArray(block.transactions)) {
    return false;
  }

  // Check rewards exists
  if (!block.rewards) {
    return false;
  }

  // Check oakPrime structure
  if (!block.oakPrime || !block.oakPrime.location) {
    return false;
  }

  // Check foragers exists and has at least one entry
  if (!block.foragers || block.foragers.length === 0) {
    return false;
  }

  return true;
}

/**
 * Validate common transaction structure
 */
function validateTxStructure(tx: any): string[] {
  const errors: string[] = [];
  if (!tx.from) errors.push('missing from');
  if (!tx.to) errors.push('missing to');
  if (!tx.signature) errors.push('missing signature');
  if (!tx.publicKey) errors.push('missing public key');
  if (!tx.amount) errors.push('missing amount');
  return errors;
}


/**
 * Check that a location string contains only valid characters.
 * Allows alphanumeric, colons, dots, and underscores — nothing else.
 */
export function isValidLocationString(location: string): boolean {
  if (!location || typeof location !== 'string') return false;
  return /^[A-Za-z0-9:._]+$/.test(location);
}

/** Oakspoke local: X:{x}.{8 hex}{3 hex}_Y:{y}.{8 hex}{3 hex} — matches browser client parseLocation. */
const OAKSPOKE_LOCAL_LOCATION_RE =
  /^X:(\d{1,3})\.([a-f0-9]{8})([a-f0-9]{3})_Y:(\d{1,3})\.([a-f0-9]{8})([a-f0-9]{3})$/i;

function isValidOakspokeLocalLocationCore(local: string): boolean {
  const m = OAKSPOKE_LOCAL_LOCATION_RE.exec(local);
  if (!m) return false;
  const x = parseInt(m[1], 10);
  const y = parseInt(m[4], 10);
  return x >= 0 && x <= 255 && y >= 0 && y <= 255;
}

/** True if `location` is local Oakspoke `X:…_Y:…` with 8+3 hex per axis and grid 0–255 (no interoak prefix). */
export function isValidOakspokeLocalLocation(location: string): boolean {
  return isValidOakspokeLocalLocationCore(location);
}

/**
 * Transaction from/to: strict Oakspoke local X:_Y:_ (8+3+8+3, coords 0–255)
 * OR interoak AAA:X:_Y:_ with the same local body (three letters + colon + local).
 */
export function isValidAcoornTransactionLocation(location: string): boolean {
  if (!location || typeof location !== 'string') return false;
  if (!isValidLocationString(location)) return false;
  if (isValidOakspokeLocalLocationCore(location)) return true;
  // Interoak prefix must be three uppercase letters; do not use /i on the whole pattern (would allow "rye:").
  if (location.indexOf(':') !== 3) return false;
  const prefix = location.slice(0, 3);
  if (!/^[A-Z]{3}$/.test(prefix)) return false;
  return isValidOakspokeLocalLocationCore(location.slice(4));
}

const LOCATION_FORMAT_HINT =
  "must be X:_Y:_ (8+3 hex digits per axis, grid 0–255) or AAA:X:_Y:_ (interoak, e.g. RYE:X:…_Y:…)";

/**
 * Validate a transaction with detailed error reporting
 * validateTransaction(tx, stateRoot, pendingBalance)
 */
export function validateTransaction(tx: any, stateRoot: string, pendingBalance: number): ValidationResult {

  if (!isValidAcoornTransactionLocation(tx.from)) {
    return { valid: false, errors: [`invalid 'from' location: ${LOCATION_FORMAT_HINT}`] };
  }
  if (!isValidAcoornTransactionLocation(tx.to)) {
    return { valid: false, errors: [`invalid 'to' location: ${LOCATION_FORMAT_HINT}`] };
  }

  if (!verifyProof(tx.from, tx.balanceProof, stateRoot)) {
    return { valid: false, errors: [`invalid balance proof (proof balance: ${tx.balanceProof?.balance}, stateRoot: ${stateRoot?.substring(0, 16)}...)`] };
  }
  
  const available = (tx.balanceProof?.balance ?? 0) + pendingBalance;
  const required = tx.amount + tx.fee;
  if (available < required) {
    return { valid: false, errors: [`insufficient balance: have ${available} (proof: ${tx.balanceProof?.balance}, pending: ${pendingBalance}), need ${required} (amount: ${tx.amount}, fee: ${tx.fee})`] };
  }

  return { valid: true, errors: [] };
}



/**
 * Validate a location format and check it matches the public key hash commitment format.
 * Format: N:{y}.{hashA}{msY}_E:{x}.{hashB}{msX}
 *   - y, x: 1-3 digit integers from 1 to 255
 *   - hashA, hashB: 16 hex chars each
 *   - msY, msX: 3 hex chars each
 * Example: N:45.a1b2c3d4e5f67890f0c_E:122.fedcba9876543210a3b
 * 
 * Returns { valid: boolean, errors: string[] }
 */
export function validateLocationFormat(location: string, publicKey: string): ValidationResult {
  const errors: string[] = [];
  
  // Step 1: Regex format
  const regex = /^N:(\d{1,3})\.([a-f0-9]{16})([a-f0-9]{3})_E:(\d{1,3})\.([a-f0-9]{16})([a-f0-9]{3})$/i;
  const match = regex.exec(location);
  if (!match) {
    errors.push("Location format does not match expected pattern");
    return { valid: false, errors };
  }
  
  // Parse parts
  const y = parseInt(match[1], 10);
  const hashA = match[2];
  const msY = match[3];
  const x = parseInt(match[4], 10);
  const hashB = match[5];
  const msX = match[6];

  // Validate integer ranges
  if (!(y > 0 && y < 256)) errors.push("North coordinate (y) must be 1-255");
  if (!(x > 0 && x < 256)) errors.push("East coordinate (x) must be 1-255");

  // Step 2: hash the public key
  let hPk: string;
  try {
    hPk = sha256(typeof publicKey === "string" ? publicKey : Buffer.from(publicKey).toString('hex'));
  } catch (e) {
    errors.push("Failed to hash publicKey");
    return { valid: false, errors };
  }
  
  // Step 3: split hash
  if (hPk.length < 32) {
    errors.push("Public key hash too short");
    return { valid: false, errors };
  }
  const hashAA = hPk.substring(0, 16).toLowerCase();
  const hashBB = hPk.substring(16, 32).toLowerCase();

  // Step 4: compare hashes
  if (hashA.toLowerCase() !== hashAA) errors.push("hashA does not match publicKey commitment");
  if (hashB.toLowerCase() !== hashBB) errors.push("hashB does not match publicKey commitment");

  return {
    valid: errors.length === 0,
    errors
  };
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Hash a block for signing (excludes foragers array)
 */
export function hashBlock(block: Block): string {
  const data = JSON.stringify({
    block: block.block,
    created: block.created,
    prevBlockHash: block.prevBlockHash,
    prevStateRoot: block.prevStateRoot,
    stateRoot: block.stateRoot,
    finalized: block.finalized,
    transactions: block.transactions,
    rewards: block.rewards,
    oakPrime: block.oakPrime
    // Note: foragers excluded - they contain signatures
  });
  return sha256(data);
}

/**
 * Hash a transaction for signing
 */
export function hashTransaction(tx: Omit<Transaction, 'signature'>): string {
  const data = JSON.stringify({
    type: tx.type,
    from: tx.from,
    to: tx.to,
    amount: tx.amount,
    fee: tx.fee,
    memo: tx.memo,
    balanceProof: tx.balanceProof,
    destinationOak: tx.destinationOak,
    interOakTransferProof: tx.interOakTransferProof
  });
  return sha256(data);
}


/**
 * Convert hex string to Uint8Array
 */
function hexToBytes(hex: string): Uint8Array {
  hex = hex.replace(/^0x/, '');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Get crypto.subtle - works in both Node.js 18+ and browser
 */
function getSubtleCrypto(): SubtleCrypto {
  // Browser
  if (typeof globalThis.crypto?.subtle !== 'undefined') {
    return globalThis.crypto.subtle;
  }
  // Node.js fallback
  const nodeCrypto = require('crypto');
  if (nodeCrypto.webcrypto?.subtle) {
    return nodeCrypto.webcrypto.subtle;
  }
  throw new Error('Web Crypto API not available');
}

/**
 * Validate a P-256 ECDSA signature
 * Works in both Node.js (AWS Lambda) and browser
 * 
 * @param pubKeyHex - Uncompressed public key (65 bytes, starts with 04)
 * @param data - Original data that was signed (will be hashed with SHA-256)
 * @param signatureHex - Raw r||s signature (64 bytes) or DER format
 */
export async function validateSignature(
  pubKeyHex: string,
  data: string,
  signatureHex: string
): Promise<boolean> {
  try {
    const subtle = getSubtleCrypto();
    
    // Import public key
    const pubKeyBytes = hexToBytes(pubKeyHex);
    const publicKey = await subtle.importKey(
      'raw',
      pubKeyBytes.buffer as ArrayBuffer,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    
    // Parse signature (handle both raw r||s and DER-like format)
    let sigBytes = hexToBytes(signatureHex);
    
    // If DER-like (starts with 0x02), convert to raw r||s
    if (sigBytes[0] === 0x02) {
      sigBytes = derToRaw(sigBytes);
    } else if (sigBytes[0] === 0x30) {
      // Full DER with SEQUENCE wrapper
      sigBytes = derToRaw(sigBytes.slice(2)); // Skip 30 xx
    }
    
    // Encode data as bytes
    const encoder = new TextEncoder();
    const dataBytes = encoder.encode(data);
    
    // Verify signature (Web Crypto hashes internally with SHA-256)
    const isValid = await subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      sigBytes.buffer as ArrayBuffer,
      dataBytes
    );
    
    return isValid;
  } catch (err) {
    console.error('Signature validation error:', err);
    return false;
  }
}

/**
 * Convert DER-like signature (02 rlen r 02 slen s) to raw r||s (64 bytes)
 */
function derToRaw(sigBytes: Uint8Array): Uint8Array {
  const raw = new Uint8Array(64);
  let idx = 0;
  
  // Parse r
  if (sigBytes[idx++] !== 0x02) throw new Error('Invalid DER: expected 0x02 for r');
  let rLen = sigBytes[idx++];
  let rStart = idx;
  if (rLen === 33 && sigBytes[rStart] === 0x00) {
    rStart++;
    rLen = 32;
  }
  const rPad = 32 - rLen;
  for (let i = 0; i < rLen && i < 32; i++) {
    raw[rPad + i] = sigBytes[rStart + i];
  }
  idx = rStart + rLen;
  if (sigBytes[idx - rLen - 1] === 0x00) idx++;
  
  // Recalculate idx
  idx = 2 + sigBytes[1];
  
  // Parse s
  if (sigBytes[idx++] !== 0x02) throw new Error('Invalid DER: expected 0x02 for s');
  let sLen = sigBytes[idx++];
  let sStart = idx;
  if (sLen === 33 && sigBytes[sStart] === 0x00) {
    sStart++;
    sLen = 32;
  }
  const sPad = 32 - sLen;
  for (let i = 0; i < sLen && i < 32; i++) {
    raw[32 + sPad + i] = sigBytes[sStart + i];
  }
  
  return raw;
}

