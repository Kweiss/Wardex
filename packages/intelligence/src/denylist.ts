/**
 * Denylist Management
 *
 * Loads and manages lists of known malicious addresses.
 * v1: Local JSON file
 * v2: Community-shared feeds with privacy-preserving sharing
 */

import * as fs from 'node:fs';

export interface DenylistEntry {
  /** Ethereum address (lowercase, with 0x prefix) */
  address: string;
  /** Reason for denylisting */
  reason: string;
  /** When this entry was added (ISO timestamp) */
  addedAt: string;
  /** Source of the report */
  source: string;
  /** Severity */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Optional tags for categorization */
  tags?: string[];
}

interface DenylistFile {
  version: number;
  lastUpdated: string;
  entries: DenylistEntry[];
}

/**
 * Loads a denylist from a JSON file.
 */
export function loadDenylist(filePath: string): DenylistEntry[] {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const data: DenylistFile = JSON.parse(content);

    if (data.version !== 1) {
      throw new Error(`Unsupported denylist version: ${data.version}`);
    }

    return data.entries.map((entry) => ({
      ...entry,
      address: entry.address.toLowerCase(),
    }));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      // File doesn't exist - return empty list
      return [];
    }
    throw err;
  }
}

/**
 * Saves a denylist to a JSON file.
 */
export function saveDenylist(
  filePath: string,
  entries: DenylistEntry[]
): void {
  const data: DenylistFile = {
    version: 1,
    lastUpdated: new Date().toISOString(),
    entries,
  };

  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
}

/**
 * Creates a new denylist entry.
 */
export function createDenylistEntry(
  address: string,
  reason: string,
  source: string,
  severity: DenylistEntry['severity'] = 'high',
  tags?: string[]
): DenylistEntry {
  return {
    address: address.toLowerCase(),
    reason,
    addedAt: new Date().toISOString(),
    source,
    severity,
    tags,
  };
}
