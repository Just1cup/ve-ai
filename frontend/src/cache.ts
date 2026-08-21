import type { GraphResponse, IocDetails } from './types';

const DB_NAME = 'ioc-graph';
const DB_VERSION = 2;
const SNAPSHOT_STORE = 'graph-snapshots';
const DETAILS_STORE = 'ioc-details';
const VIEW_STATE_STORE = 'view-state';
const DEFAULT_VIEW_STATE_KEY = 'default';

export interface CachedGraphSnapshot {
  data: GraphResponse;
  etag: string | null;
  cachedAt: number;
}

export interface CachedIocDetails {
  detail: IocDetails;
  cachedAt: number;
}

export interface CachedViewState {
  enabledTypes: string[];
  query: string;
  cachedAt: number;
}

export async function readGraphSnapshot(key: string): Promise<CachedGraphSnapshot | null> {
  return readStore<CachedGraphSnapshot>(SNAPSHOT_STORE, key);
}

export async function writeGraphSnapshot(
  key: string,
  data: GraphResponse,
  etag: string | null,
): Promise<void> {
  await writeStore(SNAPSHOT_STORE, key, {
    data,
    etag,
    cachedAt: Date.now(),
  });
}

export async function readIocDetails(id: string): Promise<CachedIocDetails | null> {
  return readStore<CachedIocDetails>(DETAILS_STORE, id);
}

export async function writeIocDetails(id: string, detail: IocDetails): Promise<void> {
  await writeStore(DETAILS_STORE, id, {
    detail,
    cachedAt: Date.now(),
  });
}

export async function readViewState(): Promise<CachedViewState | null> {
  return readStore<CachedViewState>(VIEW_STATE_STORE, DEFAULT_VIEW_STATE_KEY);
}

export async function writeViewState(enabledTypes: string[], query: string): Promise<void> {
  await writeStore(VIEW_STATE_STORE, DEFAULT_VIEW_STATE_KEY, {
    enabledTypes,
    query,
    cachedAt: Date.now(),
  });
}

async function readStore<T>(storeName: string, key: IDBValidKey): Promise<T | null> {
  if (!supportsIndexedDb()) return null;

  try {
    const db = await openDb();
    return await transaction<T | null>(db, storeName, 'readonly', (store, finish, fail) => {
      const request = store.get(key);
      request.onsuccess = () => finish(request.result || null);
      request.onerror = () => fail(request.error);
    });
  } catch {
    return null;
  }
}

async function writeStore(storeName: string, key: IDBValidKey, value: unknown): Promise<void> {
  if (!supportsIndexedDb()) return;

  try {
    const db = await openDb();
    await transaction<void>(db, storeName, 'readwrite', (store, finish, fail) => {
      const request = store.put(value, key);
      request.onsuccess = () => finish(undefined);
      request.onerror = () => fail(request.error);
    });
  } catch {
    // Cache failures should never break the investigation workflow.
  }
}

function supportsIndexedDb(): boolean {
  return typeof indexedDB !== 'undefined';
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;
      for (const storeName of [SNAPSHOT_STORE, DETAILS_STORE, VIEW_STATE_STORE]) {
        if (!db.objectStoreNames.contains(storeName)) {
          db.createObjectStore(storeName);
        }
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function transaction<T>(
  db: IDBDatabase,
  storeName: string,
  mode: IDBTransactionMode,
  run: (
    store: IDBObjectStore,
    finish: (value: T) => void,
    fail: (reason?: unknown) => void,
  ) => void,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, mode);
    const store = tx.objectStore(storeName);

    tx.oncomplete = () => db.close();
    tx.onabort = () => {
      db.close();
      reject(tx.error);
    };
    tx.onerror = () => {
      db.close();
      reject(tx.error);
    };

    run(store, resolve, reject);
  });
}
