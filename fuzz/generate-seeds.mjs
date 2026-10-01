// Génère le corpus de départ versionné (fuzz/seeds/<cible>/) à partir des
// vecteurs de tickets et de la configuration d'exemple. Déterministe.
//
//   node fuzz/generate-seeds.mjs
//
// Le fuzzer part de ces entrées réalistes au lieu de partir de rien ; ses
// découvertes s'accumulent ensuite dans fuzz/corpus/ (non versionné, gardé
// en cache par la CI).

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const seedsDir = join(here, 'seeds');

const seeds = { ticket: [], ticket_claims: [], range: [], path: [], config: [], session_record: [] };

// --- Tickets (signés par l'implémentation de référence Node) ---------------
const vectors = JSON.parse(readFileSync(join(root, 'tests/vectors/tickets.json'), 'utf8'));
for (const c of vectors.cases) {
  seeds.ticket.push(Buffer.from(c.token, 'utf8'));
  const payload = c.token.split('.')[2];
  if (payload) seeds.ticket_claims.push(Buffer.from(payload, 'base64url'));
}
const NOW = 1_759_230_000;
const base = { tid: '6f1c1f3e-1c1a-4a70-9d1f-1b1c1d1e1f20', fid: '0b7a2d8e-5b1f-4f55-8a33-2e4f5a6b7c8d', sub: 'u' };
for (const claims of [
  { op: 'up', ...base, iat: NOW, exp: NOW + 3600, size: 0, psz: 65536 },
  { op: 'up', ...base, iat: NOW, exp: NOW + 7200, size: 10 * 1024 ** 3, psz: 64 * 1024 ** 2 },
  { op: 'up', ...base, iat: NOW, exp: NOW + 60, size: 65536 * 100000, psz: 65536 },
  { op: 'down', ...base, iat: NOW, exp: NOW + 900, size: 0, mtime: '0' },
  { op: 'down', ...base, iat: NOW, exp: NOW + 900, size: 18446744073709551615n, mtime: '18446744073709551615' },
]) {
  seeds.ticket_claims.push(Buffer.from(JSON.stringify(claims, (_, v) => (typeof v === 'bigint' ? Number(v) : v))));
}

// --- Range : 8 octets de taille (LE) puis l'en-tête ------------------------
const rangeCase = (len, header) => {
  const size = Buffer.alloc(8);
  size.writeBigUInt64LE(BigInt(len));
  return Buffer.concat([size, Buffer.from(header, 'utf8')]);
};
for (const [len, header] of [
  [1000, 'bytes=0-499'], [1000, 'bytes=500-'], [1000, 'bytes=-200'], [1000, 'bytes=0-0,5-6'],
  [0, 'bytes=0-0'], [1000, 'bytes=999-1000'], [1000, 'BYTES = 1-1'], [1000, 'bytes=5-2'],
  [2 ** 53, 'bytes=18446744073709551615-'], [1000, 'items=0-1'], [4194320, 'bytes=4194304-8388623'],
]) {
  seeds.range.push(rangeCase(len, header));
}

// --- Chemins ---------------------------------------------------------------
const id = '0b7a2d8e-5b1f-4f55-8a33-2e4f5a6b7c8d';
for (const p of [
  '/healthz', '/v1/uploads', `/v1/uploads/${id}`, `/v1/uploads/${id}/part`, `/v1/uploads/${id}/complete`,
  `/v1/files/${id}`, '/readyz', '/metrics', '/internal/v1/revocations', `/internal/v1/uploads/${id}`,
  '/v1/files/../../etc/passwd', `/v1/files/${id.toUpperCase()}`, `//v1/files/${id}`, `/v1/files/{${id}}`,
]) {
  seeds.path.push(Buffer.from(p, 'utf8'));
}

// --- Configuration ---------------------------------------------------------
const key = vectors.public_keys['vec-1'];
const example = readFileSync(join(root, 'deploy/config.example.toml'), 'utf8')
  .replace('REMPLACER_PAR_LA_CLÉ_PUBLIQUE', key)
  .replace('ORIGINE_WEB_DE_SYNCO_APP', 'app.example')
  .replace('internal_secret_file = "/etc/synco-cdn/internal_secret"', `internal_secret = "${'ab'.repeat(32)}"`);
seeds.config.push(Buffer.from(example, 'utf8'));
seeds.config.push(Buffer.from(
  `[storage]\ndata_dir = "/srv"\n[tickets]\npublic_keys = { "k" = "${key}" }\n` +
  `[api]\ninternal_url = "http://127.0.0.1:9"\ninternal_secret = "${'ab'.repeat(32)}"\n`, 'utf8'));

// --- Fichiers de session : 2 octets (N), N octets d'états, puis le JSON --
const sessionCase = (markers, record) => {
  const n = Buffer.alloc(2);
  n.writeUInt16LE(markers.length);
  return Buffer.concat([n, Buffer.from(markers), Buffer.from(JSON.stringify(record), 'utf8')]);
};
const record = { version: 1, tid: base.tid, fid: base.fid, sub: 'u', size: 300000, part_size: 100000, expires_at: NOW, phase: 'open' };
seeds.session_record.push(sessionCase([1, 0, 1], record));
seeds.session_record.push(sessionCase([], { ...record, phase: 'finalized', hash: 'sha256p:00' }));
seeds.session_record.push(sessionCase([1], { ...record, size: 0, part_size: 65536, phase: 'completed', hash: 'x' }));
// Non-régression : géométrie hors bornes trouvée par le fuzzing (taille de
// part sous le minimum), et variante qui provoquerait une allocation démesurée.
seeds.session_record.push(sessionCase([1], { ...record, size: 0, part_size: 65236 }));
seeds.session_record.push(sessionCase([], { ...record, size: 10 * 1024 ** 3, part_size: 1 }));

// --- Écriture (noms = empreinte du contenu, comme libFuzzer) --------------
rmSync(seedsDir, { recursive: true, force: true });
let total = 0;
for (const [target, inputs] of Object.entries(seeds)) {
  const dir = join(seedsDir, target);
  mkdirSync(dir, { recursive: true });
  for (const input of inputs) {
    writeFileSync(join(dir, createHash('sha1').update(input).digest('hex')), input);
    total++;
  }
}
console.log(`${total} entrées de départ écrites dans ${seedsDir}`);
