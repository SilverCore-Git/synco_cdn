// Génère tests/vectors/tickets.json : vecteurs de tickets partagés entre
// synco_cdn (Rust, vérification) et synco_api (TypeScript, signature).
//
//   node tests/vectors/generate.mjs
//
// Implémentation de référence de la signature côté API (cf.
// docs/plan/02-tickets.md) : node:crypto uniquement, aucune dépendance.
// Ed25519 est déterministe : le fichier produit est identique à chaque
// exécution.

import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const SEED = Buffer.alloc(32, 0x2a);
// En-tête PKCS#8 d'une clé privée Ed25519 brute de 32 octets.
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, SEED]), format: 'der', type: 'pkcs8' });
const publicKey = createPublicKey(privateKey).export({ format: 'jwk' }).x; // base64url, 32 octets

const KID = 'vec-1';
const DOMAIN = Buffer.from('synco-cdn-ticket\0', 'latin1');

/** Signe un contenu arbitraire (objet → JSON, ou chaîne brute). */
function signTicket(payload, kid = KID) {
  const json = typeof payload === 'string' ? payload : JSON.stringify(payload);
  const payloadB64 = Buffer.from(json, 'utf8').toString('base64url');
  const message = Buffer.concat([DOMAIN, Buffer.from(`sct1.${kid}.${payloadB64}`, 'utf8')]);
  const signature = sign(null, message, privateKey).toString('base64url');
  return `sct1.${kid}.${payloadB64}.${signature}`;
}

const NOW = 1_759_230_000;
const upload = {
  op: 'up',
  tid: '6f1c1f3e-1c1a-4a70-9d1f-1b1c1d1e1f20',
  fid: '0b7a2d8e-5b1f-4f55-8a33-2e4f5a6b7c8d',
  sub: 'user-42',
  iat: NOW - 60,
  exp: NOW + 3600 - 60,
  size: 1_073_741_840,
  psz: 4_194_320,
};
const download = {
  op: 'down',
  tid: 'a3d9c7e1-2b4f-4c6d-8e0f-112233445566',
  fid: '0b7a2d8e-5b1f-4f55-8a33-2e4f5a6b7c8d',
  sub: 'user-42',
  iat: NOW - 10,
  exp: NOW + 890,
  size: 1_073_741_840,
  // Chaîne : les nanosecondes dépassent la précision des nombres JSON en JS.
  mtime: '1759229000123456789',
};

const tamper = (token, index) => {
  const parts = token.split('.');
  const signature = Buffer.from(parts[3], 'base64url');
  signature[index] ^= 0x01;
  parts[3] = signature.toString('base64url');
  return parts.join('.');
};

const cases = [
  { name: 'upload valide', token: signTicket(upload), op: 'up', now: NOW, expect: 'ok', part_count: 256 },
  { name: 'download valide', token: signTicket(download), op: 'down', now: NOW, expect: 'ok' },
  { name: 'upload présenté pour un download', token: signTicket(upload), op: 'down', now: NOW, expect: 'ticket_wrong_operation' },
  { name: 'expiré', token: signTicket(upload), op: 'up', now: upload.exp + 31, expect: 'ticket_expired' },
  { name: 'dans la tolérance d\'horloge', token: signTicket(upload), op: 'up', now: upload.exp + 29, expect: 'ok', part_count: 256 },
  { name: 'pas encore valide', token: signTicket(upload), op: 'up', now: upload.iat - 31, expect: 'ticket_invalid' },
  { name: 'signature altérée', token: tamper(signTicket(upload), 5), op: 'up', now: NOW, expect: 'ticket_invalid' },
  { name: 'clé inconnue', token: signTicket(upload, 'vec-2'), op: 'up', now: NOW, expect: 'ticket_unknown_key' },
  { name: 'préfixe de version inconnu', token: signTicket(upload).replace(/^sct1/, 'sct9'), op: 'up', now: NOW, expect: 'ticket_invalid' },
  { name: 'champ inconnu signé', token: signTicket({ ...upload, admin: true }), op: 'up', now: NOW, expect: 'ticket_invalid' },
  { name: 'opération inconnue signée', token: signTicket({ ...upload, op: 'delete' }), op: 'up', now: NOW, expect: 'ticket_invalid' },
  { name: 'part trop petite', token: signTicket({ ...upload, psz: 1024 }), op: 'up', now: NOW, expect: 'ticket_invalid' },
  { name: 'fichier trop gros', token: signTicket({ ...upload, size: 11 * 1024 ** 3 }), op: 'up', now: NOW, expect: 'ticket_invalid' },
  { name: 'durée de vie excessive', token: signTicket({ ...upload, exp: upload.iat + 7201 }), op: 'up', now: NOW, expect: 'ticket_invalid' },
  { name: 'mtime numérique', token: signTicket({ ...download, mtime: 1759229000 }), op: 'down', now: NOW, expect: 'ticket_invalid' },
  { name: 'identifiant non UUID', token: signTicket({ ...upload, tid: '../../etc/passwd' }), op: 'up', now: NOW, expect: 'ticket_invalid' },
  { name: 'contenu signé non JSON', token: signTicket('not json'), op: 'up', now: NOW, expect: 'ticket_invalid' },
  { name: 'segment supplémentaire', token: `${signTicket(upload)}.x`, op: 'up', now: NOW, expect: 'ticket_invalid' },
  { name: 'trop long', token: signTicket({ ...upload, sub: 'x'.repeat(2100) }), op: 'up', now: NOW, expect: 'ticket_invalid' },
  { name: 'vide', token: '', op: 'up', now: NOW, expect: 'ticket_missing' },
];

const out = {
  description: 'Vecteurs de tickets synco_cdn (sct1). Générés par generate.mjs, ne pas modifier à la main.',
  public_keys: { [KID]: publicKey },
  policy: { clock_skew_secs: 30, max_lifetime_secs: 7200, max_file_bytes: 10 * 1024 ** 3 },
  cases,
};
const target = join(dirname(fileURLToPath(import.meta.url)), 'tickets.json');
writeFileSync(target, `${JSON.stringify(out, null, 2)}\n`);
console.log(`${cases.length} vecteurs écrits dans ${target}`);
