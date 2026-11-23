import fs from 'node:fs';
import { readFile } from 'node:fs/promises';

export async function GET({ params, url, request, fetch }) {
  const id = params.id;
  // ruleid: helix-sveltekit-taint-sql
  await db.query('SELECT * FROM orders WHERE id=' + id);
  // ok: helix-sveltekit-taint-sql
  await db.query('SELECT * FROM orders WHERE id=$1', [id]);
  const target = url.searchParams.get('url');
  // ruleid: helix-sveltekit-taint-fetch
  await fetch(target);
  // ok: helix-sveltekit-taint-fetch
  await fetch('https://example.test', { body: target });
  const body = await request.json();
  // ruleid: helix-sveltekit-taint-fs
  await fs.promises.readFile(body.path);
  // ruleid: helix-sveltekit-taint-fs
  await readFile(params.name);
  // ok: helix-sveltekit-taint-fs
  await fs.promises.writeFile('/tmp/fixed.txt', body.text);
}

export async function POST(event) {
  const input = await event.request.json();
  // ruleid: helix-sveltekit-taint-sql
  await sql.unsafe(input.sql);
  // ruleid: helix-sveltekit-taint-fetch
  await event.fetch(event.params.target);
  // ruleid: helix-sveltekit-taint-fs
  fs.readFileSync(event.url.searchParams.get('file'));
  // ok: helix-sveltekit-taint-sql
  await sql`SELECT * FROM orders WHERE id = ${event.params.id}`;
  // ok: helix-sveltekit-taint-fetch
  await event.fetch('/api/fixed');
}
