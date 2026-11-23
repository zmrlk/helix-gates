import {env} from '$env/dynamic/private';
export async function handle({event, resolve}) {
  if (!env.S3_ACCESS_KEY_ID || !env.S3_SECRET_ACCESS_KEY || !env.SMTP_PASSWORD) throw Error('synthetic SDK values required');
  if (new URL(env.S3_ENDPOINT).hostname !== '127.0.0.1' || env.SMTP_HOST !== '127.0.0.1') throw Error('loopback services required');
  return resolve(event);
}
