const limit = process.env.REQUEST_SIZE_LIMIT;
if (!/^\d+$/.test(limit || '')) {
  console.error(`Invalid REQUEST_SIZE_LIMIT: '${limit}'. Please provide a numeric value.`);
  process.exit(2);
}
