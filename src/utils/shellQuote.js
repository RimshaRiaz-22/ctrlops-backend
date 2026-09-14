export function shellQuote(str) {
  if (typeof str !== 'string') {
    throw new TypeError('shellQuote requires a string');
  }
  return `'${str.replace(/'/g, `'\\''`)}'`;
}
