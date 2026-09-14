export function attachmentDisposition(basename) {
  const encoded = encodeURIComponent(basename);
  return `attachment; filename="${encoded}"; filename*=UTF-8''${encoded}`;
}
