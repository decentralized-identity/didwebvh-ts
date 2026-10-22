let urlSupportsIdna: boolean | undefined;

export function urlToASCII(host: string): string {
  try {
    urlSupportsIdna ??=
      new URL('https://faß.de').hostname === 'xn--fa-hia.de' &&
      new URL('https://BÜCHER.example').hostname === 'xn--bcher-kva.example';
  } catch {
    urlSupportsIdna = false;
  }
  if (!urlSupportsIdna) {
    throw new Error("This runtime's URL implementation does not support IDNA; use an A-label (xn--) domain");
  }
  try {
    return new URL(`https://${host}`).hostname;
  } catch {
    throw new Error('Host must be a valid fully qualified domain');
  }
}
