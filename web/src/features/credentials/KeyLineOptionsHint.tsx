/**
 * What the options of a suggested authorized_keys line do. `from=` is only present when the server configuration
 * names the gateway's egress addresses, so the text must not claim it otherwise.
 */
export function KeyLineOptionsHint({ line }: { line: string }) {
  if (line.includes('from="')) {
    return (
      <>
        The <code className="hp-mono">from=</code> and <code className="hp-mono">restrict</code> options limit
        the key to the gateway.
      </>
    );
  }
  return (
    <>
      The <code className="hp-mono">restrict</code> option limits what the key can do. Set{' '}
      <code className="hp-mono">egress.source_addresses</code> in the server configuration to also add a{' '}
      <code className="hp-mono">from=</code> restriction to the gateway&apos;s address.
    </>
  );
}
