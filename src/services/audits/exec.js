/**
 * Thin conn.exec wrapper with Node-side timeout.
 * Shell-level timeout should still wrap the remote command.
 */
export function exec(conn, command, { timeoutMs = 30_000 } = {}) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error(`Remote command timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    conn.exec(command, (err, stream) => {
      if (err) {
        clearTimeout(timer);
        if (!settled) {
          settled = true;
          reject(err);
        }
        return;
      }

      let stdout = '';
      let stderr = '';
      stream.on('data', (d) => {
        stdout += d.toString('utf8');
      });
      stream.stderr?.on('data', (d) => {
        stderr += d.toString('utf8');
      });
      stream.on('close', () => {
        clearTimeout(timer);
        if (settled) return;
        settled = true;
        resolve(stdout + (stderr ? `\n${stderr}` : ''));
      });
      stream.on('error', (e) => {
        clearTimeout(timer);
        if (settled) return;
        settled = true;
        reject(e);
      });
    });
  });
}
