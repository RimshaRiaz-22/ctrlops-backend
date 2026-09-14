import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { corsAllowedOrigins, originAllowed } from '../../src/ws/origin.js';

describe('originAllowed', () => {
  it('allows the Netlify frontend origin used in production', () => {
    assert.equal(
      originAllowed('https://ctrlops-frontend-rim.netlify.app'),
      true,
    );
  });

  it('includes FRONTEND_URL in the CORS allowlist', () => {
    const origins = corsAllowedOrigins();
    assert.ok(origins.includes('https://ctrlops-frontend-rim.netlify.app'));
    assert.ok(origins.some((origin) => origin.includes('localhost')));
  });
});
