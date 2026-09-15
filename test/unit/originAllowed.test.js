import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { corsAllowedOrigins, originAllowed } from '../../src/ws/origin.js';

describe('originAllowed', () => {
  it('allows the Render frontend origin', () => {
    assert.equal(
      originAllowed('https://ctrlops-frontend.onrender.com'),
      true,
    );
  });

  it('allows the Netlify frontend origin', () => {
    assert.equal(
      originAllowed('https://ctrlops-frontend-rim.netlify.app'),
      true,
    );
  });

  it('includes known frontends in the CORS allowlist', () => {
    const origins = corsAllowedOrigins();
    assert.ok(origins.includes('https://ctrlops-frontend.onrender.com'));
    assert.ok(origins.includes('https://ctrlops-frontend-rim.netlify.app'));
  });
});
