const sessions = new Map();

export function createSession(uploadId) {
  const session = {
    uploadId,
    files: [],
    status: 'active',
    listeners: new Set(),
    createdAt: Date.now(),
  };
  sessions.set(uploadId, session);
  return session;
}

export function getSession(uploadId) {
  return sessions.get(uploadId) ?? null;
}

export function emit(uploadId, event, data) {
  const session = sessions.get(uploadId);
  if (!session) return;
  for (const listener of session.listeners) {
    try {
      listener(event, data);
    } catch {
      /* ignore */
    }
  }
}

export function subscribe(uploadId, listener) {
  const session = sessions.get(uploadId) ?? createSession(uploadId);
  session.listeners.add(listener);
  return () => session.listeners.delete(listener);
}

export function completeSession(uploadId, payload) {
  const session = sessions.get(uploadId);
  if (!session) return;
  session.status = 'complete';
  session.result = payload;
  emit(uploadId, 'complete', payload);
}

export function failSession(uploadId, payload) {
  const session = sessions.get(uploadId);
  if (!session) return;
  session.status = 'failed';
  session.result = payload;
  emit(uploadId, 'error', payload);
}

export function cancelSession(uploadId) {
  const session = sessions.get(uploadId);
  if (!session) return;
  session.status = 'cancelled';
  emit(uploadId, 'cancelled', { uploadId });
}

export function removeSession(uploadId) {
  sessions.delete(uploadId);
}
