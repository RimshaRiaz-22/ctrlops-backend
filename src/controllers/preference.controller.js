import { getOrCreate, update } from '../repositories/userPreference.repository.js';

export async function getPreferences(req, res, next) {
  try {
    const data = await getOrCreate(req.user.id);
    res.json({ ok: true, data });
  } catch (err) {
    next(err);
  }
}

export async function patchPreferences(req, res, next) {
  try {
    const data = await update(req.user.id, {
      fileManagerLayout: req.body.fileManagerLayout,
      showHiddenFiles: req.body.showHiddenFiles,
      editorTheme: req.body.editorTheme,
    });
    res.json({ ok: true, data });
  } catch (err) {
    next(err);
  }
}
