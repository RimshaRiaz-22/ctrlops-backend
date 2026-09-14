import { Router } from 'express';
import express from 'express';
import { validate } from '../middleware/validate.js';
import {
  mkdirSchema,
  renameSchema,
  deleteSchema,
  unzipSchema,
  zipSchema,
  downloadTicketSchema,
  contentPutSchema,
} from '../schemas/file.schema.js';
import * as fileController from '../controllers/file.controller.js';

const router = Router({ mergeParams: true });

router.get('/', fileController.list);
router.get('/progress', fileController.progress);
router.get('/download', fileController.download);
router.get('/download-zip', fileController.downloadZip);
router.post(
  '/download-ticket',
  validate(downloadTicketSchema),
  fileController.createDownloadTicket,
);
router.post(
  '/download-zip-ticket',
  validate(zipSchema),
  fileController.createZipDownloadTicket,
);
router.get('/content', fileController.getContent);
router.get('/folder-size', fileController.folderSize);
router.get('/stat', fileController.resolveSymlink);

router.post('/upload', fileController.upload);
router.post('/download-zip', validate(zipSchema), fileController.downloadZip);
router.post('/mkdir', validate(mkdirSchema), fileController.mkdir);
router.post('/unzip', validate(unzipSchema), fileController.unzip);

router.put(
  '/content',
  express.json({ limit: '6mb' }),
  validate(contentPutSchema),
  fileController.putContent,
);

router.patch('/rename', validate(renameSchema), fileController.rename);
router.delete('/', validate(deleteSchema), fileController.remove);

export default router;
