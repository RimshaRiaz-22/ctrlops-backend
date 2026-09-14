import PdfPrinter from 'pdfmake';
import { coverageLine } from './scoring.js';

const fonts = {
  Helvetica: {
    normal: 'Helvetica',
    bold: 'Helvetica-Bold',
    italics: 'Helvetica-Oblique',
    bolditalics: 'Helvetica-BoldOblique',
  },
};

const printer = new PdfPrinter(fonts);

function gradeColor(grade) {
  switch (grade) {
    case 'A':
      return '#059669';
    case 'B':
      return '#2563eb';
    case 'C':
      return '#d97706';
    case 'D':
      return '#ea580c';
    case 'F':
      return '#dc2626';
    default:
      return '#64748b';
  }
}

function findingBlock(f) {
  return [
    {
      text: `${f.severity} · ${f.status} — ${f.title}`,
      bold: true,
      margin: [0, 8, 0, 2],
    },
    { text: f.detail || '', color: '#444', margin: [0, 0, 0, 2] },
    f.remediationText
      ? { text: `Remediation: ${f.remediationText}`, italics: true, color: '#666', fontSize: 9 }
      : null,
  ].filter(Boolean);
}

function findingsTable(findings) {
  const body = [
    [
      { text: 'Status', bold: true },
      { text: 'Severity', bold: true },
      { text: 'Check', bold: true },
      { text: 'Detail', bold: true },
    ],
    ...findings.map((f) => [
      f.status,
      f.severity,
      f.title,
      (f.detail || '').slice(0, 120),
    ]),
  ];
  return {
    table: {
      headerRows: 1,
      widths: [55, 55, '*', '*'],
      body,
    },
    layout: 'lightHorizontalLines',
    fontSize: 8,
  };
}

export function buildDocDefinition(run, findings, server) {
  const critical = findings.filter(
    (f) => f.status === 'FAIL' && ['CRITICAL', 'HIGH'].includes(f.severity),
  );

  return {
    pageMargins: [40, 60, 40, 60],
    header: {
      text: 'Server Hardening Report',
      alignment: 'right',
      margin: [0, 20, 40, 0],
      fontSize: 8,
      color: '#888',
    },
    footer: (page, total) => ({
      text: `${page} / ${total}`,
      alignment: 'center',
      fontSize: 8,
      color: '#888',
    }),
    content: [
      { text: server.name || 'Server', fontSize: 24, bold: true, margin: [0, 40, 0, 4] },
      {
        text: `${server.host} · ${run.osSnapshot?.distro ?? 'Unknown OS'}`,
        fontSize: 11,
        color: '#666',
      },
      {
        text: new Date(run.startedAt).toLocaleString(),
        fontSize: 10,
        color: '#888',
        margin: [0, 0, 0, 28],
      },
      {
        table: {
          widths: ['*'],
          body: [
            [
              {
                stack: [
                  {
                    text: String(run.score ?? '—'),
                    fontSize: 48,
                    bold: true,
                    alignment: 'center',
                    color: gradeColor(run.grade),
                  },
                  {
                    text: `Grade ${run.grade ?? 'N/A'}`,
                    fontSize: 14,
                    alignment: 'center',
                    color: '#666',
                  },
                ],
                margin: [0, 12, 0, 12],
              },
            ],
          ],
        },
        layout: 'noBorders',
        fillColor: '#f6f8fa',
      },
      {
        text: coverageLine(run),
        fontSize: 10,
        color: '#666',
        margin: [0, 16, 0, 0],
        italics: true,
      },
      { text: '', pageBreak: 'after' },
      { text: 'Priority findings', fontSize: 16, bold: true, margin: [0, 0, 0, 8] },
      ...(critical.length
        ? critical.flatMap(findingBlock)
        : [{ text: 'No critical or high failures.', color: '#666' }]),
      { text: 'All checks', fontSize: 16, bold: true, margin: [0, 24, 0, 8] },
      findingsTable(findings),
    ],
    defaultStyle: { font: 'Helvetica', fontSize: 10 },
  };
}

export function buildPdfBuffer(run, findings, server) {
  const doc = buildDocDefinition(run, findings, server);
  const pdfDoc = printer.createPdfKitDocument(doc);
  return new Promise((resolve, reject) => {
    const chunks = [];
    pdfDoc.on('data', (c) => chunks.push(c));
    pdfDoc.on('end', () => resolve(Buffer.concat(chunks)));
    pdfDoc.on('error', reject);
    pdfDoc.end();
  });
}

export function pdfFilename(server, run) {
  const safe = String(server.name || 'server')
    .replace(/[^a-zA-Z0-9._-]+/g, '_')
    .slice(0, 40);
  const day = new Date(run.startedAt).toISOString().slice(0, 10);
  return `hardening-${safe}-${day}.pdf`;
}
