import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(__dirname, '..');
const workflowRoot = path.join(repositoryRoot, '.github', 'workflows');

export async function validateWorkflows() {
  const failures = [];
  let uploadCount = 0;
  for (const name of (await readdir(workflowRoot)).filter(item => item.endsWith('.yml')).sort()) {
    const content = await readFile(path.join(workflowRoot, name), 'utf8');
    const lines = content.split(/\r?\n/);
    const workflowUploadCount = lines.filter(line => line.includes('uses: actions/upload-artifact@v4')).length;
    const preparationCount = lines.filter(line => line.includes('scripts/artifact-upload-manifest.mjs')).length;
    const gateCount = lines.filter(line => line.includes('scripts/artifact-upload-gate.mjs')).length;
    if (workflowUploadCount !== preparationCount || workflowUploadCount !== gateCount) {
      failures.push(`${name}: every upload must have one manifest preparation and one fail-closed upload gate`);
    }
    for (let index = 0; index < lines.length; index += 1) {
      if (!lines[index].includes('uses: actions/upload-artifact@v4')) continue;
      uploadCount += 1;
      const before = lines.slice(Math.max(0, index - 8), index).join('\n');
      const after = lines.slice(index, Math.min(lines.length, index + 12)).join('\n');
      if (!/steps\.(?:prepare[_a-z]*)\.outcome == 'success'/.test(before)) {
        failures.push(`${name}:${index + 1}: upload lacks fail-closed preparation outcome`);
      }
      if (!/steps\.(?:[a-z_]*secret_scan)\.outcome == 'success'/.test(before)) {
        failures.push(`${name}:${index + 1}: upload lacks fail-closed scanner outcome`);
      }
      if (!/path:\s*(?:\||)?[\s\S]*runner\.temp.*deep-upload\//.test(after)) {
        failures.push(`${name}:${index + 1}: upload path is not an exact staged manifest root`);
      }
    }
    if (/path:\s*deep-devops\/artifacts\/.*\*\*/.test(content)) {
      failures.push(`${name}: broad artifact glob remains uploadable`);
    }
  }
  if (uploadCount === 0) failures.push('no artifact uploads were found');
  return { uploadCount, failures };
}

export async function main() {
  const result = await validateWorkflows();
  if (result.failures.length > 0) {
    for (const failure of result.failures) console.error(failure);
    throw new Error(`${result.failures.length} artifact upload contract violation(s)`);
  }
  console.log(`Artifact upload contracts passed (${result.uploadCount} exact staged uploads).`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(`Artifact upload contract validation failed: ${error.message}`);
    process.exitCode = 1;
  });
}
