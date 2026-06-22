if (!process.env.SERVICE_MODE) {
  process.env.SERVICE_MODE = 'file';
}

if (!process.env.SERVICE_NAME) {
  process.env.SERVICE_NAME = 'deep-file-service';
}

await import('./file-service-runtime.mjs');