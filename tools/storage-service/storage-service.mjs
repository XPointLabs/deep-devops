if (!process.env.SERVICE_MODE) {
  process.env.SERVICE_MODE = 'storage';
}

if (!process.env.SERVICE_NAME) {
  process.env.SERVICE_NAME = 'deep-storage-service';
}

await import('./storage-service-runtime.mjs');