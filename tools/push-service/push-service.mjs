if (!process.env.SERVICE_MODE) {
  process.env.SERVICE_MODE = 'push';
}

if (!process.env.SERVICE_NAME) {
  process.env.SERVICE_NAME = 'deep-push-service';
}

await import('./push-service-runtime.mjs');