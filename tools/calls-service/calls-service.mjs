if (!process.env.SERVICE_MODE) {
  process.env.SERVICE_MODE = 'calls';
}

if (!process.env.SERVICE_NAME) {
  process.env.SERVICE_NAME = 'deep-calls-service';
}

await import('./calls-service-runtime.mjs');
