// Runs the shared API suite (app.test.mjs) against the Go backend.
process.env.TRINETRA_BACKEND = 'go';
await import('./app.test.mjs');
