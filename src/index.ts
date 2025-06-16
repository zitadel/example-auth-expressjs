import 'dotenv/config';
import app, { initializeOIDC } from './app.js';

async function startServer(): Promise<void> {
  const PORT = process.env.PORT || 3000;

  await initializeOIDC();
  app.listen(PORT, (): void => {
    console.log(`Server running on port ${PORT}`);
  });
}

startServer().catch(console.error);
