import 'dotenv/config';
import { createApp } from './app.js';

/**
 * The main entry point for the application.
 * It creates the Express app and starts the server.
 */
async function startServer(): Promise<void> {
  const app = await createApp();
  const PORT = process.env.PORT || 3000;

  app.listen(PORT, (): void => {
    console.log(`Stateless server with express-jwt running on port ${PORT}`);
  });
}

startServer().catch(console.error);
