import 'dotenv/config';
import { build } from './app.js';

async function startServer(): Promise<void> {
  const app = await build();
  const PORT = process.env.PORT || 3000;

  app.listen(PORT, (): void => {
    console.log(`Stateless server with Express running on port ${PORT}`);
  });
}

startServer().catch(console.error);
