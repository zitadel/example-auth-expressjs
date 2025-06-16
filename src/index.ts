import 'dotenv/config';
import app from './app.js';

async function startServer(): Promise<void> {
  const PORT = process.env.PORT || 3000;

  app.listen(PORT, (): void => {
    console.log(`Server running on port ${PORT}`);
  });
}

startServer().catch(console.error);
