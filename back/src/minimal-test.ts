import 'reflect-metadata';
import express from 'express';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const app: express.Express = express();
const PORT = process.env.PORT || 5000;

console.log('🔄 Starting minimal test server...');

// Basic middleware
app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'Minimal server is running',
    timestamp: new Date().toISOString(),
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Minimal server running on port ${PORT}`);
  console.log(`🔗 Health check: https://node.localhost/health`);
});

export default app;
