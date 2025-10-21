import request from 'supertest';
import { build } from '../src/app.js';
import { Application } from 'express';

describe('GET /', () => {
  let app: Application;

  beforeAll(async () => {
    app = await build();
  });

  it('should return 200 OK and render the home page', async () => {
    const res = await request(app).get('/');
    expect(res.status).toBe(200);
  });
});
