import { SecRunner } from '@sectester/runner';
import { TestType } from '@sectester/scan';
import request from 'supertest';
import { INestApplication } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { AppModule } from '../src/app.module';
import { configureApp } from '../src/main';

let app: INestApplication;
let server: any;
let runner: SecRunner;

beforeAll(async () => {
  const moduleFixture: TestingModule = await Test.createTestingModule({
    imports: [AppModule],
  }).compile();

  app = moduleFixture.createNestApplication();
  await configureApp(app);
  await app.init();

  server = app.getHttpServer();

  runner = new SecRunner({ hostname: 'app.brightsec.com' });
  await runner.init();
});

afterAll(async () => {
  await runner.clear();
  await app.close();
});

describe('User login security tests', () => {
  it('should not have SQLi vulnerability', async () => {
    const scan = runner.createScan({
      tests: [TestType.SQLI],
    });

    await scan.run({
      method: 'POST',
      url: 'https://api.example.com/api/users/login',
      body: { user: { email: 'example@example.com', password: 'password' } },
    });
  });

  it('should not have XSS vulnerability', async () => {
    const scan = runner.createScan({
      tests: [TestType.XSS],
    });

    await scan.run({
      method: 'POST',
      url: 'https://api.example.com/api/users/login',
      body: { user: { email: 'example@example.com', password: 'password' } },
    });
  });

  it('should not have CSRF vulnerability', async () => {
    const scan = runner.createScan({
      tests: [TestType.CSRF],
    });

    await scan.run({
      method: 'POST',
      url: 'https://api.example.com/api/users/login',
      body: { user: { email: 'example@example.com', password: 'password' } },
    });
  });
});
