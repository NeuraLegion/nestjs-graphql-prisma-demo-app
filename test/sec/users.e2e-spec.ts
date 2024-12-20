import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, Severity, TestType } from '@sectester/scan';
import { INestApplication } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { AppModule } from '../src/app.module';
import request from 'supertest';

let app: INestApplication;
let server: any;
let runner: SecRunner;

const baseUrl = 'https://api.example.com';

beforeAll(async () => {
  const moduleFixture: TestingModule = await Test.createTestingModule({
    imports: [AppModule],
  }).compile();

  app = moduleFixture.createNestApplication();
  await app.init();

  server = app.getHttpServer();

  runner = new SecRunner({ hostname: 'app.brightsec.com' });
  await runner.init();
});

afterAll(async () => {
  await runner.clear();
  await app.close();
});

describe('User Registration Security Tests', () => {
  it('should not have SQL Injection', async () => {
    const scan = runner.createScan({
      tests: [TestType.SQLI],
      attackParamLocations: [AttackParamLocation.BODY]
    });

    await scan.run({
      method: 'POST',
      url: `${baseUrl}/api/users`,
      body: { user: { username: 'example', email: 'example@example.com', password: 'password' } }
    });
  });

  it('should not have Cross-Site Scripting (XSS)', async () => {
    const scan = runner.createScan({
      tests: [TestType.XSS],
      attackParamLocations: [AttackParamLocation.BODY]
    });

    await scan.run({
      method: 'POST',
      url: `${baseUrl}/api/users`,
      body: { user: { username: 'example', email: 'example@example.com', password: 'password' } }
    });
  });

  it('should not have Cross-Site Request Forgery (CSRF)', async () => {
    const scan = runner.createScan({
      tests: [TestType.CSRF],
      attackParamLocations: [AttackParamLocation.BODY]
    });

    await scan.run({
      method: 'POST',
      url: `${baseUrl}/api/users`,
      body: { user: { username: 'example', email: 'example@example.com', password: 'password' } }
    });
  });
});
