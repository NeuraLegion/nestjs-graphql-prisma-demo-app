import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, Severity, TestType } from '@sectester/scan';
import request from 'supertest';
import { INestApplication } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { AppModule } from '../src/app.module';
import { configureApp } from '../src/main';

let app: INestApplication;
let server: any;
let runner: SecRunner;

const authToken = 'Token exampleToken';

beforeAll(async () => {
  const moduleFixture: TestingModule = await Test.createTestingModule({
    imports: [AppModule],
  }).compile();

  app = moduleFixture.createNestApplication();
  await configureApp(app);
  server = app.getHttpServer();
  await app.init();

  runner = new SecRunner({ hostname: 'app.brightsec.com' });
  await runner.init();
});

afterAll(async () => {
  await runner.clear();
  await app.close();
});

describe('GET /api/articles/feed', () => {
  const timeout = 300000;
  jest.setTimeout(timeout);

  it('should not have SQLi', async () => {
    await runner
      .createScan({
        tests: [TestType.SQLI],
        attackParamLocations: [AttackParamLocation.QUERY]
      })
      .threshold(Severity.HIGH)
      .timeout(timeout)
      .run({
        method: 'GET',
        url: 'https://api.example.com/api/articles/feed',
        headers: { Authorization: authToken },
        query: { limit: '20', offset: '0' }
      });
  });

  it('should not have XSS', async () => {
    await runner
      .createScan({
        tests: [TestType.XSS],
        attackParamLocations: [AttackParamLocation.QUERY]
      })
      .threshold(Severity.MEDIUM)
      .timeout(timeout)
      .run({
        method: 'GET',
        url: 'https://api.example.com/api/articles/feed',
        headers: { Authorization: authToken },
        query: { limit: '20', offset: '0' }
      });
  });

  it('should not have CSRF', async () => {
    await runner
      .createScan({
        tests: [TestType.CSRF],
        attackParamLocations: [AttackParamLocation.QUERY]
      })
      .threshold(Severity.HIGH)
      .timeout(timeout)
      .run({
        method: 'GET',
        url: 'https://api.example.com/api/articles/feed',
        headers: { Authorization: authToken },
        query: { limit: '20', offset: '0' }
      });
  });

  it('should not have SQLi (localhost)', async () => {
    await runner
      .createScan({
        tests: [TestType.SQLI],
        attackParamLocations: [AttackParamLocation.QUERY]
      })
      .threshold(Severity.MEDIUM)
      .timeout(timeout)
      .run({
        method: 'GET',
        url: 'http://localhost:3000/api/articles/feed',
        query: { offset: '0', limit: '20' }
      });
  });

  it('should not have XSS (localhost)', async () => {
    await runner
      .createScan({
        tests: [TestType.XSS],
        attackParamLocations: [AttackParamLocation.QUERY]
      })
      .threshold(Severity.MEDIUM)
      .timeout(timeout)
      .run({
        method: 'GET',
        url: 'http://localhost:3000/api/articles/feed',
        query: { offset: '0', limit: '20' }
      });
  });
});
