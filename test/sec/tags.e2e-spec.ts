import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, Severity, TestType } from '@sectester/scan';
import { INestApplication } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigModule } from '@nestjs/config';
import { AppModule } from '../src/app.module';
import request from 'supertest';
import { Server } from 'https';

let app: INestApplication;
let runner: SecRunner;
let server: any;
let baseUrl: string;

beforeAll(async () => {
  const moduleFixture: TestingModule = await Test.createTestingModule({
    imports: [AppModule, ConfigModule.forRoot()]
  }).compile();

  app = moduleFixture.createNestApplication({
    logger: false
  });
  await app.init();

  server = app.getHttpServer();
  server.listen(0);

  const port = server.address().port;
  const protocol = server instanceof Server ? 'https' : 'http';
  baseUrl = `${protocol}://localhost:${port}`;

  runner = new SecRunner({ hostname: 'app.brightsec.com' });
  await runner.init();
});

afterAll(async () => {
  await runner.clear();
  await app.close();
});

describe('Tags API Security Tests', () => {
  const timeout = 600000;
  jest.setTimeout(timeout);

  beforeEach(async () => {
    await runner.init();
  });

  afterEach(() => runner.clear());

  it('should not have SQL Injection vulnerability', async () => {
    await runner
      .createScan({
        tests: [TestType.SQLI],
      })
      .run({
        method: 'GET',
        url: 'http://example.com/tags',
      });
  });

  it('should not have Cross-Site Scripting (XSS) vulnerability', async () => {
    await runner
      .createScan({
        tests: [TestType.XSS],
      })
      .run({
        method: 'GET',
        url: 'http://example.com/tags',
      });
  });

  it('should not have Server-Side Request Forgery (SSRF) vulnerability', async () => {
    await runner
      .createScan({
        tests: [TestType.SSRF],
      })
      .run({
        method: 'GET',
        url: 'http://example.com/tags',
      });
  });

  it('should not have XSS (localhost)', async () => {
    await runner
      .createScan({
        name: expect.getState().currentTestName,
        tests: [TestType.XSS],
        attackParamLocations: [AttackParamLocation.QUERY]
      })
      .threshold(Severity.MEDIUM)
      .timeout(timeout)
      .run({
        method: 'GET',
        url: `${baseUrl}/tags`
      });
  });
});
