import { Test } from '@nestjs/testing';
import { SecRunner } from '@sectester/runner';
import { INestApplication } from '@nestjs/common';
import { AppModule } from '../../src/app.module';
import { configureApp } from '../../src/main';
import { TestType } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

describe('Security Tests for POST /api/users', () => {
  let runner!: SecRunner;
  let app!: INestApplication;
  let server: any;
  let baseUrl: string;

  beforeAll(async () => {
    const moduleFixture = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await configureApp(app);
    app.useLogger(false);

    server = app.getHttpServer();
    await app.init();

    const port = server.address().port;
    const protocol = app instanceof Server ? 'https' : 'http';
    baseUrl = `${protocol}://localhost:${port}`;
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(async () => {
    runner = new SecRunner({
      hostname: process.env.BRIGHT_HOSTNAME,
    });

    await runner.init();
  });

  afterEach(() => runner.clear());

  it('POST /api/users', async () => {
    await runner
      .createScan({
        tests: [TestType.CSRF, TestType.BRUTE_FORCE_LOGIN, TestType.MASS_ASSIGNMENT, TestType.SQLI, TestType.XSS],
        attackParamLocations: ['BODY', 'HEADER', 'QUERY']
      })
      .threshold('MEDIUM')
      .timeout(15 * 60 * 1000)
      .run({
        method: 'POST',
        url: `${baseUrl}/api/users`,
        headers: [],
        body: {
          mimeType: 'application/json',
          text: JSON.stringify({
            user: {
              username: 'example',
              email: 'user@example.com',
              password: 'password123'
            }
          })
        }
      });
  });
});