import { Test } from '@nestjs/testing';
import { SecRunner } from '@sectester/runner';
import { INestApplication } from '@nestjs/common';
import { AppModule } from '../../src/app.module';
import { configureApp } from '../../src/main';
import { TestType, AttackParamLocation, Severity } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

describe('POST /createComment', () => {
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

  it('POST /createComment', async () => {
    await runner
      .createScan({
        tests: [TestType.CSRF, TestType.XSS, TestType.SQLI, 'broken_access_control', 'mass_assignment'],
        attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER],
      })
      .threshold(Severity.MEDIUM)
      .timeout(15 * 60 * 1000)
      .run({
        method: 'POST',
        url: `${baseUrl}/createComment`,
        headers: {
          Authorization: 'Bearer <token>',
          'Content-Type': 'application/json',
        },
        body: {
          data: { body: 'This is a comment.' },
          where: { articleId: 'example-article-id' },
        },
      });
  });
});