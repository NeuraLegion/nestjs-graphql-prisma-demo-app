import { Test } from '@nestjs/testing';
import { SecRunner } from '@sectester/runner';
import { INestApplication } from '@nestjs/common';
import { AppModule } from '../../src/app.module';
import { configureApp } from '../../src/main';
import { TestType, AttackParamLocation, Severity } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

describe('Security Tests for GET /articles', () => {
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
    baseUrl = `http://localhost:${port}`;
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

  it('GET /articles', async () => {
    await runner
      .createScan({
        tests: [TestType.SQLI, TestType.XSS, 'excessive_data_exposure', 'mass_assignment'],
        attackParamLocations: [AttackParamLocation.QUERY_STRING]
      })
      .threshold(Severity.MEDIUM)
      .run({
        method: 'GET',
        url: `${baseUrl}/articles`,
        queryString: {
          where: '{}',
          feed: 'false'
        }
      });
  });
});