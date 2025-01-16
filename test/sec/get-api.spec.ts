import { Test } from '@nestjs/testing';
import { SecRunner } from '@sectester/runner';
import { INestApplication } from '@nestjs/common';
import { AppModule } from '../../src/app.module';
import { configureApp } from '../../src/main';
import { TestType } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

describe('Security Tests for GET /api/', () => {
  let runner!: SecRunner;
  let app!: INestApplication;
  let server: any;

  beforeAll(async () => {
    const moduleFixture = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await configureApp(app);
    app.useLogger(false);

    server = app.getHttpServer();
    await app.init();
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

  it('should test for CSRF and Excessive Data Exposure', async () => {
    await runner
      .createScan({
        tests: [TestType.CSRF, 'excessive_data_exposure'],
        attackParamLocations: ['query', 'body', 'header'],
      })
      .threshold('medium')
      .timeout(15 * 60 * 1000)
      .run({
        method: 'GET',
        url: `${server}/api/`,
      });
  });
});