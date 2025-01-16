import { SecRunner } from '@sectester/runner';
import { TestType } from '@sectester/scan';
import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { AppModule } from '../../src/app.module';
import { configureApp } from '../../src/main';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

describe('GET /articles/count', () => {
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

  it('should test security vulnerabilities', async () => {
    await runner
      .createScan({
        tests: [TestType.SQLI, 'nosql', 'excessive_data_exposure', 'mass_assignment'],
        attackParamLocations: ['query']
      })
      .threshold('medium')
      .timeout(15 * 60 * 1000)
      .run({
        method: 'GET',
        url: `${server}/articles/count`,
        query: {
          where: '{}',
          feed: 'false'
        }
      });
  });
});