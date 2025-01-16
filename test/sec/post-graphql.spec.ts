import { Test } from '@nestjs/testing';
import { SecRunner } from '@sectester/runner';
import { INestApplication } from '@nestjs/common';
import { AppModule } from '../../src/app.module';
import { configureApp } from '../../src/main';
import { TestType } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

describe('Security Tests for POST /graphql', () => {
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

  it('POST /graphql', async () => {
    await runner
      .createScan({
        tests: [TestType.SQLI, TestType.XSS, 'graphql_introspection', 'excessive_data_exposure'],
        attackParamLocations: ['BODY']
      })
      .threshold('MEDIUM')
      .timeout(15 * 60 * 1000)
      .run({
        method: 'POST',
        url: `${server}/graphql`,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: 'mutation { follow(where: { userId: "sampleUserId" }, value: true) { userId, email, name, bio, image } }'
        })
      });
  });
});