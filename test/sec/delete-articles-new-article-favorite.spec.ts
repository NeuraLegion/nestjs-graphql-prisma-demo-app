import { Test } from '@nestjs/testing';
import { SecRunner } from '@sectester/runner';
import { INestApplication } from '@nestjs/common';
import { AppModule } from '../../src/app.module';
import { configureApp } from '../../src/main';
import { TestType } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

describe('DELETE /api/articles/new-article/favorite', () => {
  let runner!: SecRunner;
  let app!: INestApplication;
  let server: any;
  const baseUrl = 'https://api.example.com';

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
        tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.CSRF, 'HTTP_METHOD_FUZZING'],
        attackParamLocations: ['HEADER', 'BODY', 'QUERY']
      })
      .threshold('MEDIUM')
      .timeout(15 * 60 * 1000)
      .run({
        method: 'DELETE',
        url: `${baseUrl}/api/articles/new-article/favorite`,
        headers: { Authorization: 'Token exampleToken' },
        body: {}
      });
  });
});