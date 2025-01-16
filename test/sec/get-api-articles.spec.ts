import { Test } from '@nestjs/testing';
import { SecRunner } from '@sectester/runner';
import { INestApplication } from '@nestjs/common';
import { AppModule } from '../../src/app.module';
import { configureApp } from '../../src/main';
import { TestType } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

describe('Security Tests for GET /api/articles', () => {
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

  it('GET /api/articles', async () => {
    await runner
      .createScan({
        tests: [
          TestType.BROKEN_ACCESS_CONTROL,
          TestType.CSRF,
          'EXCESSIVE_DATA_EXPOSURE',
          TestType.HTTP_METHOD_FUZZING,
          'ID_ENUMERATION',
          'INSECURE_OUTPUT_HANDLING',
          TestType.SQLI,
          TestType.XSS
        ],
        attackParamLocations: [
          'QUERY',
          'HEADER'
        ]
      })
      .threshold('MEDIUM')
      .timeout(15 * 60 * 1000)
      .run({
        method: 'GET',
        url: `${server}/api/articles`,
        headers: {
          Authorization: 'Token exampleToken'
        },
        queryString: {
          tag: 'tag1',
          author: 'johndoe',
          favorited: 'janedoe',
          limit: '20',
          offset: '0'
        }
      });
  });
});