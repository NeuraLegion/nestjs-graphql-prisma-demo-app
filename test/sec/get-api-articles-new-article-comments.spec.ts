import { SecRunner } from '@sectester/runner';
import { TestType } from '@sectester/scan';
import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { AppModule } from '../../src/app.module';
import { configureApp } from '../../src/main';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

describe('GET /api/articles/new-article/comments', () => {
  let runner!: SecRunner;
  let app!: INestApplication;
  let server: any;
  let baseUrl!: string;

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

  it('should perform security tests', async () => {
    await runner
      .createScan({
        tests: [
          TestType.BROKEN_ACCESS_CONTROL,
          TestType.CSRF,
          TestType.EXCESSIVE_DATA_EXPOSURE,
          TestType.HTTP_METHOD_FUZZING,
          TestType.JWT,
        ],
        attackParamLocations: [],
      })
      .threshold('MEDIUM')
      .timeout(15 * 60 * 1000)
      .run({
        method: 'GET',
        url: `${baseUrl}/api/articles/new-article/comments`,
        headers: {
          Authorization: 'Token exampleToken',
        },
      });
  });
});