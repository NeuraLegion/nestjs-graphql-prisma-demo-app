import { Test } from '@nestjs/testing';
import { SecRunner } from '@sectester/runner';
import { INestApplication } from '@nestjs/common';
import { AppModule } from '../../src/app.module';
import { configureApp } from '../../src/main';
import { TestType } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

describe('Security Tests for POST /articles', () => {
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

  it('POST /articles', async () => {
    await runner
      .createScan({
        tests: [TestType.XSS, TestType.SQLI, 'mass_assignment', 'csrf'],
        attackParamLocations: ['body']
      })
      .threshold('medium')
      .timeout(15 * 60 * 1000)
      .run({
        method: 'POST',
        url: `${baseUrl}/articles`,
        headers: [],
        body: {
          mimeType: 'application/json',
          text: JSON.stringify({
            input: {
              title: '<title>',
              description: '<description>',
              body: '<body>',
              tags: ['<tag>']
            }
          })
        }
      });
  });
});