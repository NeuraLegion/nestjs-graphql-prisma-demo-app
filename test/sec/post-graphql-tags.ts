import { Test } from '@nestjs/testing';
import { SecRunner } from '@sectester/runner';
import { INestApplication } from '@nestjs/common';
import { AppModule } from '../../src/app.module';
import { configureApp } from '../../src/main';
import { TestType } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

describe('POST /graphql', () => {
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

  it('should test for security vulnerabilities', async () => {
    await runner
      .createScan({
        tests: [TestType.GraphQLIntrospection, TestType.ExcessiveDataExposure, TestType.SQLI, TestType.XSS],
        attackParamLocations: ['BODY']
      })
      .threshold('MEDIUM')
      .timeout(15 * 60 * 1000)
      .run({
        method: 'POST',
        url: `${baseUrl}/graphql`,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: '{ tags { id name } }' })
      });
  });
});