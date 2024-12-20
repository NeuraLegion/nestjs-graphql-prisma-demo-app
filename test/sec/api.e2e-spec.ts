import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, Severity, TestType } from '@sectester/scan';
import { INestApplication } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigModule } from '@nestjs/config';
import { Server } from 'https';

describe('/api', () => {
  const timeout = 600000;
  jest.setTimeout(timeout);

  let runner!: SecRunner;
  let app!: INestApplication;
  let baseUrl!: string;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot()
      ]
    }).compile();

    app = moduleFixture.createNestApplication({
      logger: false
    });
    await app.init();

    const server = app.getHttpServer();

    server.listen(0);

    const port = server.address().port;
    const protocol = server instanceof Server ? 'https' : 'http';
    baseUrl = `${protocol}://localhost:${port}`;
  });

  afterAll(() => app.close());

  beforeEach(async () => {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    runner = new SecRunner({ hostname: process.env.BRIGHT_HOSTNAME! });

    await runner.init();
  });

  afterEach(() => runner.clear());

  describe('GET /', () => {
    it('should not have SQLi', async () => {
      await runner
        .createScan({
          name: expect.getState().currentTestName,
          tests: [TestType.SQLI],
          attackParamLocations: [AttackParamLocation.QUERY]
        })
        .threshold(Severity.MEDIUM)
        .timeout(timeout)
        .run({
          method: 'GET',
          url: `${baseUrl}/api`
        });
    });
  });
});