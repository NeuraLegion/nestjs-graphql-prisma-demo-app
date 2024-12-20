import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, Severity, TestType } from '@sectester/scan';
import { INestApplication } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigModule } from '@nestjs/config';
import { Server } from 'https';

describe('/profiles', () => {
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

  describe('GET /api/profiles/exampleUser', () => {
    it('should not have excessive data exposure', async () => {
      await runner
        .createScan({
          name: expect.getState().currentTestName,
          tests: [TestType.EXCESSIVE_DATA_EXPOSURE],
          attackParamLocations: [AttackParamLocation.QUERY]
        })
        .threshold(Severity.MEDIUM)
        .timeout(timeout)
        .run({
          method: 'GET',
          url: `${baseUrl}/api/profiles/exampleUser`,
          headers: { Authorization: 'Token exampleToken' }
        });
    });
  });

  describe('POST /api/profiles/:username/follow', () => {
    it('should not have CSRF', async () => {
      await runner
        .createScan({
          name: expect.getState().currentTestName,
          tests: [TestType.CSRF],
          attackParamLocations: [AttackParamLocation.BODY]
        })
        .threshold(Severity.MEDIUM)
        .timeout(timeout)
        .run({
          method: 'POST',
          url: `${baseUrl}/api/profiles/exampleUser/follow`,
          headers: { Authorization: 'Token exampleToken' },
          body: {}
        });
    });
  });

  describe('DELETE /api/profiles/:username/follow', () => {
    it('should not have broken access control', async () => {
      await runner
        .createScan({
          name: expect.getState().currentTestName,
          tests: [TestType.BROKEN_ACCESS_CONTROL],
          attackParamLocations: [AttackParamLocation.HEADER]
        })
        .threshold(Severity.MEDIUM)
        .timeout(timeout)
        .run({
          method: 'DELETE',
          url: `${baseUrl}/api/profiles/exampleUser/follow`,
          headers: { Authorization: 'Token exampleToken' }
        });
    });
  });
});
