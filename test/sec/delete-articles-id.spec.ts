import { Test } from '@nestjs/testing';
import { SecRunner } from '@sectester/runner';
import { INestApplication } from '@nestjs/common';
import { AppModule } from '../../src/app.module';
import { configureApp } from '../../src/main';
import { TestType, AttackParamLocation, Severity } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

describe('DELETE /articles/:id', () => {
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

  it('should test security vulnerabilities', async () => {
    await runner
      .createScan({
        tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.MASS_ASSIGNMENT, TestType.SQLI],
        attackParamLocations: [AttackParamLocation.PATH, AttackParamLocation.BODY],
      })
      .threshold(Severity.MEDIUM)
      .timeout(15 * 60 * 1000)
      .run({
        method: 'DELETE',
        url: `${baseUrl}/articles/<article_id>`,
        body: { where: { id: '<article_id>' } },
      });
  });
});