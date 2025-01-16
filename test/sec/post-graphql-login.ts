import { SecRunner } from '@sectester/runner';
import { TestType } from '@sectester/scan';
import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { AppModule } from '../../src/app.module';
import { configureApp } from '../../src/main';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

describe('POST /graphql login', () => {
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

  it('should test security of POST /graphql login', async () => {
    await runner
      .createScan({
        tests: [
          TestType.GRAPHQL_INTROSPECTION,
          TestType.BRUTE_FORCE_LOGIN,
          TestType.EXCESSIVE_DATA_EXPOSURE,
          TestType.SQLI,
          TestType.XSS,
        ],
        attackParamLocations: ['BODY', 'HEADER'],
      })
      .threshold('MEDIUM')
      .timeout(15 * 60 * 1000)
      .run({
        method: 'POST',
        url: '/graphql',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: 'mutation { loginUser(data: { email: "sample@example.com", password: "password123" }) { userId, email, name, bio, image } }',
        }),
      });
  });
});