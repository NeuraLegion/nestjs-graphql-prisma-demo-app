import { Test } from '@nestjs/testing';
import { SecRunner } from '@sectester/runner';
import { INestApplication } from '@nestjs/common';
import { AppModule } from '../../src/app.module';
import { configureApp } from '../../src/main';
import { TestType } from '@sectester/scan';

jest.setTimeout(15 * 60 * 1000); // 15 minutes

describe('POST /api/users/login', () => {
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

  it('should perform security tests', async () => {
    await runner
      .createScan({
        tests: [
          'brute_force_login',
          TestType.CSRF,
          TestType.EXCESSIVE_DATA_EXPOSURE,
          TestType.INSECURE_OUTPUT_HANDLING
        ],
        attackParamLocations: ['body']
      })
      .threshold('medium')
      .timeout(15 * 60 * 1000)
      .run({
        method: 'POST',
        url: `${server}/api/users/login`,
        body: {
          mimeType: 'application/json',
          text: JSON.stringify({
            user: {
              email: 'user@example.com',
              password: 'password123'
            }
          })
        }
      });
  });
});