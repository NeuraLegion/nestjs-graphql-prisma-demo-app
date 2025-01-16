import { SecRunner } from '@sectester/runner';
import { TestType } from '@sectester/scan';

let runner: SecRunner;
const baseUrl = 'https://api.example.com';
const timeout = 15 * 60 * 1000; // 15 minutes

beforeAll(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME,
  });

  await runner.init();
});

afterAll(() => runner.clear());

describe('DELETE /api/articles/new-article/comments/:id', () => {
  it('should test for security vulnerabilities', async () => {
    await runner
      .createScan({
        tests: [TestType.BROKEN_ACCESS_CONTROL, 'csrf', TestType.EXCESSIVE_DATA_EXPOSURE],
        attackParamLocations: ['path', 'header']
      })
      .threshold('medium')
      .timeout(timeout)
      .run({
        method: 'DELETE',
        url: `${baseUrl}/api/articles/new-article/comments/123`,
        headers: {
          Authorization: 'Token exampleToken'
        }
      });
  });
});