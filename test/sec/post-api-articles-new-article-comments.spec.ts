import { SecRunner } from '@sectester/runner';
import { TestType } from '@sectester/scan';

let runner: SecRunner;

beforeAll(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME,
  });

  await runner.init();
});

afterAll(async () => {
  await runner.clear();
});

it('POST /api/articles/new-article/comments', async () => {
  await runner
    .createScan({
      tests: [TestType.CSRF, TestType.XSS, TestType.BROKEN_ACCESS_CONTROL, 'INSECURE_OUTPUT_HANDLING'],
      attackParamLocations: ['BODY', 'HEADER']
    })
    .threshold('MEDIUM')
    .timeout(15 * 60 * 1000) // 15 minutes
    .run({
      method: 'POST',
      url: 'https://api.example.com/api/articles/new-article/comments',
      headers: [{ name: 'Authorization', value: 'Token exampleToken' }],
      body: { mimeType: 'application/json', text: '{"comment": {"body": "Great article!"}}' }
    });
});