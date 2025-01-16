import { SecRunner } from '@sectester/runner';
import { TestType } from '@sectester/scan';

let runner: SecRunner;

beforeAll(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME,
  });

  await runner.init();
});

afterAll(() => runner.clear());

it('DELETE /deleteComment', async () => {
  await runner
    .createScan({
      tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.CSRF, TestType.SQLI, TestType.XSS],
      attackParamLocations: ['query', 'header']
    })
    .threshold('medium')
    .timeout(15 * 60 * 1000) // 15 minutes
    .run({
      method: 'DELETE',
      url: 'https://api.example.com/deleteComment',
      headers: {
        Authorization: 'Bearer <token>'
      },
      query: {
        where: '{"commentId": "example-comment-id"}'
      }
    });
});