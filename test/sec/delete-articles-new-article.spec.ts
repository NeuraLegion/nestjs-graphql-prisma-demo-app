import { SecRunner } from '@sectester/runner';
import { TestType } from '@sectester/scan';

it('DELETE /api/articles/new-article', async () => {
  const runner = new SecRunner({ hostname: process.env.BRIGHT_HOSTNAME });
  await runner.init();

  await runner
    .createScan({
      tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.CSRF, TestType.HTTP_METHOD_FUZZING],
      attackParamLocations: ['HEADER', 'BODY', 'QUERY']
    })
    .threshold('MEDIUM')
    .timeout(15 * 60 * 1000) // 15 minutes
    .run({
      method: 'DELETE',
      url: 'https://api.example.com/api/articles/new-article',
      headers: { Authorization: 'Token exampleToken' }
    });
});