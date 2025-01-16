import { SecRunner } from '@sectester/runner';
import { TestType, AttackParamLocation, Severity } from '@sectester/scan';

it('POST /api/articles/new-article/favorite', async () => {
  const runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME,
  });

  await runner.init();

  await runner
    .createScan({
      tests: [TestType.CSRF, TestType.BROKEN_ACCESS_CONTROL, TestType.JWT],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER],
    })
    .threshold(Severity.MEDIUM)
    .timeout(15 * 60 * 1000) // 15 minutes
    .run({
      method: 'POST',
      url: 'https://api.example.com/api/articles/new-article/favorite',
      headers: [{ name: 'Authorization', value: 'Token exampleToken' }],
      body: '',
    });

  await runner.clear();
});