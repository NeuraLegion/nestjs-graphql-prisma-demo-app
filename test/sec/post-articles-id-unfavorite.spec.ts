import { SecRunner } from '@sectester/runner';
import { TestType, AttackParamLocation, Severity } from '@sectester/scan';

it('POST /articles/{id}/unfavorite', async () => {
  const runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME,
  });

  await runner.init();

  await runner
    .createScan({
      tests: [TestType.CSRF, TestType.BROKEN_ACCESS_CONTROL, TestType.MASS_ASSIGNMENT, TestType.SQLI, TestType.XSS],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.PATH]
    })
    .threshold(Severity.MEDIUM)
    .timeout(15 * 60 * 1000) // 15 minutes
    .run({
      method: 'POST',
      url: `${baseUrl}/articles/{id}/unfavorite`,
      body: {
        mimeType: 'application/json',
        text: '{"where": {"id": "<article_id>"}, "value": false}'
      }
    });
});