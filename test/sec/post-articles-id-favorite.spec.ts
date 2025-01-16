import { SecRunner } from '@sectester/runner';
import { TestType, AttackParamLocation, Severity } from '@sectester/scan';

it('POST /articles/{id}/favorite', async () => {
  const runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME,
  });

  await runner.init();

  await runner
    .createScan({
      tests: [
        TestType.CSRF,
        'mass_assignment',
        TestType.BROKEN_ACCESS_CONTROL,
        'id_enumeration'
      ],
      attackParamLocations: [
        AttackParamLocation.BODY,
        AttackParamLocation.PATH
      ]
    })
    .threshold(Severity.MEDIUM)
    .timeout(15 * 60 * 1000) // 15 minutes
    .run({
      method: 'POST',
      url: `${baseUrl}/articles/{id}/favorite`,
      body: {
        mimeType: 'application/json',
        text: JSON.stringify({
          where: { id: '<article_id>' },
          value: true
        })
      }
    });
});