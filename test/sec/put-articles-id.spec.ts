import { SecRunner } from '@sectester/runner';
import { TestType, AttackParamLocation, Severity } from '@sectester/scan';

it('PUT /articles/:id', async () => {
  const runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME,
  });

  await runner.init();

  await runner
    .createScan({
      tests: [
        TestType.BROKEN_ACCESS_CONTROL,
        TestType.CSRF,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.MASS_ASSIGNMENT,
        TestType.SQLI,
        TestType.XSS,
      ],
      attackParamLocations: [
        AttackParamLocation.BODY,
        AttackParamLocation.HEADER,
        AttackParamLocation.PATH,
        AttackParamLocation.QUERY,
      ],
    })
    .threshold(Severity.MEDIUM)
    .timeout(15 * 60 * 1000) // 15 minutes
    .run({
      method: 'PUT',
      url: `${baseUrl}/articles/{id}`,
      headers: {},
      body: {
        mimeType: 'application/json',
        text: JSON.stringify({
          data: {
            title: '<title>',
            description: '<description>',
            body: '<body>',
            tags: ['<tag>'],
          },
          where: { id: '<article_id>' },
        }),
      },
    });

  await runner.clear();
});