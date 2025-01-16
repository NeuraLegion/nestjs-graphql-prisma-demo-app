import { SecRunner } from '@sectester/runner';
import { TestType, AttackParamLocation, Severity } from '@sectester/scan';

it('GET /articles/feed', async () => {
  const runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME,
  });

  await runner.init();

  await runner
    .createScan({
      tests: [
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.BROKEN_ACCESS_CONTROL,
        'HTTP_METHOD_FUZZING',
        'ID_ENUMERATION'
      ],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.MEDIUM)
    .timeout(15 * 60 * 1000) // 15 minutes
    .run({
      method: 'GET',
      url: `${baseUrl}/articles/feed`,
      query: {
        offset: '0',
        limit: '20'
      }
    });
});