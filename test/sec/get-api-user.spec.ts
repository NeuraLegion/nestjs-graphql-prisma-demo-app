import { SecRunner } from '@sectester/runner';
import { TestType, AttackParamLocation, Severity } from '@sectester/scan';

it('GET /api/user', async () => {
  const runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME,
  });

  await runner.init();

  await runner
    .createScan({
      tests: [
        TestType.BROKEN_ACCESS_CONTROL,
        TestType.CSRF,
        'EXCESSIVE_DATA_EXPOSURE',
        TestType.HTTP_METHOD_FUZZING,
        TestType.ID_ENUMERATION,
        TestType.INSECURE_OUTPUT_HANDLING
      ],
      attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.PATH, AttackParamLocation.QUERY]
    })
    .threshold(Severity.MEDIUM)
    .timeout(15 * 60 * 1000) // 15 minutes
    .run({
      method: 'GET',
      url: 'https://api.example.com/api/user',
      headers: { 'Authorization': 'Token exampleToken' }
    });
});