import { SecRunner } from '@sectester/runner';
import { TestType, AttackParamLocation, Severity } from '@sectester/scan';

it('PUT /api/user', async () => {
  const runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME,
  });

  await runner.init();

  await runner
    .createScan({
      tests: [
        TestType.BROKEN_ACCESS_CONTROL,
        TestType.CSRF,
        'MASS_ASSIGNMENT',
        'EMAIL_INJECTION',
        TestType.XSS
      ],
      attackParamLocations: [
        AttackParamLocation.BODY,
        AttackParamLocation.HEADER
      ]
    })
    .threshold(Severity.MEDIUM)
    .timeout(15 * 60 * 1000) // 15 minutes
    .run({
      method: 'PUT',
      url: 'https://api.example.com/api/user',
      headers: {
        Authorization: 'Token exampleToken',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        user: {
          email: 'newemail@example.com',
          bio: 'New bio',
          image: 'newimage.jpg'
        }
      })
    });

  await runner.clear();
});