import { SecRunner } from '@sectester/runner';
import { TestType } from '@sectester/scan';

it('POST /api/profiles/:username/follow', async () => {
  const runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME,
  });

  await runner.init();

  await runner
    .createScan({
      tests: [TestType.CSRF, TestType.BROKEN_ACCESS_CONTROL, 'EXCESSIVE_DATA_EXPOSURE', 'BRUTE_FORCE_LOGIN'],
      attackParamLocations: ['BODY', 'HEADER'],
    })
    .threshold('MEDIUM')
    .timeout(15 * 60 * 1000) // 15 minutes
    .run({
      method: 'POST',
      url: 'https://api.example.com/api/profiles/johndoe/follow',
      headers: [{ name: 'Authorization', value: 'Token exampleToken' }],
      body: '',
    });

  await runner.clear();
});