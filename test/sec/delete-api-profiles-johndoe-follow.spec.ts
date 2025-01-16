import { SecRunner } from '@sectester/runner';
import { TestType } from '@sectester/scan';

it('DELETE /api/profiles/johndoe/follow', async () => {
  const runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME,
  });

  await runner.init();

  await runner
    .createScan({
      tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.CSRF, 'HTTP_METHOD_FUZZING'],
      attackParamLocations: ['HEADER', 'BODY', 'QUERY']
    })
    .threshold('MEDIUM')
    .timeout(15 * 60 * 1000) // 15 minutes
    .run({
      method: 'DELETE',
      url: 'https://api.example.com/api/profiles/johndoe/follow',
      headers: [{ name: 'Authorization', value: 'Token exampleToken' }],
      queryString: [],
      postData: { mimeType: '', text: '' }
    });

  await runner.clear();
});