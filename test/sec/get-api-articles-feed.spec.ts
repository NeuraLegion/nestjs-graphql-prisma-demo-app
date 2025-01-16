import { SecRunner } from '@sectester/runner';
import { TestType } from '@sectester/scan';

it('GET /api/articles/feed', async () => {
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
        'HTTP_METHOD_FUZZING',
        TestType.SECRET_TOKENS
      ],
      attackParamLocations: ['QUERY', 'HEADER']
    })
    .threshold('MEDIUM')
    .timeout(15 * 60 * 1000) // 15 minutes
    .run({
      method: 'GET',
      url: 'https://api.example.com/api/articles/feed',
      headers: {
        Authorization: 'Token exampleToken'
      },
      query: {
        limit: '20',
        offset: '0'
      }
    });
});