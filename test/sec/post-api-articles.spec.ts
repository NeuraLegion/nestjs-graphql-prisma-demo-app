import { SecRunner } from '@sectester/runner';
import { TestType } from '@sectester/scan';

it('POST /api/articles', async () => {
  const runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME,
  });

  await runner.init();

  await runner
    .createScan({
      tests: [
        TestType.CSRF,
        TestType.MASS_ASSIGNMENT,
        TestType.XSS,
        TestType.BROKEN_ACCESS_CONTROL,
        TestType.JWT
      ],
      attackParamLocations: [
        'body',
        'header'
      ]
    })
    .threshold('MEDIUM')
    .timeout(15 * 60 * 1000) // 15 minutes
    .run({
      method: 'POST',
      url: 'https://api.example.com/api/articles',
      headers: {
        'Authorization': 'Token exampleToken',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        article: {
          title: 'New Article',
          description: 'Article description',
          body: 'Article body',
          tagList: ['tag1', 'tag2']
        }
      })
    });

  await runner.clear();
});