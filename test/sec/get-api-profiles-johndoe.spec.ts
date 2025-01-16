import { SecRunner } from '@sectester/runner';
import { TestType } from '@sectester/scan';

let runner: SecRunner;

beforeAll(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME,
  });

  await runner.init();
});

afterAll(() => runner.clear());

it('GET /api/profiles/johndoe', async () => {
  await runner
    .createScan({
      tests: [TestType.BROKEN_ACCESS_CONTROL, 'EXCESSIVE_DATA_EXPOSURE', TestType.CSRF],
      attackParamLocations: ['HEADER', 'QUERY', 'BODY']
    })
    .threshold('MEDIUM')
    .timeout(15 * 60 * 1000) // 15 minutes
    .run({
      method: 'GET',
      url: 'https://api.example.com/api/profiles/johndoe',
      headers: [{ name: 'Authorization', value: 'Token exampleToken' }],
      queryString: [],
      postData: { mimeType: '', text: '' }
    });
});