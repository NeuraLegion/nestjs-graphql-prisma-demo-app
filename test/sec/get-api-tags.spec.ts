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

it('GET /api/tags', async () => {
  await runner
    .createScan({
      tests: [TestType.EXCESSIVE_DATA_EXPOSURE, 'HTTP_METHOD_FUZZING'],
      attackParamLocations: ['QUERY', 'BODY', 'HEADER', 'PATH']
    })
    .threshold('MEDIUM')
    .timeout(15 * 60 * 1000) // 15 minutes
    .run({
      method: 'GET',
      url: 'https://api.example.com/api/tags'
    });
});