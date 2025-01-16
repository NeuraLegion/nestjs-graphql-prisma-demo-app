import { SecRunner } from '@sectester/runner';
import { TestType } from '@sectester/scan';

it('POST /graphql', async () => {
  const runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME,
  });

  await runner.init();

  await runner
    .createScan({
      tests: [
        TestType.GraphQLIntrospection, 
        TestType.ExcessiveDataExposure, 
        TestType.MassAssignment, 
        TestType.SQLI, 
        TestType.XSS
      ],
      attackParamLocations: [
        'BODY'
      ]
    })
    .threshold('MEDIUM')
    .timeout(15 * 60 * 1000) // 15 minutes
    .run({
      method: 'POST',
      url: `${baseUrl}/graphql`,
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        query: 'mutation { updateUser(data: { bio: "Updated bio" }) { userId, email, name, bio, image } }'
      })
    });

  await runner.clear();
});