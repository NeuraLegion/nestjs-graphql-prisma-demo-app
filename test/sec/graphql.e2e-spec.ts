import { SecRunner, SecScan } from '@sectester/runner';
import { AttackParamLocation, Severity, TestType } from '@sectester/scan';
import request from 'supertest';
import { INestApplication } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { AppModule } from '../src/app.module';
import { configureApp, createApp } from '../src/main';
import { GraphQLClient } from 'graphql-request';
import { createSpyObj } from 'jest-createspyobj';
import { Await } from '../src/types';

let app: Await<ReturnType<typeof createApp>>;
let server: any;
let runner: SecRunner;
let graphQLClient: jest.Mocked<GraphQLClient>;

const authToken = (() => {
  let token: string;
  return async () => {
    if (token === undefined) {
      const credentials = { email: 'root@conduit.com', password: '123' };
      const response = await request(server)
        .post('/api/users/login')
        .set('Content-Type', 'application/json')
        .send({ user: credentials })
        .then(response => response.body);
      token = response.data.user.token;
    }
    return token;
  };
})();

beforeAll(async () => {
  graphQLClient = createSpyObj(GraphQLClient);
  const testingModule = await Test.createTestingModule({
    imports: [AppModule],
  })
    .overrideProvider('GraphQLClient')
    .useValue(graphQLClient)
    .compile();
  app = testingModule.createNestApplication();
  await configureApp(app);
  app.useLogger(false);

  graphQLClient = app.get('GraphQLClient');
  graphQLClient.request.mockImplementation(async function (query, variables) {
    const [headerName, headerValue] = this._header ? this._header : [];
    return await request(server)
      .post('/graphql')
      .set('Content-Type', 'application/json')
      .set(
        headerName
          ? {
              [headerName]: headerValue,
            }
          : {},
      )
      .send({ query, variables })
      .then(response => response.body);
  });
  graphQLClient.setHeader.mockImplementation(function (name, value) {
    this._header = [name, value];
    return this;
  });

  server = app.getHttpServer();
  await app.init();

  runner = new SecRunner({ hostname: 'app.brightsec.com' });
  await runner.init();
});

afterAll(async () => {
  await runner.clear();
  await app.close();
});

describe('GraphQL API Security Tests', () => {
  const timeout = 300000;
  jest.setTimeout(timeout);

  describe('Queries', () => {
    it('should not have SQLi in articleComments query', async () => {
      const scan = runner.createScan({
        tests: [TestType.SQLI],
        attackParamLocations: [AttackParamLocation.BODY]
      });

      await scan.run({
        method: 'POST',
        url: 'http://localhost:3000/graphql',
        headers: { 'Content-Type': 'application/json' },
        body: {
          query: 'query articleComments($where: ArticleWhereUniqueInput!) { articleComments(where: $where) { id content createdAt updatedAt author { id username } } }',
          variables: { where: { id: 'example-article-id' } }
        }
      });
    });

    it('should not have GraphQL Introspection enabled', async () => {
      const scan = runner.createScan({ tests: [TestType.GRAPHQL_INTROSPECTION] });
      await scan.run({
        method: 'POST',
        url: 'http://localhost:3000/graphql',
        headers: { 'Content-Type': 'application/json' },
        body: { query: '{ __schema { types { name } } }' }
      });
    });

    it('should not have SQL Injection vulnerability', async () => {
      const scan = runner.createScan({ tests: [TestType.SQLI] });
      await scan.run({
        method: 'POST',
        url: 'http://localhost:3000/graphql',
        headers: { 'Content-Type': 'application/json' },
        body: { query: 'query { me { userId, ... } }' }
      });
    });

    it('should not have Cross-Site Scripting (XSS) vulnerability', async () => {
      const scan = runner.createScan({ tests: [TestType.XSS] });
      await scan.run({
        method: 'POST',
        url: 'http://localhost:3000/graphql',
        headers: { 'Content-Type': 'application/json' },
        body: { query: 'query { user(where: { userId: "<script>alert(1)</script>" }) { userId, ... } }' }
      });
    });
  });

  describe('Mutations', () => {
    it('should not have SQL Injection vulnerability', async () => {
      const scan: SecScan = runner.createScan({
        tests: [TestType.SQLI],
      });

      await scan.run({
        method: 'POST',
        url: 'http://localhost:3000/graphql',
        headers: { 'Content-Type': 'application/json' },
        body: { query: 'mutation { createUser(data: { ... }) { userId, ... } }' },
      });
    });

    it('should not have Cross-Site Scripting (XSS) vulnerability', async () => {
      const scan: SecScan = runner.createScan({
        tests: [TestType.XSS],
      });

      await scan.run({
        method: 'POST',
        url: 'http://localhost:3000/graphql',
        headers: { 'Content-Type': 'application/json' },
        body: { query: 'mutation { createUser(data: { ... }) { userId, ... } }' },
      });
    });

    it('should not have Cross-Site Request Forgery (CSRF) vulnerability', async () => {
      const scan: SecScan = runner.createScan({
        tests: [TestType.CSRF],
      });

      await scan.run({
        method: 'POST',
        url: 'http://localhost:3000/graphql',
        headers: { 'Content-Type': 'application/json' },
        body: { query: 'mutation { createUser(data: { ... }) { userId, ... } }' },
      });
    });

    it('should not have SQL Injection vulnerability in updateUser', async () => {
      const scan = runner.createScan({
        tests: [TestType.SQLI],
      });

      await scan.run({
        method: 'POST',
        url: 'http://localhost:3000/graphql',
        headers: { 'Content-Type': 'application/json' },
        body: { query: 'mutation { updateUser(data: { ... }) { userId, ... } }' },
      });
    });

    it('should not have Cross-Site Scripting (XSS) vulnerability in updateUser', async () => {
      const scan = runner.createScan({
        tests: [TestType.XSS],
      });

      await scan.run({
        method: 'POST',
        url: 'http://localhost:3000/graphql',
        headers: { 'Content-Type': 'application/json' },
        body: { query: 'mutation { updateUser(data: { ... }) { userId, ... } }' },
      });
    });

    it('should not have Cross-Site Request Forgery (CSRF) vulnerability in updateUser', async () => {
      const scan = runner.createScan({
        tests: [TestType.CSRF],
      });

      await scan.run({
        method: 'POST',
        url: 'http://localhost:3000/graphql',
        headers: { 'Content-Type': 'application/json' },
        body: { query: 'mutation { updateUser(data: { ... }) { userId, ... } }' },
      });
    });

    it('should not have SQL Injection vulnerability in follow mutation', async () => {
      const scan = runner.createScan({ tests: [TestType.SQLI] });
      await scan.run({
        method: 'POST',
        url: 'http://localhost:3000/graphql',
        headers: { 'Content-Type': 'application/json' },
        body: { query: 'mutation { follow(where: { userId: "example-id" }, value: true) { userId, ... } }' }
      });
    });

    it('should not have Cross-Site Scripting (XSS) vulnerability in follow mutation', async () => {
      const scan = runner.createScan({ tests: [TestType.XSS] });
      await scan.run({
        method: 'POST',
        url: 'http://localhost:3000/graphql',
        headers: { 'Content-Type': 'application/json' },
        body: { query: 'mutation { follow(where: { userId: "example-id" }, value: true) { userId, ... } }' }
      });
    });
  });

  describe('Subscriptions', () => {
    it('should not have SQLi', async () => {
      const scan = runner.createScan({
        tests: [TestType.SQLI],
      });

      await scan.run({
        method: 'POST',
        url: 'http://localhost:3000/graphql',
        headers: { 'Content-Type': 'application/json' },
        body: { query: 'subscription commentAdded { commentAdded { id content createdAt updatedAt author { id username } } }' },
      });
    });

    it('should not have XSS', async () => {
      const scan = runner.createScan({
        tests: [TestType.XSS],
      });

      await scan.run({
        method: 'POST',
        url: 'http://localhost:3000/graphql',
        headers: { 'Content-Type': 'application/json' },
        body: { query: 'subscription commentAdded { commentAdded { id content createdAt updatedAt author { id username } } }' },
      });
    });
  });

  describe('Login Mutation', () => {
    it('should not have SQLi', async () => {
      const scan = runner.createScan({
        tests: [TestType.SQLI]
      });

      await scan.run({
        method: 'POST',
        url: 'http://localhost:3000/graphql',
        headers: { 'Content-Type': 'application/json' },
        body: { query: 'mutation { loginUser(data: { email: "test@test.com", password: "password" }) { userId, token } }' }
      });
    });

    it('should not have XSS', async () => {
      const scan = runner.createScan({
        tests: [TestType.XSS]
      });

      await scan.run({
        method: 'POST',
        url: 'http://localhost:3000/graphql',
        headers: { 'Content-Type': 'application/json' },
        body: { query: 'mutation { loginUser(data: { email: "<script>alert(1)</script>", password: "password" }) { userId, token } }' }
      });
    });
  });
});
