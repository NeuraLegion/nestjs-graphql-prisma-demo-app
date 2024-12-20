import { SecRunner, SecScan } from '@sectester/runner';
import { AttackParamLocation, Severity, TestType } from '@sectester/scan';
import { INestApplication } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { configureApp } from '../src/main';

let app: INestApplication;
let server: any;
let runner: SecRunner;

const authToken = async () => {
  const credentials = { email: 'root@conduit.com', password: '123' };
  const response = await request(server)
    .post('/api/users/login')
    .set('Content-Type', 'application/json')
    .send({ user: credentials })
    .then(response => response.body);
  return response.data.user.token;
};

beforeAll(async () => {
  const moduleFixture: TestingModule = await Test.createTestingModule({
    imports: [AppModule],
  }).compile();

  app = moduleFixture.createNestApplication();
  await configureApp(app);
  app.useLogger(false);

  server = app.getHttpServer();
  await app.init();

  runner = new SecRunner({ hostname: 'app.brightsec.com' });
  await runner.init();
});

afterAll(async () => {
  await runner.clear();
  await app.close();
});

describe('GraphQL Comment Operations', () => {
  it('should not have SQLi in createComment', async () => {
    const token = await authToken();
    const scan = runner.createScan({
      tests: [TestType.SQLI],
      attackParamLocations: [AttackParamLocation.BODY]
    });

    await scan.run({
      method: 'POST',
      url: '/graphql',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: {
        query: 'mutation createComment($data: CreateCommentInput!, $where: ArticleWhereUniqueInput!) { createComment(data: $data, where: $where) { id content createdAt updatedAt author { id username } } }',
        variables: {
          data: { body: 'This is a comment.' },
          where: { id: 'example-article-id' }
        }
      }
    });
  });

  it('should not have XSS in createComment', async () => {
    const token = await authToken();
    const scan = runner.createScan({
      tests: [TestType.XSS],
      attackParamLocations: [AttackParamLocation.BODY]
    });

    await scan.run({
      method: 'POST',
      url: '/graphql',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: {
        query: 'mutation createComment($data: CreateCommentInput!, $where: ArticleWhereUniqueInput!) { createComment(data: $data, where: $where) { id content createdAt updatedAt author { id username } } }',
        variables: {
          data: { body: 'This is a comment.' },
          where: { id: 'example-article-id' }
        }
      }
    });
  });

  it('should not have SQLi in deleteComment', async () => {
    const token = await authToken();
    const scan = runner.createScan({ tests: [TestType.SQLI] });

    await scan.run({
      method: 'POST',
      url: 'http://localhost:3000/graphql',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
      body: {
        query: 'mutation deleteComment($where: CommentWhereUniqueInput!) { deleteComment(where: $where) { id content createdAt updatedAt author { id username } } }',
        variables: { where: { id: 'example-comment-id' } }
      }
    });
  });
});
