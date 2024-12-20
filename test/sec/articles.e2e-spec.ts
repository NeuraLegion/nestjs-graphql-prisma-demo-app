import { SecRunner, SecScan } from '@sectester/runner';
import { AttackParamLocation, Severity, TestType } from '@sectester/scan';
import request from 'supertest';
import { INestApplication } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { AppModule } from '../src/app.module';
import { configureApp } from '../src/main';
import { ConfigModule } from '@nestjs/config';
import { ArticlesModule } from '../../src/articles';
import config from '../../src/mikro-orm.config';
import { MikroOrmModule } from '@mikro-orm/nestjs';
import { Server } from 'https';

let app: INestApplication;
let server: any;
let runner: SecRunner;

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
  const moduleFixture: TestingModule = await Test.createTestingModule({
    imports: [AppModule, ConfigModule.forRoot(), ArticlesModule, MikroOrmModule.forRoot(config)]
  }).compile();

  app = moduleFixture.createNestApplication();
  await configureApp(app);
  app.useLogger(false);
  await app.init();

  server = app.getHttpServer();

  runner = new SecRunner({ hostname: 'app.brightsec.com' });
  await runner.init();
});

afterAll(async () => {
  await runner.clear();
  await app.close();
});

describe('Security tests for /api/articles', () => {
  const timeout = 300000;
  jest.setTimeout(timeout);

  describe('Create Article', () => {
    it('should not have SQLi', async () => {
      const token = await authToken();
      await runner
        .createScan({
          tests: [TestType.SQLI],
          attackParamLocations: [AttackParamLocation.BODY]
        })
        .threshold(Severity.HIGH)
        .timeout(timeout)
        .run({
          method: 'POST',
          url: 'http://localhost:3000/api/articles',
          headers: { 'Authorization': `Token ${token}` },
          body: {
            article: {
              title: 'Sample Title',
              description: 'Sample Description',
              body: 'Sample Body',
              tagList: ['tag1', 'tag2']
            }
          }
        });
    });

    it('should not have XSS', async () => {
      const token = await authToken();
      await runner
        .createScan({
          tests: [TestType.XSS],
          attackParamLocations: [AttackParamLocation.BODY]
        })
        .threshold(Severity.MEDIUM)
        .timeout(timeout)
        .run({
          method: 'POST',
          url: 'http://localhost:3000/api/articles',
          headers: { 'Authorization': `Token ${token}` },
          body: {
            article: {
              title: 'Sample Title',
              description: 'Sample Description',
              body: 'Sample Body',
              tagList: ['tag1', 'tag2']
            }
          }
        });
    });
  });

  describe('GET /api/articles', () => {
    it('should not have SQLi', async () => {
      await runner
        .createScan({
          tests: [TestType.SQLI],
          attackParamLocations: [AttackParamLocation.QUERY]
        })
        .threshold(Severity.HIGH)
        .timeout(timeout)
        .run({
          method: 'GET',
          url: 'http://localhost:3000/api/articles',
          query: { args: '{}' }
        });
    });

    it('should not have XSS', async () => {
      await runner
        .createScan({
          tests: [TestType.XSS],
          attackParamLocations: [AttackParamLocation.QUERY]
        })
        .threshold(Severity.HIGH)
        .timeout(timeout)
        .run({
          method: 'GET',
          url: 'http://localhost:3000/api/articles',
          query: { args: '{}' }
        });
    });
  });

  describe('GET /api/articles/example-article', () => {
    it('should not have SQL Injection vulnerability', async () => {
      const scan: SecScan = runner.createScan({ tests: [TestType.SQLI] });
      await scan.run({
        method: 'GET',
        url: 'https://api.example.com/api/articles/example-article',
        headers: { Authorization: `Token ${await authToken()}` },
      });
    });

    it('should not have Cross-Site Scripting (XSS) vulnerability', async () => {
      const scan: SecScan = runner.createScan({ tests: [TestType.XSS] });
      await scan.run({
        method: 'GET',
        url: 'https://api.example.com/api/articles/example-article',
        headers: { Authorization: `Token ${await authToken()}` },
      });
    });

    it('should not have Server-Side Request Forgery (SSRF) vulnerability', async () => {
      const scan: SecScan = runner.createScan({ tests: [TestType.SSRF] });
      await scan.run({
        method: 'GET',
        url: 'https://api.example.com/api/articles/example-article',
        headers: { Authorization: `Token ${await authToken()}` },
      });
    });
  });

  describe('PUT /api/articles/example-article', () => {
    it('should not have SQLi', async () => {
      await runner
        .createScan({
          name: expect.getState().currentTestName,
          tests: [TestType.SQLI],
          attackParamLocations: [AttackParamLocation.BODY]
        })
        .threshold(Severity.MEDIUM)
        .timeout(timeout)
        .run({
          method: 'PUT',
          url: `${baseUrl}/api/articles/example-article`,
          headers: { Authorization: 'Token exampleToken' },
          body: { article: { title: 'Updated Article', description: 'Updated description', body: 'Updated body' } }
        });
    });
  });

  describe('DELETE /api/articles/example-article', () => {
    it('should not have SQLi', async () => {
      await runner
        .createScan({
          tests: [TestType.SQLI],
        })
        .run({
          method: 'DELETE',
          url: 'https://api.example.com/api/articles/example-article',
          headers: { Authorization: authToken },
        });
    });

    it('should not have XSS', async () => {
      await runner
        .createScan({
          tests: [TestType.XSS],
        })
        .run({
          method: 'DELETE',
          url: 'https://api.example.com/api/articles/example-article',
          headers: { Authorization: authToken },
        });
    });

    it('should not have CSRF', async () => {
      await runner
        .createScan({
          tests: [TestType.CSRF],
        })
        .run({
          method: 'DELETE',
          url: 'https://api.example.com/api/articles/example-article',
          headers: { Authorization: authToken },
        });
    });
  });

  describe('POST /example-article/comments', () => {
    it('should not have XSS', async () => {
      await runner
        .createScan({
          name: expect.getState().currentTestName,
          tests: [TestType.XSS],
          attackParamLocations: [AttackParamLocation.BODY]
        })
        .threshold(Severity.MEDIUM)
        .timeout(timeout)
        .run({
          method: 'POST',
          url: `${baseUrl}/api/articles/example-article/comments`,
          headers: { Authorization: 'Token exampleToken' },
          body: { comment: { body: 'Great article!' } }
        });
    });
  });

  describe('GET /example-article/comments', () => {
    it('should not have XSS', async () => {
      await runner
        .createScan({
          name: expect.getState().currentTestName,
          tests: [TestType.XSS],
          attackParamLocations: [AttackParamLocation.QUERY]
        })
        .threshold(Severity.MEDIUM)
        .timeout(timeout)
        .run({
          method: 'GET',
          url: `${baseUrl}/api/articles/example-article/comments`,
          headers: { Authorization: 'Token exampleToken' }
        });
    });
  });

  describe('DELETE /api/articles/example-article/comments/1', () => {
    it('should not have SQLi', async () => {
      await runner
        .createScan({
          tests: [TestType.SQLI],
        })
        .run({
          method: 'DELETE',
          url: 'https://api.example.com/api/articles/example-article/comments/1',
          headers: { Authorization: authToken },
        });
    });

    it('should not have XSS', async () => {
      await runner
        .createScan({
          tests: [TestType.XSS],
        })
        .run({
          method: 'DELETE',
          url: 'https://api.example.com/api/articles/example-article/comments/1',
          headers: { Authorization: authToken },
        });
    });

    it('should not have CSRF', async () => {
      await runner
        .createScan({
          tests: [TestType.CSRF],
        })
        .run({
          method: 'DELETE',
          url: 'https://api.example.com/api/articles/example-article/comments/1',
          headers: { Authorization: authToken },
        });
    });
  });

  describe('POST /example-article/favorite', () => {
    it('should not have XSS', async () => {
      await runner
        .createScan({
          name: expect.getState().currentTestName,
          tests: [TestType.XSS],
          attackParamLocations: [AttackParamLocation.BODY]
        })
        .threshold(Severity.MEDIUM)
        .timeout(timeout)
        .run({
          method: 'POST',
          url: `${baseUrl}/api/articles/example-article/favorite`,
          headers: { Authorization: 'Token exampleToken' },
          body: {}
        });
    });
  });

  describe('DELETE /example-article/favorite', () => {
    it('should not have broken access control', async () => {
      await runner
        .createScan({
          name: expect.getState().currentTestName,
          tests: [TestType.BROKEN_ACCESS_CONTROL],
          attackParamLocations: [AttackParamLocation.HEADER]
        })
        .threshold(Severity.MEDIUM)
        .timeout(timeout)
        .run({
          method: 'DELETE',
          url: `${baseUrl}/api/articles/example-article/favorite`,
          headers: { Authorization: 'Token exampleToken' }
        });
    });
  });

  describe('GET /articles/count', () => {
    it('should not have SQLi', async () => {
      await runner
        .createScan({
          tests: [TestType.SQLI],
          attackParamLocations: [AttackParamLocation.QUERY]
        })
        .threshold(Severity.HIGH)
        .timeout(timeout)
        .run({
          method: 'GET',
          url: 'http://localhost:3000/articles/count',
          query: {
            where: '{}',
            feed: 'false'
          }
        });
    });
  });

  describe('GET /articles/{id}', () => {
    it('should not have SQLi', async () => {
      await runner
        .createScan({
          tests: [TestType.SQLI],
          attackParamLocations: [AttackParamLocation.QUERY]
        })
        .threshold(Severity.HIGH)
        .timeout(timeout)
        .run({
          method: 'GET',
          url: 'http://localhost:3000/api/articles/1',
          query: { where: '{"id": 1}' }
        });
    });
  });

  describe('PUT /articles/{id}', () => {
    it('should not have SQLi', async () => {
      await runner
        .createScan({
          tests: [TestType.SQLI],
          attackParamLocations: [AttackParamLocation.QUERY]
        })
        .threshold(Severity.HIGH)
        .timeout(timeout)
        .run({
          method: 'PUT',
          url: 'http://localhost:3000/articles/1',
          query: {
            data: '{"title": "Updated Title", "description": "Updated Description", "body": "Updated Body", "tagList": ["tag1", "tag2"]}',
            where: '{"id": 1}'
          }
        });
    });

    it('should not have XSS', async () => {
      await runner
        .createScan({
          tests: [TestType.XSS],
          attackParamLocations: [AttackParamLocation.BODY]
        })
        .threshold(Severity.MEDIUM)
        .timeout(timeout)
        .run({
          method: 'PUT',
          url: 'http://localhost:3000/articles/1',
          body: {
            title: 'Updated Title',
            description: 'Updated Description',
            body: 'Updated Body',
            tagList: ['tag1', 'tag2']
          }
        });
    });
  });

  describe('DELETE /articles/{id}', () => {
    it('should not have SQLi', async () => {
      const scan = runner.createScan({
        tests: [TestType.SQLI],
        attackParamLocations: [AttackParamLocation.QUERY]
      });

      await scan.run({
        method: 'DELETE',
        url: 'http://localhost:3000/articles/1',
        query: { where: '{"id": 1}' }
      });
    });
  });

  describe('Articles favoriting security tests', () => {
    it('should not have SQLi', async () => {
      const token = await authToken();
      await runner
        .createScan({
          tests: [TestType.SQLI],
          attackParamLocations: [AttackParamLocation.QUERY]
        })
        .threshold(Severity.HIGH)
        .timeout(timeout)
        .run({
          method: 'POST',
          url: 'http://localhost:3000/api/articles/1/favorite',
          headers: { 'Authorization': `Token ${token}` },
          query: { where: '{"id": 1}', value: 'true' }
        });
    });
  });
});
