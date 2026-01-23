const http = require('http');

function post(path, data) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(data);
    const options = {
      hostname: 'localhost',
      port: 3001,
      path,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      },
      timeout: 5000
    };

    const req = http.request(options, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => body += chunk);
      res.on('end', () => {
        try {
          resolve({ statusCode: res.statusCode, body: JSON.parse(body) });
        } catch (e) {
          resolve({ statusCode: res.statusCode, body: body });
        }
      });
    });

    req.on('error', (err) => reject(err));
    req.on('timeout', () => { req.destroy(new Error('timeout')); });
    req.write(payload);
    req.end();
  });
}

(async () => {
  try {
    const reg = await post('/api/auth/register', { username: 'testuser_ci', email: 'testuser_ci@example.com', password: 'secret123', fullName: 'CI Tester' });
  } catch (e) {
    console.error('Register error:', e.message || e);
  }

  try {
    const login = await post('/api/auth/login', { username: 'testuser_ci', password: 'secret123' });
  } catch (e) {
    console.error('Login error:', e.message || e);
  }

  try {
    const contact = await post('/api/public/contact', { name: 'CI Tester', email: 'ci-tester@example.com', message: 'Automated contact test from script.', subject: 'CI Test' });
  } catch (e) {
    console.error('Contact error:', e.message || e);
  }

  process.exit(0);
})();
