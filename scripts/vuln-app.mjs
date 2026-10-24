// Deliberately vulnerable local app for verification scans.
// Serves: .git exposure, .env exposure, exposed admin panel, phpinfo,
// reflected parameter (for dalfox), and missing security headers.
import http from 'node:http'

const body = (html, headers = {}) => ({ html, headers })

const routes = {
  '/': body('<html><body><h1>Welcome</h1><a href="/?q=hello">search</a></body></html>'),
  '/.git/HEAD': body('ref: refs/heads/main\n', { 'content-type': 'text/plain' }),
  '/.git/config': body('[core]\n\trepositoryformatversion = 0\n\tbare = false\n', { 'content-type': 'text/plain' }),
  '/.env': body('APP_ENV=production\nDB_PASSWORD=s3cr3t-p4ss\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n', { 'content-type': 'text/plain' }),
  '/admin': body('<html><body><h2>Admin Console</h2><form><input name="user"><input type="password" name="pass"></form></body></html>'),
  '/phpinfo.php': body('<html><body>phpinfo()\nPHP Version 7.4.3\nSystem Linux\nDOCUMENT_ROOT /var/www/html\n</body></html>'),
  '/server-status': body('Apache Server Status\nTotal accesses: 1234\n', { 'content-type': 'text/plain' }),
  '/backup.sql': body('-- MySQL dump\nINSERT INTO users VALUES (1, \'admin\', \'$1$abc$hashhashhash\');\n', { 'content-type': 'text/plain' }),
  '/robots.txt': body('User-agent: *\nDisallow: /admin\n', { 'content-type': 'text/plain' }),
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1')
  const path = url.pathname

  // Reflected parameter for dalfox: /?q=<payload> echoes back unencoded.
  if (path === '/' && url.searchParams.has('q')) {
    const q = url.searchParams.get('q')
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end(`<html><body><h1>Results for: ${q}</h1></body></html>`)
    return
  }

  const route = routes[path]
  if (route) {
    res.writeHead(200, route.headers)
    res.end(route.html)
    return
  }
  res.writeHead(404, { 'content-type': 'text/html' })
  res.end('<html><body><h1>404 Not Found</h1></body></html>')
})

server.listen(8899, '127.0.0.1', () => console.log('vuln-app on :8899'))
