const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, test } = require('node:test');

const databasePath = path.join(os.tmpdir(), `forum-${process.pid}.sqlite`);
process.env.DB_PATH = databasePath;

const app = require('../server');
const db = require('../db');
const server = app.listen(0);
const baseUrl = `http://127.0.0.1:${server.address().port}`;
const tinyPng = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/WioAAAAASUVORK5CYII=', 'base64');

function cookieFrom(response) {
  return (response.headers.get('set-cookie') || '').split(';')[0];
}

function csrfFrom(html) {
  return html.match(/name="_csrf" value="([^"]+)"/)[1];
}

function post(pathname, cookie, token, fields = {}) {
  return fetch(`${baseUrl}${pathname}`, {
    method: 'POST',
    redirect: 'manual',
    headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ ...fields, ...(token ? { _csrf: token } : {}) })
  });
}

function postImage(pathname, cookie, token, fields) {
  const body = new FormData();
  body.set('_csrf', token);
  body.set('title', fields.title);
  body.set('content', fields.content || '');
  if (fields.image) body.set('image', new Blob([fields.image], { type: 'image/png' }), 'tiny.png');
  return fetch(`${baseUrl}${pathname}`, { method: 'POST', redirect: 'manual', headers: { cookie }, body });
}

function postAvatar(pathname, cookie, token, fields, image) {
  const body = new FormData();
  body.set('_csrf', token);
  body.set('username', fields.username);
  body.set('display_name', fields.displayName);
  body.set('bio', fields.bio || '');
  body.set('avatar', new Blob([image], { type: 'image/png' }), 'avatar.png');
  return fetch(`${baseUrl}${pathname}`, { method: 'POST', redirect: 'manual', headers: { cookie }, body });
}

async function register(username) {
  const response = await fetch(`${baseUrl}/register`);
  const cookie = cookieFrom(response);
  const setCookie = response.headers.get('set-cookie');
  assert.match(setCookie, /HttpOnly/i);
  assert.match(setCookie, /SameSite=Strict/i);
  const token = csrfFrom(await response.text());
  const result = await post('/register', cookie, token, {
    username,
    password: 'assignment-pass-123'
  });
  assert.equal(result.status, 302);
  return cookie;
}

async function login(cookie, username) {
  const response = await fetch(`${baseUrl}/login`, { headers: { cookie } });
  const token = csrfFrom(await response.text());
  const result = await post('/login', cookie, token, {
    username,
    password: 'assignment-pass-123'
  });
  assert.equal(result.status, 302);
  return cookieFrom(result);
}

test('bilingual forum, image uploads, profile, ownership, and admin moderation', async () => {
  assert.ok(db.pragma('table_info(users)').some(column => column.name === 'bio'));
  assert.ok(db.pragma('table_info(users)').some(column => column.name === 'avatar_url'));
  assert.ok(db.pragma('table_info(users)').some(column => column.name === 'display_name'));
  assert.ok(db.pragma('table_info(posts)').some(column => column.name === 'image_url'));
  assert.ok(db.pragma('table_info(comments)').some(column => column.name === 'content'));
  assert.ok(db.pragma('table_info(comments)').some(column => column.name === 'parent_comment_id'));
  assert.equal(db.pragma('table_info(users)').find(column => column.name === 'avatar_url').dflt_value, "'/avatar-placeholder.svg'");

  const adminCookie = await login(await register('admin'), 'admin');
  let response = await fetch(`${baseUrl}/`, { headers: { cookie: adminCookie } });
  let html = await response.text();
  assert.equal(response.status, 200);
  assert.match(html, /<h1>Feed<\/h1>/);
  assert.match(html, /<h2>Create Post<\/h2>/);
  assert.match(html, /placeholder="แชร์ไอเดียหรือเรื่องราวของคุณ/);
  assert.match(html, /ยังไม่มีโพสต์ในขณะนี้/);
  assert.doesNotMatch(html, /Create Post\s*\/\s*สร้างโพสต์/);
  const adminToken = csrfFrom(html);

  assert.equal((await postImage('/posts', adminCookie, adminToken, {
    title: '<script>alert(1)</script>',
    content: 'An image post.',
    image: tinyPng
  })).status, 302);
  const adminPost = db.prepare('SELECT id, image_url FROM posts WHERE user_id = (SELECT id FROM users WHERE username = ?)').get('admin');
  const imagePath = path.join(__dirname, '..', 'public', adminPost.image_url.slice(1));
  assert.equal(fs.existsSync(imagePath), true);

  const studentCookie = await login(await register('student'), 'student');
  response = await fetch(`${baseUrl}/`, { headers: { cookie: studentCookie } });
  html = await response.text();
  const studentToken = csrfFrom(html);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);

  assert.equal((await postImage('/posts', studentCookie, studentToken, {
    title: 'Student post',
    content: 'Owned by student.'
  })).status, 302);
  const studentPost = db.prepare('SELECT id FROM posts WHERE user_id = (SELECT id FROM users WHERE username = ?)').get('student');
  assert.equal((await post(`/posts/${adminPost.id}/delete`, studentCookie, studentToken)).status, 404);
  assert.equal((await post(`/admin/posts/${adminPost.id}/delete`, studentCookie, studentToken)).status, 403);
  assert.equal((await post(`/posts/${adminPost.id}/comments`, studentCookie, studentToken, {
    content: '<script>alert("comment")</script>'
  })).status, 302);
  const parentComment = db.prepare('SELECT id FROM comments WHERE post_id = ?').get(adminPost.id);
  assert.equal((await post(`/posts/${adminPost.id}/comments`, studentCookie, studentToken, {
    content: 'A nested reply',
    parent_comment_id: String(parentComment.id)
  })).status, 302);
  const nestedReply = db.prepare('SELECT parent_comment_id FROM comments WHERE content = ?').get('A nested reply');
  assert.equal(nestedReply.parent_comment_id, parentComment.id);

  assert.equal((await postAvatar('/profile', studentCookie, studentToken, {
    username: 'student2',
    displayName: 'Sam',
    bio: 'Here for good conversations.'
  }, tinyPng)).status, 302);
  const student = db.prepare('SELECT username, display_name, bio, avatar_url FROM users WHERE username = ?').get('student2');
  assert.equal(student.username, 'student2');
  assert.equal(student.display_name, 'Sam');
  assert.equal(student.bio, 'Here for good conversations.');
  const avatarUrl = student.avatar_url;
  const avatarPath = path.join(__dirname, '..', 'public', avatarUrl.slice(1));
  assert.equal(fs.existsSync(avatarPath), true);
  assert.equal((await fetch(`${baseUrl}${avatarUrl}`)).status, 200);
  response = await fetch(`${baseUrl}/profile`, { headers: { cookie: studentCookie } });
  html = await response.text();
  assert.match(html, /<h1>Sam<\/h1>/);
  assert.match(html, /@student2/);
  assert.match(html, /Here for good conversations\./);
  assert.ok(html.includes(`src="${avatarUrl}"`));
  response = await fetch(`${baseUrl}/`, { headers: { cookie: studentCookie } });
  html = await response.text();
  assert.ok(html.includes(`src="${avatarUrl}"`));
  assert.ok(html.includes('&lt;script&gt;alert(&#34;comment&#34;)&lt;/script&gt;'));
  assert.match(html, /class="comment-replies"/);
  assert.match(html, /A nested reply/);
  assert.doesNotMatch(html, /<script>alert\("comment"\)<\/script>/);
  assert.equal((await fetch(`${baseUrl}/admin`, { headers: { cookie: studentCookie } })).status, 403);

  response = await fetch(`${baseUrl}/admin`, { headers: { cookie: adminCookie } });
  html = await response.text();
  assert.equal(response.status, 200);
  assert.match(html, /student2/);
  assert.match(html, /Delete user/);
  assert.match(html, /Delete post/);
  assert.doesNotMatch(html, /Delete post\s*\/\s*ลบโพสต์/);
  const adminPanelToken = csrfFrom(html);
  assert.equal((await post(`/admin/posts/${studentPost.id}/delete`, adminCookie, adminPanelToken)).status, 302);
  assert.equal((await post(`/admin/posts/${adminPost.id}/delete`, adminCookie, adminPanelToken)).status, 302);
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM comments WHERE post_id = ?').get(adminPost.id).count, 0);
  assert.equal(fs.existsSync(imagePath), false);
  const studentId = db.prepare('SELECT id FROM users WHERE username = ?').get('student2').id;
  assert.equal((await post(`/admin/users/${studentId}/delete`, adminCookie, adminPanelToken)).status, 302);
  assert.equal(db.prepare('SELECT id FROM users WHERE username = ?').get('student2'), undefined);
  assert.equal(fs.existsSync(avatarPath), false);
});

after(async () => {
  const images = db.prepare('SELECT image_url FROM posts WHERE image_url IS NOT NULL').all();
  images.forEach(({ image_url }) => {
    const filePath = path.join(__dirname, '..', 'public', image_url.slice(1));
    try { fs.unlinkSync(filePath); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  });
  const avatars = db.prepare("SELECT avatar_url FROM users WHERE avatar_url LIKE '/uploads/%'").all();
  avatars.forEach(({ avatar_url }) => {
    const filePath = path.join(__dirname, '..', 'public', avatar_url.slice(1));
    try { fs.unlinkSync(filePath); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  });
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  db.close();
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(databasePath + suffix); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
});