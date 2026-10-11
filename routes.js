const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('./db');

const router = express.Router();
const authLimiter = require('express-rate-limit').rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: 'พยายามเข้าสู่ระบบหลายครั้งเกินไป กรุณาลองใหม่ภายหลัง'
});

function requireAuth(req, res, next) {
  const sessionUser = req.session.user;
  if (!sessionUser) {
    req.session.flash = { type: 'error', message: 'กรุณาเข้าสู่ระบบก่อนดำเนินการต่อ' };
    return res.redirect('/login');
  }

  const user = db.prepare('SELECT id, username, role, bio, avatar_url, display_name FROM users WHERE id = ?')
    .get(sessionUser.id);
  if (!user) {
    delete req.session.user;
    req.session.flash = { type: 'error', message: 'ไม่พบบัญชีผู้ใช้นี้แล้ว' };
    return res.redirect('/login');
  }
  req.session.user = user;
  res.locals.currentUser = user;
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) {
    req.session.flash = { type: 'error', message: 'กรุณาเข้าสู่ระบบก่อนดำเนินการต่อ' };
    return res.redirect('/login');
  }
  if (req.session.user.role !== 'admin') {
    return res.status(403).send('คุณไม่มีสิทธิ์เข้าถึงหน้านี้');
  }
  next();
}

function asyncHandler(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

function requireCsrf(req, res, next) {
  if (!validCsrfToken(req.session.csrfToken, req.body && req.body._csrf)) {
    return res.status(403).send('แบบฟอร์มหมดอายุหรือไม่ถูกต้อง กรุณาโหลดหน้าใหม่แล้วลองอีกครั้ง');
  }
  next();
}

function validCsrfToken(expected, actual) {
  if (typeof actual !== 'string') {
    return false;
  }
  const expectedBytes = Buffer.from(expected);
  const actualBytes = Buffer.from(actual);
  return actualBytes.length === expectedBytes.length && crypto.timingSafeEqual(expectedBytes, actualBytes);
}

router.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  res.locals.csrfToken = req.session.csrfToken;
  if (req.method !== 'POST') {
    return next();
  }
  if (req.is('multipart/form-data')) {
    if (req.path !== '/posts' && req.path !== '/profile') {
      return res.status(415).send('ไม่รองรับการส่งไฟล์ในแบบฟอร์มนี้');
    }
    return next();
  }
  if (!validCsrfToken(req.session.csrfToken, req.body && req.body._csrf)) {
    return res.status(403).send('แบบฟอร์มหมดอายุหรือไม่ถูกต้อง กรุณาโหลดหน้าใหม่แล้วลองอีกครั้ง');
  }
  next();
});

function imageExtension(buffer) {
  if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return 'jpg';
  if (buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'png';
  if (buffer.subarray(0, 3).toString() === 'GIF') return 'gif';
  if (buffer.length >= 12 && buffer.subarray(0, 4).toString() === 'RIFF' && buffer.subarray(8, 12).toString() === 'WEBP') return 'webp';
  return null;
}

function removeUploadedImage(imageUrl) {
  if (typeof imageUrl !== 'string' || !/^\/uploads\/[a-f0-9-]+\.(jpg|png|gif|webp)$/i.test(imageUrl)) {
    return;
  }
  const filePath = path.join(__dirname, 'public', imageUrl.slice(1));
  try {
    fs.unlinkSync(filePath);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

function storeUploadedImage(req, file) {
  const extension = imageExtension(file.buffer);
  const expectedExtensions = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/gif': 'gif', 'image/webp': 'webp' };
  if (!extension || extension !== expectedExtensions[file.mimetype]) {
    const error = new Error('Invalid image file.');
    error.status = 400;
    throw error;
  }
  const imageUrl = `/uploads/${crypto.randomUUID()}.${extension}`;
  fs.writeFileSync(path.join(req.app.locals.uploadDirectory, path.basename(imageUrl)), file.buffer, { flag: 'wx' });
  return imageUrl;
}

router.get(['/', '/feed'], (req, res) => {
  const posts = db.prepare(`
    SELECT posts.id, posts.user_id, posts.title, posts.content, posts.image_url,
      posts.created_at, users.username, users.display_name, users.avatar_url
    FROM posts
    JOIN users ON users.id = posts.user_id
    ORDER BY posts.created_at DESC, posts.id DESC
  `).all();
  const comments = db.prepare(`
    SELECT comments.id, comments.post_id, comments.user_id, comments.content, comments.created_at,
      users.username, users.display_name, users.avatar_url
    FROM comments
    JOIN users ON users.id = comments.user_id
    ORDER BY comments.created_at, comments.id
  `).all();
  const commentsByPost = Object.create(null);
  for (const comment of comments) {
    (commentsByPost[comment.post_id] ||= []).push(comment);
  }
  res.render('feed', { posts, commentsByPost });
});

router.get('/register', (req, res) => {
  res.render('register', { error: null });
});

router.post('/register', authLimiter, asyncHandler(async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (!/^[a-z0-9_.-]{3,32}$/.test(username)) {
    return res.status(400).render('register', {
      error: 'ชื่อผู้ใช้ต้องมีความยาว 3–32 ตัวอักษร และใช้ได้เฉพาะ a-z ตัวเลข จุด ขีดล่าง หรือขีดกลาง'
    });
  }
  if (Buffer.byteLength(password, 'utf8') < 10 || Buffer.byteLength(password, 'utf8') > 72) {
    return res.status(400).render('register', {
      error: 'รหัสผ่านต้องมีความยาว 10–72 ไบต์'
    });
  }

  const hash = await bcrypt.hash(password, 12);
  const role = username === 'admin' ? 'admin' : 'user';
  try {
    db.prepare('INSERT INTO users (username, password, role, bio) VALUES (?, ?, ?, ?)')
      .run(username, hash, role, '');
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).render('register', { error: 'ชื่อผู้ใช้นี้ถูกใช้แล้ว' });
    }
    throw error;
  }

  req.session.flash = { type: 'success', message: 'สร้างบัญชีเรียบร้อยแล้ว กรุณาเข้าสู่ระบบ' };
  res.redirect('/login');
}));

router.get('/login', (req, res) => {
  res.render('login', { error: null });
});

router.post('/login', authLimiter, asyncHandler(async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = db.prepare('SELECT id, username, password, role, avatar_url, display_name FROM users WHERE username = ?')
    .get(username);

  if (Buffer.byteLength(password, 'utf8') > 72 || !user || !await bcrypt.compare(password, user.password)) {
    return res.status(401).render('login', { error: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
  }

  await new Promise((resolve, reject) => {
    req.session.regenerate(error => error ? reject(error) : resolve());
  });
  req.session.user = { id: user.id, username: user.username, role: user.role, avatar_url: user.avatar_url, display_name: user.display_name };
  req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  req.session.flash = { type: 'success', message: `ยินดีต้อนรับกลับมา ${user.username}` };
  res.redirect('/');
}));

router.post('/logout', requireAuth, (req, res, next) => {
  req.session.destroy(error => {
    if (error) {
      return next(error);
    }
    res.clearCookie('forum.sid', {
      httpOnly: true,
      sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production',
      path: '/'
    });
    res.redirect('/login');
  });
});

router.post('/posts', requireAuth, (req, res, next) => req.app.locals.postUpload(req, res, next), requireCsrf, (req, res, next) => {
  const title = String(req.body.title || '').trim();
  const content = String(req.body.content || '').trim();
  if (!title || title.length > 160 || content.length > 10000) {
    req.session.flash = { type: 'error', message: 'กรุณาระบุหัวข้อไม่เกิน 160 ตัวอักษร และเนื้อหาไม่เกิน 10,000 ตัวอักษร' };
    return res.redirect('/');
  }

  let imageUrl = null;
  if (req.file) {
    imageUrl = storeUploadedImage(req, req.file);
  }

  try {
    db.prepare('INSERT INTO posts (user_id, title, content, image_url) VALUES (?, ?, ?, ?)')
      .run(req.session.user.id, title, content, imageUrl);
  } catch (error) {
    if (imageUrl) removeUploadedImage(imageUrl);
    return next(error);
  }
  req.session.flash = { type: 'success', message: 'เผยแพร่โพสต์เรียบร้อยแล้ว' };
  res.redirect('/');
});

router.post('/posts/:id/delete', requireAuth, (req, res) => {
  const postId = Number(req.params.id);
  if (!Number.isSafeInteger(postId) || postId < 1) return res.status(404).send('ไม่พบโพสต์ที่ต้องการ');
  const post = db.prepare('SELECT image_url FROM posts WHERE id = ? AND user_id = ?')
    .get(postId, req.session.user.id);
  if (!post) return res.status(404).send('ไม่พบโพสต์ที่ต้องการ');
  db.prepare('DELETE FROM posts WHERE id = ? AND user_id = ?').run(postId, req.session.user.id);
  removeUploadedImage(post.image_url);
  req.session.flash = { type: 'success', message: 'ลบโพสต์เรียบร้อยแล้ว' };
  res.redirect('/');
});

router.post('/posts/:id/comments', requireAuth, (req, res) => {
  const postId = Number(req.params.id);
  const content = String(req.body.content || '').trim();
  if (!Number.isSafeInteger(postId) || postId < 1) return res.status(404).send('ไม่พบโพสต์ที่ต้องการ');
  if (!db.prepare('SELECT id FROM posts WHERE id = ?').get(postId)) {
    return res.status(404).send('ไม่พบโพสต์ที่ต้องการ');
  }
  if (!content || content.length > 2000) {
    req.session.flash = { type: 'error', message: 'กรุณาเขียนความคิดเห็นไม่เกิน 2,000 ตัวอักษร' };
    return res.redirect(`/#comments-${postId}`);
  }
  db.prepare('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)')
    .run(postId, req.session.user.id, content);
  req.session.flash = { type: 'success', message: 'เพิ่มความคิดเห็นแล้ว' };
  res.redirect(`/#comments-${postId}`);
});

router.get('/profile', requireAuth, (req, res) => {
  const posts = db.prepare(`
    SELECT id, title, content, image_url, created_at
    FROM posts WHERE user_id = ? ORDER BY created_at DESC, id DESC
  `).all(req.session.user.id);
  res.render('profile', { profile: req.session.user, posts });
});

router.post('/profile', requireAuth, (req, res, next) => req.app.locals.profileImageUpload(req, res, next), requireCsrf, (req, res, next) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const displayName = String(req.body.display_name || '').trim();
  if (!/^[a-z0-9_.-]{3,32}$/.test(username)) {
    req.session.flash = { type: 'error', message: 'ชื่อผู้ใช้ต้องมีความยาว 3–32 ตัวอักษร และใช้ได้เฉพาะ a-z ตัวเลข จุด ขีดล่าง หรือขีดกลาง' };
    return res.redirect('/profile');
  }
  if (!displayName || displayName.length > 50) {
    req.session.flash = { type: 'error', message: 'กรุณากรอกชื่อเล่นไม่เกิน 50 ตัวอักษร' };
    return res.redirect('/profile');
  }
  const duplicate = db.prepare('SELECT id FROM users WHERE username = ? AND id != ?')
    .get(username, req.session.user.id);
  if (duplicate) {
    req.session.flash = { type: 'error', message: 'ชื่อผู้ใช้นี้มีคนใช้แล้ว' };
    return res.redirect('/profile');
  }

  let avatarUrl = req.session.user.avatar_url;
  if (req.file) {
    try {
      avatarUrl = storeUploadedImage(req, req.file);
    } catch (error) {
      return next(error);
    }
  }

  try {
    db.prepare('UPDATE users SET username = ?, display_name = ?, avatar_url = ? WHERE id = ?')
      .run(username, displayName, avatarUrl, req.session.user.id);
  } catch (error) {
    if (req.file) removeUploadedImage(avatarUrl);
    return next(error);
  }
  if (req.file) removeUploadedImage(req.session.user.avatar_url);
  req.session.user.username = username;
  req.session.user.display_name = displayName;
  req.session.user.avatar_url = avatarUrl;
  req.session.flash = { type: 'success', message: 'อัปเดตโปรไฟล์เรียบร้อยแล้ว' };
  res.redirect('/profile');
});

router.get('/admin', requireAuth, requireAdmin, (req, res) => {
  const users = db.prepare('SELECT id, username, display_name, role, bio FROM users ORDER BY id').all();
  const posts = db.prepare(`
    SELECT posts.id, posts.title, posts.content, posts.image_url, posts.created_at,
      posts.user_id, users.username
    FROM posts JOIN users ON users.id = posts.user_id
    ORDER BY posts.created_at DESC, posts.id DESC
  `).all();
  res.render('admin', { users, posts });
});

router.post('/admin/posts/:id/delete', requireAuth, requireAdmin, (req, res) => {
  const postId = Number(req.params.id);
  if (!Number.isSafeInteger(postId) || postId < 1) return res.status(404).send('ไม่พบโพสต์ที่ต้องการ');
  const post = db.prepare('SELECT image_url FROM posts WHERE id = ?').get(postId);
  if (!post) return res.status(404).send('ไม่พบโพสต์ที่ต้องการ');
  db.prepare('DELETE FROM posts WHERE id = ?').run(postId);
  removeUploadedImage(post.image_url);
  req.session.flash = { type: 'success', message: 'ลบโพสต์เรียบร้อยแล้ว' };
  res.redirect('/admin');
});

router.post('/admin/users/:id/delete', requireAuth, requireAdmin, (req, res) => {
  const userId = Number(req.params.id);
  if (!Number.isSafeInteger(userId) || userId < 1) return res.status(404).send('ไม่พบผู้ใช้ที่ต้องการ');
  const user = db.prepare('SELECT avatar_url FROM users WHERE id = ?').get(userId);
  if (!user) return res.status(404).send('ไม่พบผู้ใช้ที่ต้องการ');
  const images = db.prepare('SELECT image_url FROM posts WHERE user_id = ?').all(userId);
  const result = db.prepare('DELETE FROM users WHERE id = ?').run(userId);
  if (result.changes === 0) return res.status(404).send('ไม่พบผู้ใช้ที่ต้องการ');
  images.forEach(post => removeUploadedImage(post.image_url));
  removeUploadedImage(user.avatar_url);
  req.session.flash = { type: 'success', message: 'ลบผู้ใช้เรียบร้อยแล้ว' };
  res.redirect('/admin');
});

module.exports = router;
module.exports.requireAuth = requireAuth;
module.exports.requireAdmin = requireAdmin;