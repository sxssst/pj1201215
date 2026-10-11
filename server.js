require('dotenv').config();

const path = require('node:path');
const crypto = require('node:crypto');
const fs = require('node:fs');
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const multer = require('multer');
const db = require('./db');
const routes = require('./routes');

const app = express();
const isProduction = process.env.NODE_ENV === 'production';
const sessionSecret = process.env.SESSION_SECRET;
const publicDirectory = path.join(__dirname, 'public');
const uploadDirectory = path.join(publicDirectory, 'uploads');
fs.mkdirSync(uploadDirectory, { recursive: true });

if (isProduction && (!sessionSecret || sessionSecret.length < 32)) {
  throw new Error('SESSION_SECRET must contain at least 32 characters in production.');
}

app.disable('x-powered-by');
if (process.env.TRUST_PROXY === '1') {
  app.set('trust proxy', 1);
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(helmet());
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(express.static(publicDirectory, {
  dotfiles: 'deny',
  index: false,
  maxAge: isProduction ? '1d' : 0
}));

const acceptedImageTypes = new Set(['image/jpeg', 'image/png', 'image/gif', 'image/webp']);
const imageUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 1, fields: 4 },
  fileFilter: (req, file, callback) => {
    if (!acceptedImageTypes.has(file.mimetype)) {
      const error = new Error('Only JPEG, PNG, GIF, and WebP images are allowed.');
      error.status = 400;
      return callback(error);
    }
    callback(null, true);
  }
});
app.locals.postUpload = imageUpload.single('image');
app.locals.profileImageUpload = imageUpload.single('avatar');
app.locals.uploadDirectory = uploadDirectory;

app.use(session({
  name: 'forum.sid',
  secret: sessionSecret || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'strict',
    secure: isProduction,
    maxAge: 1000 * 60 * 60 * 2
  }
}));

app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;
  next();
});

app.use(routes);
app.use((req, res) => {
  res.status(404).send('ไม่พบหน้าที่ต้องการ');
});
app.use((error, req, res, next) => {
  if (res.headersSent) {
    return next(error);
  }
  const status = error instanceof multer.MulterError ? 400 : Number(error.status) || 500;
  if (status >= 500) {
    console.error(error);
  }
  req.session.flash = {
    type: 'error',
    message: status === 400 ? 'อัปโหลดไม่สำเร็จ กรุณาเลือกภาพที่รองรับและมีขนาดไม่เกิน 5 MB' : 'เกิดข้อผิดพลาด กรุณาลองอีกครั้ง'
  };
  res.redirect(req.path === '/profile' ? '/profile' : '/');
});

const port = Number(process.env.PORT) || 3000;
if (require.main === module) {
  app.listen(port, () => {
    console.log(`Fieldnotes Webboard listening on port ${port}`);
  });
}

module.exports = app;