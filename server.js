'use strict';
const express    = require('express');
const http       = require('http');
const WebSocket  = require('ws');
const Database   = require('better-sqlite3');
const bcrypt     = require('bcryptjs');
const crypto     = require('crypto');
const nodemailer = require('nodemailer');
const path       = require('path');

// ── Database ─────────────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'tp.db'));
db.exec(`
  PRAGMA journal_mode=WAL;
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT UNIQUE NOT NULL,
    nick          TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    avatar        TEXT,
    verified      INTEGER DEFAULT 0,
    created_at    TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS email_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT NOT NULL,
    code       TEXT NOT NULL,
    type       TEXT NOT NULL,
    new_email  TEXT,
    expires_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    token      TEXT UNIQUE NOT NULL,
    remember   INTEGER DEFAULT 0,
    expires_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id   INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    content     TEXT NOT NULL,
    created_at  TEXT DEFAULT (datetime('now'))
  );
`);

// ── Mail ─────────────────────────────────────────────────────────────────────
const mailer = nodemailer.createTransport({
    sendmail: true,
    newline:  'unix',
    path:     '/usr/sbin/sendmail',
});

function sendMail(to, subject, code) {
    return mailer.sendMail({
        from: '"TP" <no-reply@tp.huttrb.ru>',
        to,
        subject,
        html: `
          <div style="font-family:system-ui,sans-serif;max-width:420px;margin:0 auto;padding:36px 24px;background:#09090f;color:#e2e4ef">
            <h2 style="color:#7c6af7;margin:0 0 16px;font-size:22px">TP</h2>
            <p style="color:#888aaa;margin:0 0 24px;font-size:15px">${subject}</p>
            <div style="background:#1e1e35;border:1px solid #7c6af7;border-radius:14px;padding:24px;text-align:center;margin-bottom:20px">
              <span style="font-size:34px;font-weight:900;letter-spacing:10px;color:#9d8ff8">${code}</span>
            </div>
            <p style="color:#636880;font-size:12px;margin:0">Код действителен 15 минут. Не сообщайте его никому.</p>
          </div>`,
    });
}

// ── Helpers ───────────────────────────────────────────────────────────────────
const genCode  = () => String(Math.floor(100000 + Math.random() * 900000));
const genToken = () => crypto.randomBytes(32).toString('hex');

function createSession(userId, remember) {
    const token   = genToken();
    const ms      = remember ? 365 * 24 * 3600e3 : 24 * 3600e3;
    const expires = new Date(Date.now() + ms).toISOString();
    db.prepare('INSERT INTO sessions (user_id,token,remember,expires_at) VALUES(?,?,?,?)')
      .run(userId, token, remember ? 1 : 0, expires);
    return token;
}

function getUserByToken(token) {
    if (!token) return null;
    return db.prepare(`
        SELECT u.id, u.email, u.nick, u.avatar, u.verified
        FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE s.token = ? AND s.expires_at > datetime('now')
    `).get(token) ?? null;
}

// ── Express app ───────────────────────────────────────────────────────────────
const app = express();
app.use(express.json({ limit: '20mb' }));
app.use(express.static(__dirname));

function reqAuth(req, res, next) {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    const u = getUserByToken(token);
    if (!u)          return res.status(401).json({ error: 'Не авторизован' });
    if (!u.verified) return res.status(403).json({ error: 'Email не подтверждён' });
    req.user = u;
    next();
}

// ── Auth routes ───────────────────────────────────────────────────────────────

app.post('/api/auth/register', (req, res) => {
    let { email = '', nick = '', password = '' } = req.body ?? {};
    email = email.trim().toLowerCase();
    nick  = nick.trim().slice(0, 24);

    if (!email || !nick || !password)
        return res.status(400).json({ error: 'Заполните все поля' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
        return res.status(400).json({ error: 'Неверный формат email' });
    if (nick.length < 2)
        return res.status(400).json({ error: 'Ник минимум 2 символа' });
    if (password.length < 6)
        return res.status(400).json({ error: 'Пароль минимум 6 символов' });
    if (db.prepare('SELECT id FROM users WHERE email=?').get(email))
        return res.status(400).json({ error: 'Email уже зарегистрирован' });
    if (db.prepare('SELECT id FROM users WHERE nick=?').get(nick))
        return res.status(400).json({ error: 'Ник уже занят' });

    db.prepare('INSERT INTO users (email,nick,password_hash) VALUES(?,?,?)')
      .run(email, nick, bcrypt.hashSync(password, 10));

    const code    = genCode();
    const expires = new Date(Date.now() + 15 * 60e3).toISOString();
    db.prepare('DELETE FROM email_codes WHERE email=? AND type=?').run(email, 'verify_reg');
    db.prepare('INSERT INTO email_codes (email,code,type,expires_at) VALUES(?,?,?,?)')
      .run(email, code, 'verify_reg', expires);

    sendMail(email, 'Код подтверждения регистрации', code).catch(console.error);
    res.json({ ok: true, email });
});

app.post('/api/auth/verify', (req, res) => {
    const email = req.body?.email?.trim().toLowerCase();
    const code  = req.body?.code?.trim();
    const row = db.prepare(`
        SELECT id FROM email_codes
        WHERE email=? AND code=? AND type='verify_reg' AND expires_at > datetime('now')
    `).get(email, code);
    if (!row) return res.status(400).json({ error: 'Неверный или устаревший код' });
    db.prepare('UPDATE users SET verified=1 WHERE email=?').run(email);
    db.prepare('DELETE FROM email_codes WHERE email=? AND type=?').run(email, 'verify_reg');
    res.json({ ok: true });
});

app.post('/api/auth/login', (req, res) => {
    const email    = req.body?.email?.trim().toLowerCase() ?? '';
    const password = req.body?.password ?? '';
    const remember = !!req.body?.remember;
    const user = db.prepare('SELECT * FROM users WHERE email=?').get(email);
    if (!user || !bcrypt.compareSync(password, user.password_hash))
        return res.status(401).json({ error: 'Неверный email или пароль' });
    if (!user.verified)
        return res.status(403).json({ error: 'Подтвердите email перед входом', needVerify: true, email: user.email });
    const token = createSession(user.id, remember);
    res.json({ ok: true, token, user: { id: user.id, email: user.email, nick: user.nick, avatar: user.avatar } });
});

app.post('/api/auth/logout', reqAuth, (req, res) => {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    db.prepare('DELETE FROM sessions WHERE token=?').run(token);
    res.json({ ok: true });
});

// ── Profile routes ────────────────────────────────────────────────────────────

app.get('/api/me', reqAuth, (req, res) => {
    const { id, email, nick, avatar } = req.user;
    res.json({ id, email, nick, avatar });
});

app.put('/api/me/nick', reqAuth, (req, res) => {
    const nick = req.body?.nick?.trim().slice(0, 24);
    if (!nick || nick.length < 2) return res.status(400).json({ error: 'Ник слишком короткий' });
    if (db.prepare('SELECT id FROM users WHERE nick=? AND id!=?').get(nick, req.user.id))
        return res.status(400).json({ error: 'Ник уже занят' });
    const oldNick = req.user.nick;
    db.prepare('UPDATE users SET nick=? WHERE id=?').run(nick, req.user.id);
    if (wsUsers.has(oldNick)) {
        const ws = wsUsers.get(oldNick);
        ws._nick = nick;
        wsUsers.delete(oldNick);
        wsUsers.set(nick, ws);
    }
    broadcastUserList();
    res.json({ ok: true, nick });
});

app.put('/api/me/avatar', reqAuth, (req, res) => {
    db.prepare('UPDATE users SET avatar=? WHERE id=?').run(req.body?.avatar ?? null, req.user.id);
    broadcastUserList();
    res.json({ ok: true });
});

app.post('/api/me/change-password', reqAuth, (req, res) => {
    const { currentPassword = '', newPassword = '' } = req.body ?? {};
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
    if (!bcrypt.compareSync(currentPassword, user.password_hash))
        return res.status(400).json({ error: 'Неверный текущий пароль' });
    if (newPassword.length < 6)
        return res.status(400).json({ error: 'Новый пароль минимум 6 символов' });
    db.prepare('UPDATE users SET password_hash=? WHERE id=?')
      .run(bcrypt.hashSync(newPassword, 10), req.user.id);
    res.json({ ok: true });
});

app.post('/api/me/request-email-change', reqAuth, (req, res) => {
    const { newEmail = '', password = '' } = req.body ?? {};
    const lo   = newEmail.trim().toLowerCase();
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
    if (!bcrypt.compareSync(password, user.password_hash))
        return res.status(400).json({ error: 'Неверный пароль' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(lo))
        return res.status(400).json({ error: 'Неверный формат email' });
    if (db.prepare('SELECT id FROM users WHERE email=?').get(lo))
        return res.status(400).json({ error: 'Email уже занят' });
    const code    = genCode();
    const expires = new Date(Date.now() + 15 * 60e3).toISOString();
    db.prepare('DELETE FROM email_codes WHERE email=? AND type=?').run(user.email, 'change_email');
    db.prepare('INSERT INTO email_codes (email,code,type,new_email,expires_at) VALUES(?,?,?,?,?)')
      .run(user.email, code, 'change_email', lo, expires);
    sendMail(lo, 'Подтверждение смены email', code).catch(console.error);
    res.json({ ok: true });
});

app.post('/api/me/verify-email-change', reqAuth, (req, res) => {
    const code = req.body?.code?.trim();
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
    const row  = db.prepare(`
        SELECT new_email FROM email_codes
        WHERE email=? AND code=? AND type='change_email' AND expires_at > datetime('now')
    `).get(user.email, code);
    if (!row) return res.status(400).json({ error: 'Неверный или устаревший код' });
    db.prepare('UPDATE users SET email=? WHERE id=?').run(row.new_email, req.user.id);
    db.prepare('DELETE FROM email_codes WHERE email=? AND type=?').run(user.email, 'change_email');
    res.json({ ok: true, newEmail: row.new_email });
});

// ── Users & messages ──────────────────────────────────────────────────────────

app.get('/api/users', reqAuth, (req, res) => {
    const list = db.prepare(
        'SELECT id, nick, avatar FROM users WHERE id != ? AND verified = 1 ORDER BY nick ASC'
    ).all(req.user.id);
    res.json(list.map(u => ({ ...u, online: wsUsers.has(u.nick) })));
});

app.get('/api/messages/:userId', reqAuth, (req, res) => {
    const other = parseInt(req.params.userId) || 0;
    const rows  = db.prepare(`
        SELECT m.id, m.sender_id, m.receiver_id, m.kind, m.content, m.created_at,
               u.nick AS from_nick
        FROM messages m JOIN users u ON u.id = m.sender_id
        WHERE (m.sender_id = ? AND m.receiver_id = ?)
           OR (m.sender_id = ? AND m.receiver_id = ?)
        ORDER BY m.created_at ASC LIMIT 500
    `).all(req.user.id, other, other, req.user.id);
    res.json(rows.map(m => {
        try { return { ...m, content: JSON.parse(m.content) }; }
        catch { return { ...m, content: {} }; }
    }));
});

// ── WebSocket ─────────────────────────────────────────────────────────────────
const server  = http.createServer(app);
const wss     = new WebSocket.Server({ server });
const wsUsers = new Map(); // nick → ws

const heartbeat = setInterval(() => {
    for (const ws of wss.clients) {
        if (!ws.isAlive) { ws.terminate(); continue; }
        ws.isAlive = false;
        ws.ping();
    }
}, 20000);
wss.on('close', () => clearInterval(heartbeat));

function wsSend(ws, obj)     { if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj)); }
function wsSendTo(nick, obj) { wsSend(wsUsers.get(nick), obj); }

function broadcastUserList() {
    for (const [, ws] of wsUsers) {
        const list = db.prepare(
            'SELECT id, nick, avatar FROM users WHERE id != ? AND verified = 1 ORDER BY nick ASC'
        ).all(ws._userId);
        wsSend(ws, { type: 'user-list', users: list.map(u => ({ ...u, online: wsUsers.has(u.nick) })) });
    }
}

wss.on('connection', ws => {
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });
    let user = null;

    ws.on('message', raw => {
        let msg;
        try { msg = JSON.parse(raw); } catch { return; }

        if (msg.type === 'auth') {
            const u = getUserByToken(msg.token);
            if (!u || !u.verified) { wsSend(ws, { type: 'auth-error', error: 'Не авторизован' }); return; }
            user       = u;
            ws._userId = u.id;
            ws._nick   = u.nick;
            wsUsers.set(u.nick, ws);
            wsSend(ws, { type: 'auth-ok', user: { id: u.id, nick: u.nick, email: u.email, avatar: u.avatar } });
            broadcastUserList();
            return;
        }

        if (!user) return;

        switch (msg.type) {
            case 'chat': {
                const receiver = db.prepare('SELECT id FROM users WHERE nick=?').get(msg.target);
                if (receiver) {
                    const content = JSON.stringify({
                        id:        msg.id        || null,
                        kind:      msg.kind      || 'text',
                        text:      msg.text      || null,
                        fileName:  msg.fileName  || null,
                        fileSize:  msg.fileSize  || null,
                        mime:      msg.mime      || null,
                        data:      msg.data      || null,
                        timestamp: msg.timestamp || new Date().toISOString(),
                    });
                    db.prepare('INSERT INTO messages (sender_id,receiver_id,kind,content) VALUES(?,?,?,?)')
                      .run(user.id, receiver.id, msg.kind || 'text', content);
                }
                wsSendTo(msg.target, { ...msg, from: user.nick });
                break;
            }
            case 'typing':
                wsSendTo(msg.target, { type: 'typing', from: user.nick });
                break;
            default:
                if (msg.target) wsSendTo(msg.target, { ...msg, from: user.nick });
        }
    });

    ws.on('close', () => {
        if (user && wsUsers.get(user.nick) === ws) {
            wsUsers.delete(user.nick);
            broadcastUserList();
        }
    });

    ws.on('error', err => console.error('WS error:', err.message));
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => console.log(`TP server on :${PORT}`));
