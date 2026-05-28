'use strict';
const express    = require('express');
const http       = require('http');
const WebSocket  = require('ws');
const { Pool }   = require('pg');
const bcrypt     = require('bcryptjs');
const crypto     = require('crypto');
const path = require('path');

// ── Database ──────────────────────────────────────────────────────────────────
const pool = new Pool({
    host:     process.env.DB_HOST,
    port:     parseInt(process.env.DB_PORT) || 5432,
    database: process.env.DB_NAME,
    user:     process.env.DB_USER,
    password: process.env.DB_PASS,
    ssl:      false,
});

const q = (sql, params) => pool.query(sql, params);

async function initDB() {
    await q(`CREATE TABLE IF NOT EXISTS users (
        id            SERIAL PRIMARY KEY,
        email         TEXT UNIQUE NOT NULL,
        nick          TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        avatar        TEXT,
        verified      INTEGER DEFAULT 0,
        created_at    TIMESTAMP DEFAULT NOW()
    )`);
    await q(`CREATE TABLE IF NOT EXISTS email_codes (
        id         SERIAL PRIMARY KEY,
        email      TEXT NOT NULL,
        code       TEXT NOT NULL,
        type       TEXT NOT NULL,
        new_email  TEXT,
        expires_at TIMESTAMP NOT NULL
    )`);
    await q(`CREATE TABLE IF NOT EXISTS sessions (
        id         SERIAL PRIMARY KEY,
        user_id    INTEGER NOT NULL,
        token      TEXT UNIQUE NOT NULL,
        remember   INTEGER DEFAULT 0,
        expires_at TIMESTAMP NOT NULL
    )`);
    await q(`CREATE TABLE IF NOT EXISTS messages (
        id          SERIAL PRIMARY KEY,
        sender_id   INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        kind        TEXT NOT NULL,
        content     TEXT NOT NULL,
        created_at  TIMESTAMP DEFAULT NOW()
    )`);
}

// ── Mail ──────────────────────────────────────────────────────────────────────
function sendMail(to, subject, code) {
    if (!process.env.MAILER_URL) { console.error('MAILER_URL not set'); return Promise.resolve(); }
    return fetch(process.env.MAILER_URL, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ to, subject, code, secret: process.env.MAILER_SECRET }),
    }).then(r => r.json()).then(d => { console.log('mailer:', d); return d; });
}

// ── Helpers ───────────────────────────────────────────────────────────────────
const genCode  = () => String(Math.floor(100000 + Math.random() * 900000));
const genToken = () => crypto.randomBytes(32).toString('hex');

async function createSession(userId, remember) {
    const token   = genToken();
    const ms      = remember ? 365 * 24 * 3600e3 : 24 * 3600e3;
    const expires = new Date(Date.now() + ms);
    await q('INSERT INTO sessions (user_id,token,remember,expires_at) VALUES($1,$2,$3,$4)',
        [userId, token, remember ? 1 : 0, expires]);
    return token;
}

async function getUserByToken(token) {
    if (!token) return null;
    const r = await q(`
        SELECT u.id, u.email, u.nick, u.avatar, u.verified
        FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE s.token = $1 AND s.expires_at > NOW()
    `, [token]);
    return r.rows[0] ?? null;
}

// ── Express ───────────────────────────────────────────────────────────────────
const app = express();
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', 'https://tp.huttrb.ru');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});
app.use(express.json({ limit: '20mb' }));
app.use(express.static(__dirname));

async function reqAuth(req, res, next) {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    const u = await getUserByToken(token);
    if (!u)          return res.status(401).json({ error: 'Не авторизован' });
    if (!u.verified) return res.status(403).json({ error: 'Email не подтверждён' });
    req.user = u;
    next();
}

// ── Auth ──────────────────────────────────────────────────────────────────────

app.post('/api/auth/register', async (req, res) => {
    try {
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
        const existingEmail = (await q('SELECT id, verified FROM users WHERE email=$1', [email])).rows[0];
        if (existingEmail?.verified) return res.status(400).json({ error: 'Email уже зарегистрирован' });

        const existingNick = (await q('SELECT id, verified FROM users WHERE nick=$1', [nick])).rows[0];
        if (existingNick && (existingNick.verified || existingNick.id !== existingEmail?.id))
            return res.status(400).json({ error: 'Ник уже занят' });

        const hash = await bcrypt.hash(password, 10);
        if (existingEmail) {
            await q('UPDATE users SET nick=$1, password_hash=$2 WHERE email=$3', [nick, hash, email]);
        } else {
            await q('INSERT INTO users (email,nick,password_hash) VALUES($1,$2,$3)', [email, nick, hash]);
        }

        const code    = genCode();
        const expires = new Date(Date.now() + 15 * 60e3);
        await q('DELETE FROM email_codes WHERE email=$1 AND type=$2', [email, 'verify_reg']);
        await q('INSERT INTO email_codes (email,code,type,expires_at) VALUES($1,$2,$3,$4)',
            [email, code, 'verify_reg', expires]);

        sendMail(email, 'Код подтверждения регистрации', code).catch(console.error);
        res.json({ ok: true, email });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/auth/verify', async (req, res) => {
    try {
        const email = req.body?.email?.trim().toLowerCase();
        const code  = req.body?.code?.trim();
        const r = await q(`
            SELECT id FROM email_codes
            WHERE email=$1 AND code=$2 AND type='verify_reg' AND expires_at > NOW()
        `, [email, code]);
        if (!r.rows[0]) return res.status(400).json({ error: 'Неверный или устаревший код' });
        await q('UPDATE users SET verified=1 WHERE email=$1', [email]);
        await q('DELETE FROM email_codes WHERE email=$1 AND type=$2', [email, 'verify_reg']);
        res.json({ ok: true });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const email    = req.body?.email?.trim().toLowerCase() ?? '';
        const password = req.body?.password ?? '';
        const remember = !!req.body?.remember;
        const r    = await q('SELECT * FROM users WHERE email=$1', [email]);
        const user = r.rows[0];
        if (!user || !(await bcrypt.compare(password, user.password_hash)))
            return res.status(401).json({ error: 'Неверный email или пароль' });
        if (!user.verified)
            return res.status(403).json({ error: 'Подтвердите email перед входом', needVerify: true, email: user.email });
        const token = await createSession(user.id, remember);
        res.json({ ok: true, token, user: { id: user.id, email: user.email, nick: user.nick, avatar: user.avatar } });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/auth/logout', reqAuth, async (req, res) => {
    try {
        const token = (req.headers.authorization || '').replace('Bearer ', '');
        await q('DELETE FROM sessions WHERE token=$1', [token]);
        res.json({ ok: true });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Ошибка сервера' }); }
});

// ── Profile ───────────────────────────────────────────────────────────────────

app.get('/api/me', reqAuth, (req, res) => {
    const { id, email, nick, avatar } = req.user;
    res.json({ id, email, nick, avatar });
});

app.put('/api/me/nick', reqAuth, async (req, res) => {
    try {
        const nick = req.body?.nick?.trim().slice(0, 24);
        if (!nick || nick.length < 2) return res.status(400).json({ error: 'Ник слишком короткий' });
        if ((await q('SELECT id FROM users WHERE nick=$1 AND id!=$2', [nick, req.user.id])).rows[0])
            return res.status(400).json({ error: 'Ник уже занят' });
        const oldNick = req.user.nick;
        await q('UPDATE users SET nick=$1 WHERE id=$2', [nick, req.user.id]);
        if (wsUsers.has(oldNick)) {
            const ws = wsUsers.get(oldNick);
            ws._nick = nick;
            wsUsers.delete(oldNick);
            wsUsers.set(nick, ws);
        }
        broadcastUserList();
        res.json({ ok: true, nick });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.put('/api/me/avatar', reqAuth, async (req, res) => {
    try {
        await q('UPDATE users SET avatar=$1 WHERE id=$2', [req.body?.avatar ?? null, req.user.id]);
        broadcastUserList();
        res.json({ ok: true });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/me/change-password', reqAuth, async (req, res) => {
    try {
        const { currentPassword = '', newPassword = '' } = req.body ?? {};
        const r    = await q('SELECT * FROM users WHERE id=$1', [req.user.id]);
        const user = r.rows[0];
        if (!(await bcrypt.compare(currentPassword, user.password_hash)))
            return res.status(400).json({ error: 'Неверный текущий пароль' });
        if (newPassword.length < 6)
            return res.status(400).json({ error: 'Новый пароль минимум 6 символов' });
        await q('UPDATE users SET password_hash=$1 WHERE id=$2',
            [await bcrypt.hash(newPassword, 10), req.user.id]);
        res.json({ ok: true });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/me/request-email-change', reqAuth, async (req, res) => {
    try {
        const { newEmail = '', password = '' } = req.body ?? {};
        const lo   = newEmail.trim().toLowerCase();
        const r    = await q('SELECT * FROM users WHERE id=$1', [req.user.id]);
        const user = r.rows[0];
        if (!(await bcrypt.compare(password, user.password_hash)))
            return res.status(400).json({ error: 'Неверный пароль' });
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(lo))
            return res.status(400).json({ error: 'Неверный формат email' });
        if ((await q('SELECT id FROM users WHERE email=$1', [lo])).rows[0])
            return res.status(400).json({ error: 'Email уже занят' });
        const code    = genCode();
        const expires = new Date(Date.now() + 15 * 60e3);
        await q('DELETE FROM email_codes WHERE email=$1 AND type=$2', [user.email, 'change_email']);
        await q('INSERT INTO email_codes (email,code,type,new_email,expires_at) VALUES($1,$2,$3,$4,$5)',
            [user.email, code, 'change_email', lo, expires]);
        sendMail(lo, 'Подтверждение смены email', code).catch(console.error);
        res.json({ ok: true });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/me/verify-email-change', reqAuth, async (req, res) => {
    try {
        const code = req.body?.code?.trim();
        const r    = await q('SELECT * FROM users WHERE id=$1', [req.user.id]);
        const user = r.rows[0];
        const cr   = await q(`
            SELECT new_email FROM email_codes
            WHERE email=$1 AND code=$2 AND type='change_email' AND expires_at > NOW()
        `, [user.email, code]);
        if (!cr.rows[0]) return res.status(400).json({ error: 'Неверный или устаревший код' });
        const newEmail = cr.rows[0].new_email;
        await q('UPDATE users SET email=$1 WHERE id=$2', [newEmail, req.user.id]);
        await q('DELETE FROM email_codes WHERE email=$1 AND type=$2', [user.email, 'change_email']);
        res.json({ ok: true, newEmail });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Ошибка сервера' }); }
});

// ── Users & messages ──────────────────────────────────────────────────────────

app.get('/api/users', reqAuth, async (req, res) => {
    try {
        const r = await q(
            'SELECT id, nick, avatar FROM users WHERE id != $1 AND verified = 1 ORDER BY nick ASC',
            [req.user.id]
        );
        res.json(r.rows.map(u => ({ ...u, online: wsUsers.has(u.nick) })));
    } catch (e) { console.error(e); res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.get('/api/messages/:userId', reqAuth, async (req, res) => {
    try {
        const other = parseInt(req.params.userId) || 0;
        const r = await q(`
            SELECT m.id, m.sender_id, m.receiver_id, m.kind, m.content, m.created_at,
                   u.nick AS from_nick
            FROM messages m JOIN users u ON u.id = m.sender_id
            WHERE (m.sender_id = $1 AND m.receiver_id = $2)
               OR (m.sender_id = $2 AND m.receiver_id = $1)
            ORDER BY m.created_at ASC LIMIT 500
        `, [req.user.id, other]);
        res.json(r.rows.map(m => {
            try { return { ...m, content: JSON.parse(m.content) }; }
            catch { return { ...m, content: {} }; }
        }));
    } catch (e) { console.error(e); res.status(500).json({ error: 'Ошибка сервера' }); }
});

// ── WebSocket ─────────────────────────────────────────────────────────────────
const server  = http.createServer(app);
const wss     = new WebSocket.Server({ server });
const wsUsers = new Map();

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

async function broadcastUserList() {
    for (const [, ws] of wsUsers) {
        try {
            const r = await q(
                'SELECT id, nick, avatar FROM users WHERE id != $1 AND verified = 1 ORDER BY nick ASC',
                [ws._userId]
            );
            wsSend(ws, { type: 'user-list', users: r.rows.map(u => ({ ...u, online: wsUsers.has(u.nick) })) });
        } catch {}
    }
}

wss.on('connection', ws => {
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });
    let user = null;

    ws.on('message', async raw => {
        let msg;
        try { msg = JSON.parse(raw); } catch { return; }

        if (msg.type === 'auth') {
            const u = await getUserByToken(msg.token);
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
                try {
                    const r = await q('SELECT id FROM users WHERE nick=$1', [msg.target]);
                    if (r.rows[0]) {
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
                        await q('INSERT INTO messages (sender_id,receiver_id,kind,content) VALUES($1,$2,$3,$4)',
                            [user.id, r.rows[0].id, msg.kind || 'text', content]);
                    }
                } catch (e) { console.error(e); }
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

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 8080;
initDB()
    .then(() => server.listen(PORT, () => console.log(`TP server on :${PORT}`)))
    .catch(err => { console.error('DB init failed:', err); process.exit(1); });
