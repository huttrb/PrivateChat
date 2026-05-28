const WebSocket = require('ws');

const PORT = process.env.PORT || 8080;
const wss  = new WebSocket.Server({ port: PORT });

// Detect dead connections (mobile tab close, network drop, etc.)
const heartbeat = setInterval(() => {
    for (const ws of wss.clients) {
        if (!ws.isAlive) { ws.terminate(); continue; }
        ws.isAlive = false;
        ws.ping();
    }
}, 20000);
wss.on('close', () => clearInterval(heartbeat));

const clients = new Map(); // username → ws
const rooms   = new Map(); // roomId  → { id, name, creator, users: [] }

wss.on('connection', ws => {
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });

    let username = null;
    let roomId   = null;

    ws.on('message', raw => {
        let msg;
        try { msg = JSON.parse(raw); } catch { return; }

        switch (msg.type) {

            case 'register': {
                const name = String(msg.username || '').trim().slice(0, 24);
                if (!name) return;
                if (clients.has(name)) {
                    send(ws, { type: 'register-error', error: 'Ник уже занят' });
                    return;
                }
                username = name;
                clients.set(username, ws);
                console.log(`[+] ${username} (online: ${clients.size})`);
                send(ws, { type: 'registered', username });
                send(ws, { type: 'room-list',  rooms: roomList() });
                break;
            }

            case 'create-room': {
                if (!username) return;
                const name = String(msg.name || '').trim().slice(0, 40) || 'Комната';
                const id   = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
                const room = { id, name, creator: username, users: [username] };
                rooms.set(id, room);
                roomId = id;
                send(ws, { type: 'room-joined', room: dto(room) });
                broadcast({ type: 'room-list', rooms: roomList() });
                console.log(`[room+] "${name}" by ${username}`);
                break;
            }

            case 'join-room': {
                if (!username) return;
                const room = rooms.get(msg.roomId);
                if (!room) {
                    send(ws, { type: 'join-error', error: 'Комната не найдена' });
                    return;
                }
                if (room.users.length >= 2) {
                    send(ws, { type: 'join-error', error: 'Комната заполнена' });
                    return;
                }
                if (room.users.includes(username)) return;
                room.users.push(username);
                roomId = room.id;
                const other = room.users.find(u => u !== username) || null;
                send(ws, { type: 'room-joined', room: dto(room), partner: other });
                if (other) sendTo(other, { type: 'user-joined', username });
                broadcast({ type: 'room-list', rooms: roomList() });
                break;
            }

            case 'leave-room': {
                if (username && roomId) { leaveRoom(username, roomId); roomId = null; }
                break;
            }

            default: {
                if (msg.target) sendTo(msg.target, { ...msg, from: username });
            }
        }
    });

    ws.on('close', () => {
        if (username && roomId) leaveRoom(username, roomId);
        if (username) {
            clients.delete(username);
            console.log(`[-] ${username} (online: ${clients.size})`);
        }
    });

    ws.on('error', err => console.error('WS error:', err.message));
});

function leaveRoom(user, rid) {
    const room = rooms.get(rid);
    if (!room) return;
    room.users = room.users.filter(u => u !== user);
    const other = room.users[0];
    sendTo(other, { type: 'user-left', username: user });
    if (room.users.length === 0) {
        rooms.delete(rid);
        console.log(`[room-] "${room.name}"`);
    }
    broadcast({ type: 'room-list', rooms: roomList() });
}

function dto(room) {
    return { id: room.id, name: room.name, creator: room.creator, count: room.users.length };
}
function roomList() { return [...rooms.values()].map(dto); }

function send(ws, obj) {
    if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}
function sendTo(username, obj) {
    if (username) send(clients.get(username), obj);
}
function broadcast(obj) {
    const s = JSON.stringify(obj);
    for (const ws of clients.values())
        if (ws.readyState === WebSocket.OPEN) ws.send(s);
}

console.log(`Server on :${PORT}`);
