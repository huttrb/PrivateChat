const WebSocket = require('ws');

const PORT = process.env.PORT || 8080;
const wss = new WebSocket.Server({ port: PORT });
const clients = new Map(); // username -> ws

wss.on('connection', (ws) => {
    let username = null;

    ws.on('message', (raw) => {
        let msg;
        try { msg = JSON.parse(raw); } catch { return; }

        if (msg.type === 'register') {
            // Close previous connection for this user if any
            if (clients.has(msg.username)) {
                const old = clients.get(msg.username);
                old.username = null;
                old.close();
            }
            username = msg.username;
            clients.set(username, ws);
            console.log(`[+] ${username} connected  (online: ${[...clients.keys()].join(', ')})`);
            broadcastPresence();
            return;
        }

        // Relay everything else to the target user
        if (msg.target) {
            const targetWs = clients.get(msg.target);
            if (targetWs && targetWs.readyState === WebSocket.OPEN) {
                targetWs.send(JSON.stringify({ ...msg, from: username }));
            }
        }
    });

    ws.on('close', () => {
        if (username && clients.get(username) === ws) {
            clients.delete(username);
            console.log(`[-] ${username} disconnected (online: ${[...clients.keys()].join(', ')})`);
            broadcastPresence();
        }
    });

    ws.on('error', (err) => console.error('WS error:', err.message));
});

function broadcastPresence() {
    const online = [...clients.keys()];
    const msg = JSON.stringify({ type: 'presence', online });
    for (const clientWs of clients.values()) {
        if (clientWs.readyState === WebSocket.OPEN) clientWs.send(msg);
    }
}

console.log(`Signaling server running on port ${PORT}`);
