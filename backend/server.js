import express from 'express';
import bcrypt from 'bcryptjs';
import { MongoClient } from 'mongodb';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID, randomBytes, pbkdf2Sync } from 'node:crypto';

const app = express();
app.use(express.json({ limit: '12mb' }));
const __dirname = path.dirname(fileURLToPath(import.meta.url));
app.use(express.static(path.join(__dirname, '..', 'frontend')));
const PORT = 3000;

// MongoDB URI is kept directly in this backend file. No .env is required.
const URI = 'mongodb+srv://officalprajapatianuj_db_user:Anuj123456@cluster0.2u1emzi.mongodb.net';

const DB_NAME = 'rent_manager';

const client = new MongoClient(URI);

try {
  await client.connect();
  console.log('MongoDB connected successfully');
} catch (error) {
  console.error('MongoDB connection failed:', error.message);
  process.exit(1);
}

const db = client.db(DB_NAME);
const states = db.collection('app_states');

const seed = {
  version: 11,
  settings: {
    theme: 'system',
    name: 'My Property'
  },
  users: [],
  tenants: [],
  bills: [],
  payments: [],
  deletedTenants: []
};

let stateDoc = await states.findOne({ _id: 'main' });

if (!stateDoc) {
  await states.insertOne({
    _id: 'main',
    data: seed,
    updatedAt: new Date()
  });
}

const sessions = new Map();
const SESSION_TTL = 1000 * 60 * 60 * 24 * 30;

function createSession(data) {
  const id = randomBytes(32).toString('hex');
  sessions.set(id, {
    ...data,
    expiresAt: Date.now() + SESSION_TTL
  });
  return id;
}

function auth(req, res, next) {
  const id = req.get('X-Session-Id');
  const session = id && sessions.get(id);

  if (!session || session.expiresAt < Date.now()) {
    if (id) sessions.delete(id);
    return res.status(401).json({
      error: 'Session expired. Please log in again.'
    });
  }

  session.expiresAt = Date.now() + SESSION_TTL;
  req.auth = session;
  next();
}

function getState() { return states.findOne({ _id: 'main' }).then(x => x?.data || structuredClone(seed)); }
function publicState(s, role, tenantId) {
  if (role === 'landlord') return s;
  const t = s.tenants.find(x => x.id === tenantId);
  if (!t) return { ...seed, settings: s.settings, tenants: [], bills: [], payments: [], deletedTenants: [], users: [] };
  const bills = s.bills.filter(b => b.tenantId === tenantId);
  const payments = s.payments.filter(p => p.tenantId === tenantId || bills.some(b => b.id === p.billId));
  return { ...seed, version: s.version, settings: s.settings, tenants: [t], bills, payments, deletedTenants: [] };
}
async function writeState(s) { s.version = 11; await states.updateOne({ _id: 'main' }, { $set: { data: s, updatedAt: new Date() } }, { upsert: true }); }
function renterHash(password, salt) { return pbkdf2Sync(String(password), Buffer.from(salt, 'hex'), 210000, 32, 'sha256').toString('hex'); }

app.post('/api/auth/register-landlord', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || typeof password !== 'string' || password.length < 8) return res.status(400).json({ error: 'Name, email and an 8+ character password are required.' });
    const s = await getState();
    if (s.users.some(u => u.role === 'landlord' && u.email.toLowerCase() === email.toLowerCase())) return res.status(409).json({ error: 'Email already exists.' });
    const u = { id: randomUUID(), name: String(name).trim(), email: String(email).trim(), passwordHash: await bcrypt.hash(password, 12), role: 'landlord', createdAt: new Date().toISOString() };
    s.users.push(u); await writeState(s);
    const sessionId = createSession({ role: 'landlord', userId: u.id });
    res.json({ sessionId, role: 'landlord', userId: u.id, state: publicState(s, 'landlord') });
  } catch { res.status(500).json({ error: 'Server error' }); }
});
app.post('/api/auth/login-landlord', async (req, res) => {
  try {
    const { email, password } = req.body || {}; const s = await getState();
    const u = s.users.find(x => x.role === 'landlord' && x.email.toLowerCase() === String(email || '').toLowerCase());
    if (!u) return res.status(401).json({ error: 'Landlord account not found.' });
    if (!(await bcrypt.compare(String(password || ''), u.passwordHash))) return res.status(401).json({ error: 'Incorrect password.' });
    const sessionId = createSession({ role: 'landlord', userId: u.id });
    res.json({ sessionId, role: 'landlord', userId: u.id, state: publicState(s, 'landlord') });
  } catch { res.status(500).json({ error: 'Server error' }); }
});
app.post('/api/auth/login-renter', async (req, res) => {
  try {
    const { email, password } = req.body || {}; const s = await getState();
    const t = s.tenants.find(x => x.renterEmail && x.renterEmail.toLowerCase() === String(email || '').toLowerCase());
    if (!t || !t.renterPasswordHash) return res.status(401).json({ error: 'Renter account not found.' });
    if (renterHash(password, t.renterSalt) !== t.renterPasswordHash) return res.status(401).json({ error: 'Incorrect password.' });
    const sessionId = createSession({ role: 'renter', tenantId: t.id });
    res.json({ sessionId, role: 'renter', tenantId: t.id, state: publicState(s, 'renter', t.id) });
  } catch { res.status(500).json({ error: 'Server error' }); }
});
app.post('/api/auth/logout', auth, (req, res) => { const id = req.get('X-Session-Id'); sessions.delete(id); res.json({ ok: true }); });
app.get('/api/state', auth, async (req, res) => { const s = await getState(); res.json({ state: publicState(s, req.auth.role, req.auth.tenantId) }); });
app.put('/api/state', auth, async (req, res) => {
  if (req.auth.role !== 'landlord') return res.status(403).json({ error: 'Landlord access required.' });
  const incoming = req.body?.state;
  if (!incoming || !Array.isArray(incoming.tenants) || !Array.isArray(incoming.bills) || !Array.isArray(incoming.payments)) return res.status(400).json({ error: 'Invalid state.' });
  const s = await getState(); incoming.users = s.users; await writeState(incoming); res.json({ ok: true });
});
app.get('/api/health', (req, res) => res.json({ ok: true, database: DB_NAME, jwt: false }));
app.get(/.*/, (req, res) => res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html')));
app.listen(PORT, () => console.log(`Rent Manager running on http://localhost:${PORT}`));
