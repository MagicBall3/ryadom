const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const supabaseUrl = process.env.SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const admin = createClient(supabaseUrl, serviceKey);

function genPassword() {
  const chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const bytes = crypto.randomBytes(14);
  let out = '';
  for (let i = 0; i < 14; i++) out += chars[bytes[i] % chars.length];
  return out;
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') { res.status(405).json({ error: 'method_not_allowed' }); return; }
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) { res.status(401).json({ error: 'no_token' }); return; }

    const { data: userData, error: userErr } = await admin.auth.getUser(token);
    if (userErr || !userData || !userData.user) { res.status(401).json({ error: 'bad_token' }); return; }

    const { data: me, error: meErr } = await admin
      .from('profiles').select('role').eq('id', userData.user.id).single();
    if (meErr || !me || me.role !== 'admin') { res.status(403).json({ error: 'forbidden' }); return; }

    const body = req.body || {};
    const action = body.action;

    if (action === 'create') {
      const name = (body.name || '').toString().trim().slice(0, 100);
      const email = (body.email || '').toString().trim().toLowerCase();
      const role = body.role;
      if (!name || !email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || !['teacher', 'psy'].includes(role)) {
        res.status(400).json({ error: 'bad_input' }); return;
      }
      const password = genPassword();
      const { data: created, error: cErr } = await admin.auth.admin.createUser({
        email, password, email_confirm: true
      });
      if (cErr) { res.status(400).json({ error: cErr.message }); return; }
      const { error: pErr } = await admin.from('profiles').insert({
        id: created.user.id, email, name, role, must_change_password: true
      });
      if (pErr) {
        await admin.auth.admin.deleteUser(created.user.id);
        res.status(400).json({ error: pErr.message }); return;
      }
      res.status(200).json({ password });
      return;
    }

    if (action === 'reset') {
      const staffId = body.id;
      if (!staffId) { res.status(400).json({ error: 'bad_input' }); return; }
      const password = genPassword();
      const { error: uErr } = await admin.auth.admin.updateUserById(staffId, { password });
      if (uErr) { res.status(400).json({ error: uErr.message }); return; }
      await admin.from('profiles').update({ must_change_password: true }).eq('id', staffId);
      res.status(200).json({ password });
      return;
    }

    if (action === 'delete') {
      const staffId = body.id;
      if (!staffId) { res.status(400).json({ error: 'bad_input' }); return; }
      await admin.from('reports').update({ assignee: null }).eq('assignee', staffId);
      const { error: dErr } = await admin.auth.admin.deleteUser(staffId);
      if (dErr) { res.status(400).json({ error: dErr.message }); return; }
      res.status(200).json({ ok: true });
      return;
    }

    res.status(400).json({ error: 'bad_action' });
  } catch (e) {
    res.status(500).json({ error: 'server_error' });
  }
};
