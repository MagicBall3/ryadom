const { createClient } = require('@supabase/supabase-js');

module.exports = async (req, res) => {
  const ua = req.headers['user-agent'] || '';
  const isCron = ua.indexOf('vercel-cron') !== -1;
  const secretOk = process.env.CRON_SECRET && req.headers['x-cron-secret'] === process.env.CRON_SECRET;
  if (!isCron && !secretOk) { res.status(401).json({ error: 'forbidden' }); return; }

  try {
    const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
    await admin.from('settings').select('key').limit(1);
    res.status(200).json({ ok: true, ts: Date.now() });
  } catch (e) {
    res.status(500).json({ ok: false });
  }
};
