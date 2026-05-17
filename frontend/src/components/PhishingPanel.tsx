import { useState, useEffect, useRef, useCallback } from 'react';
import axios from 'axios';

// ── Types ─────────────────────────────────────────────────────────────────────

interface SMTPProfile {
  id: number; name: string; from_address: string; from_name: string;
  host: string; port: number; username: string; password: string; tls: string;
}
interface EmailTemplate {
  id: number; name: string; subject: string; html_body: string; text_body: string;
}
interface LandingPage {
  id: number; name: string; html: string; redirect_url: string; capture_credentials: boolean;
}
interface TargetGroup {
  id: number; name: string; targets?: Target[]; created_at?: string;
}
interface Target {
  id: number; group_id: number; first_name: string; last_name: string; email: string; position: string;
}
interface Campaign {
  id: number; name: string; status: string; smtp_id: number; template_id: number;
  page_id: number; group_id: number; phish_url: string; launch_date: string;
  sent: number; opened: number; clicked: number; submitted: number;
}
interface PhishResult {
  id: number; rid: string; email: string; first_name: string; last_name: string;
  position: string; status: string; sent_at: string; opened_at: string;
  clicked_at: string; submitted_at: string; submitted_data: string;
}

type Tab = 'campaigns' | 'templates' | 'pages' | 'smtp' | 'groups';

// ── Status badge ──────────────────────────────────────────────────────────────

const STATUS_COLOR: Record<string, string> = {
  pending: '#546e7a', sent: '#1565c0', opened: '#f57c00',
  clicked: '#e64a19', submitted: '#b71c1c', error: '#888', completed: '#2e7d32', 'in-progress': '#1565c0',
};

function StatusBadge({ status }: { status: string }) {
  return (
    <span style={{ display:'inline-block', padding:'1px 8px', borderRadius:3, fontSize:11,
      fontWeight:700, background: STATUS_COLOR[status] || '#546e7a', color:'#fff' }}>
      {status}
    </span>
  );
}

// ── Shared form helpers ───────────────────────────────────────────────────────

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ display:'flex', flexDirection:'column', gap:4 }}>
      <label style={{ fontSize:11, color:'var(--text-dim)', textTransform:'uppercase', letterSpacing:'0.05em' }}>{label}</label>
      {children}
    </div>
  );
}

const inp: React.CSSProperties = {
  background:'var(--bg-base)', border:'1px solid var(--border-base)', borderRadius:4,
  color:'var(--text-base)', padding:'6px 10px', fontSize:13, width:'100%', boxSizing:'border-box',
};
const ta: React.CSSProperties = { ...inp, resize:'vertical', fontFamily:'monospace', minHeight:120 };
const btn = (variant: 'primary'|'danger'|'secondary' = 'secondary'): React.CSSProperties => ({
  padding:'5px 14px', borderRadius:4, border:'none', cursor:'pointer', fontSize:12, fontWeight:600,
  background: variant==='primary' ? 'var(--cyan)' : variant==='danger' ? '#c62828' : 'var(--bg-raised)',
  color: variant==='primary' ? '#000' : '#fff',
});

// ── Campaigns tab ─────────────────────────────────────────────────────────────

function CampaignsTab({ smtpList, templates, pages, groups }: {
  smtpList: SMTPProfile[]; templates: EmailTemplate[]; pages: LandingPage[]; groups: TargetGroup[];
}) {
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ name:'', smtp_id:0, template_id:0, page_id:0, group_id:0, phish_url:'' });
  const [creating, setCreating] = useState(false);
  const [err, setErr] = useState('');
  const [selected, setSelected] = useState<Campaign | null>(null);
  const [results, setResults] = useState<PhishResult[]>([]);
  const [expandedData, setExpandedData] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const load = useCallback(async () => {
    const res = await axios.get('/api/phishing/campaigns').catch(() => null);
    if (res) setCampaigns(res.data.campaigns || []);
  }, []);

  useEffect(() => { load(); }, [load]);

  const loadResults = useCallback(async (c: Campaign) => {
    const res = await axios.get(`/api/phishing/campaigns/${c.id}/results`).catch(() => null);
    if (res) { setResults(res.data.results || []); setSelected({ ...c, ...res.data.campaign }); }
  }, []);

  // Poll results while a campaign is in-progress
  useEffect(() => {
    if (pollRef.current) clearInterval(pollRef.current);
    if (selected && selected.status === 'in-progress') {
      pollRef.current = setInterval(() => loadResults(selected), 5000);
    }
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [selected, loadResults]);

  const handleCreate = async () => {
    if (!form.name || !form.smtp_id || !form.template_id || !form.group_id) {
      setErr('Name, SMTP profile, email template, and target group are required.'); return;
    }
    setCreating(true); setErr('');
    try {
      await axios.post('/api/phishing/campaigns', form);
      setShowForm(false); setForm({ name:'', smtp_id:0, template_id:0, page_id:0, group_id:0, phish_url:'' });
      load();
    } catch (e: any) { setErr(e.response?.data?.error || e.message); }
    finally { setCreating(false); }
  };

  const handleComplete = async (id: number) => {
    await axios.post(`/api/phishing/campaigns/${id}/complete`).catch(() => null);
    load();
    if (selected?.id === id) setSelected(prev => prev ? { ...prev, status:'completed' } : prev);
  };

  const handleDelete = async (id: number) => {
    await axios.delete(`/api/phishing/campaigns/${id}`).catch(() => null);
    if (selected?.id === id) setSelected(null);
    load();
  };

  if (selected) {
    return (
      <div>
        <button style={btn()} onClick={() => { setSelected(null); setResults([]); load(); }}>← Back to Campaigns</button>
        <div style={{ margin:'16px 0 8px', display:'flex', alignItems:'center', gap:12 }}>
          <strong style={{ fontSize:16 }}>{selected.name}</strong>
          <StatusBadge status={selected.status} />
          {selected.status !== 'completed' && (
            <button style={btn('danger')} onClick={() => handleComplete(selected.id)}>Mark Complete</button>
          )}
        </div>
        <div style={{ display:'flex', gap:16, marginBottom:16 }}>
          {[['Sent', selected.sent, '#1565c0'], ['Opened', selected.opened, '#f57c00'],
            ['Clicked', selected.clicked, '#e64a19'], ['Submitted', selected.submitted, '#b71c1c']].map(([label, val, color]) => (
            <div key={label as string} style={{ background:'var(--bg-surface)', border:'1px solid var(--border-base)',
              borderRadius:6, padding:'10px 20px', textAlign:'center' }}>
              <div style={{ fontSize:24, fontWeight:700, color: color as string }}>{val as number}</div>
              <div style={{ fontSize:11, color:'var(--text-dim)' }}>{label}</div>
            </div>
          ))}
        </div>
        <table className="rp-table" style={{ fontSize:12 }}>
          <thead><tr>
            <th>Email</th><th>Name</th><th>Status</th><th>Sent</th>
            <th>Opened</th><th>Clicked</th><th>Submitted</th><th>Data</th>
          </tr></thead>
          <tbody>
            {results.map(r => (
              <tr key={r.id}>
                <td className="rp-mono">{r.email}</td>
                <td>{r.first_name} {r.last_name}</td>
                <td><StatusBadge status={r.status} /></td>
                <td style={{ fontSize:10 }}>{r.sent_at ? r.sent_at.slice(0,16) : '—'}</td>
                <td style={{ fontSize:10 }}>{r.opened_at ? r.opened_at.slice(0,16) : '—'}</td>
                <td style={{ fontSize:10 }}>{r.clicked_at ? r.clicked_at.slice(0,16) : '—'}</td>
                <td style={{ fontSize:10 }}>{r.submitted_at ? r.submitted_at.slice(0,16) : '—'}</td>
                <td>
                  {r.submitted_data && r.submitted_data !== '' && r.submitted_data !== '{}' && (
                    <button style={{ ...btn(), fontSize:11 }}
                      onClick={() => setExpandedData(expandedData === r.rid ? null : r.rid)}>
                      {expandedData === r.rid ? 'Hide' : 'View'}
                    </button>
                  )}
                  {expandedData === r.rid && (
                    <pre style={{ fontSize:10, marginTop:4, background:'var(--bg-base)', padding:6, borderRadius:4 }}>
                      {JSON.stringify(JSON.parse(r.submitted_data || '{}'), null, 2)}
                    </pre>
                  )}
                </td>
              </tr>
            ))}
            {results.length === 0 && (
              <tr><td colSpan={8} style={{ textAlign:'center', color:'var(--text-dim)' }}>No results yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    );
  }

  return (
    <div>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:12 }}>
        <strong>Campaigns</strong>
        <button style={btn('primary')} onClick={() => setShowForm(s => !s)}>+ New Campaign</button>
      </div>

      {showForm && (
        <div style={{ background:'var(--bg-surface)', border:'1px solid var(--border-base)',
          borderRadius:6, padding:16, marginBottom:16, display:'flex', flexDirection:'column', gap:10 }}>
          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:10 }}>
            <Field label="Campaign Name">
              <input style={inp} value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="e.g. Q2 Phish" />
            </Field>
            <Field label="Phish URL (your server's public address)">
              <input style={inp} value={form.phish_url} onChange={e => setForm(f => ({ ...f, phish_url: e.target.value }))} placeholder="http://10.0.0.5:8080" />
            </Field>
            <Field label="Sending Profile">
              <select style={inp} value={form.smtp_id} onChange={e => setForm(f => ({ ...f, smtp_id: +e.target.value }))}>
                <option value={0}>— select —</option>
                {smtpList.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
              </select>
            </Field>
            <Field label="Email Template">
              <select style={inp} value={form.template_id} onChange={e => setForm(f => ({ ...f, template_id: +e.target.value }))}>
                <option value={0}>— select —</option>
                {templates.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
              </select>
            </Field>
            <Field label="Landing Page (optional)">
              <select style={inp} value={form.page_id} onChange={e => setForm(f => ({ ...f, page_id: +e.target.value }))}>
                <option value={0}>— none —</option>
                {pages.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            </Field>
            <Field label="Target Group">
              <select style={inp} value={form.group_id} onChange={e => setForm(f => ({ ...f, group_id: +e.target.value }))}>
                <option value={0}>— select —</option>
                {groups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
              </select>
            </Field>
          </div>
          {err && <div style={{ color:'#e57373', fontSize:12 }}>{err}</div>}
          <div style={{ display:'flex', gap:8 }}>
            <button style={btn('primary')} onClick={handleCreate} disabled={creating}>
              {creating ? 'Launching…' : 'Launch Campaign'}
            </button>
            <button style={btn()} onClick={() => { setShowForm(false); setErr(''); }}>Cancel</button>
          </div>
        </div>
      )}

      <table className="rp-table" style={{ fontSize:12 }}>
        <thead><tr>
          <th>Name</th><th>Status</th><th>Sent</th><th>Opened</th><th>Clicked</th><th>Submitted</th><th></th>
        </tr></thead>
        <tbody>
          {campaigns.map(c => (
            <tr key={c.id} style={{ cursor:'pointer' }} onClick={() => { loadResults(c); }}>
              <td><strong>{c.name}</strong></td>
              <td><StatusBadge status={c.status} /></td>
              <td>{c.sent}</td>
              <td style={{ color: c.opened > 0 ? '#f57c00' : undefined }}>{c.opened}</td>
              <td style={{ color: c.clicked > 0 ? '#e64a19' : undefined }}>{c.clicked}</td>
              <td style={{ color: c.submitted > 0 ? '#b71c1c' : undefined }}>{c.submitted}</td>
              <td onClick={e => e.stopPropagation()}>
                <button style={{ ...btn('danger'), padding:'2px 8px' }} onClick={() => handleDelete(c.id)}>Delete</button>
              </td>
            </tr>
          ))}
          {campaigns.length === 0 && (
            <tr><td colSpan={7} style={{ textAlign:'center', color:'var(--text-dim)' }}>No campaigns yet.</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

// ── Email Templates tab ───────────────────────────────────────────────────────

function TemplatesTab() {
  const [list, setList] = useState<EmailTemplate[]>([]);
  const [editing, setEditing] = useState<EmailTemplate | null>(null);
  const [form, setForm] = useState<Partial<EmailTemplate>>({ name:'', subject:'', html_body:'', text_body:'' });
  const [err, setErr] = useState('');

  const load = async () => {
    const res = await axios.get('/api/phishing/templates').catch(() => null);
    if (res) setList(res.data.templates || []);
  };
  useEffect(() => { load(); }, []);

  const startEdit = (t: EmailTemplate) => { setEditing(t); setForm(t); setErr(''); };
  const startNew  = () => { setEditing({ id:0 } as EmailTemplate); setForm({ name:'', subject:'', html_body:'', text_body:'' }); setErr(''); };

  const save = async () => {
    if (!form.name || !form.subject) { setErr('Name and subject are required.'); return; }
    try {
      if (editing!.id) {
        await axios.put(`/api/phishing/templates/${editing!.id}`, form);
      } else {
        await axios.post('/api/phishing/templates', form);
      }
      setEditing(null); load();
    } catch (e: any) { setErr(e.response?.data?.error || e.message); }
  };

  const del = async (id: number) => {
    await axios.delete(`/api/phishing/templates/${id}`).catch(() => null); load();
  };

  const VARS = ['{{.FirstName}}', '{{.LastName}}', '{{.Email}}', '{{.Position}}', '{{.TrackingURL}}', '{{.Tracker}}', '{{.From}}'];

  if (editing !== null) {
    return (
      <div style={{ display:'flex', flexDirection:'column', gap:12 }}>
        <div style={{ display:'flex', alignItems:'center', gap:10 }}>
          <button style={btn()} onClick={() => setEditing(null)}>← Back</button>
          <strong>{editing.id ? 'Edit Template' : 'New Template'}</strong>
        </div>
        <div style={{ background:'var(--bg-raised)', border:'1px solid var(--border-base)', borderRadius:4,
          padding:'6px 10px', fontSize:11, color:'var(--text-dim)' }}>
          <strong>Variables:</strong>{' '}
          {VARS.map(v => (
            <code key={v} style={{ marginRight:8, cursor:'pointer', color:'var(--cyan)' }}
              onClick={() => { navigator.clipboard.writeText(v).catch(() => {}); }}>{v}</code>
          ))}
          <span style={{ opacity:0.6 }}>(click to copy)</span>
        </div>
        <Field label="Name"><input style={inp} value={form.name || ''} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} /></Field>
        <Field label="Subject"><input style={inp} value={form.subject || ''} onChange={e => setForm(f => ({ ...f, subject: e.target.value }))} placeholder="Your account requires attention — {{.FirstName}}" /></Field>
        <Field label="HTML Body"><textarea style={{ ...ta, minHeight:220 }} value={form.html_body || ''} onChange={e => setForm(f => ({ ...f, html_body: e.target.value }))} placeholder="<p>Hi {{.FirstName}},</p>&#10;<p>Click <a href='{{.TrackingURL}}'>here</a> to verify your account.</p>&#10;{{.Tracker}}" /></Field>
        <Field label="Plain Text Body (optional)"><textarea style={ta} value={form.text_body || ''} onChange={e => setForm(f => ({ ...f, text_body: e.target.value }))} /></Field>
        {err && <div style={{ color:'#e57373', fontSize:12 }}>{err}</div>}
        <div style={{ display:'flex', gap:8 }}>
          <button style={btn('primary')} onClick={save}>Save</button>
          <button style={btn()} onClick={() => setEditing(null)}>Cancel</button>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:12 }}>
        <strong>Email Templates</strong>
        <button style={btn('primary')} onClick={startNew}>+ New Template</button>
      </div>
      <table className="rp-table" style={{ fontSize:12 }}>
        <thead><tr><th>Name</th><th>Subject</th><th></th></tr></thead>
        <tbody>
          {list.map(t => (
            <tr key={t.id}>
              <td>{t.name}</td>
              <td style={{ color:'var(--text-dim)' }}>{t.subject}</td>
              <td style={{ display:'flex', gap:6 }}>
                <button style={{ ...btn(), padding:'2px 8px' }} onClick={() => startEdit(t)}>Edit</button>
                <button style={{ ...btn('danger'), padding:'2px 8px' }} onClick={() => del(t.id)}>Delete</button>
              </td>
            </tr>
          ))}
          {list.length === 0 && <tr><td colSpan={3} style={{ textAlign:'center', color:'var(--text-dim)' }}>No templates yet.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

// ── Landing Pages tab ─────────────────────────────────────────────────────────

function PagesTab() {
  const [list, setList] = useState<LandingPage[]>([]);
  const [editing, setEditing] = useState<LandingPage | null>(null);
  const [form, setForm] = useState<Partial<LandingPage>>({ name:'', html:'', redirect_url:'', capture_credentials:false });
  const [err, setErr] = useState('');

  const load = async () => {
    const res = await axios.get('/api/phishing/pages').catch(() => null);
    if (res) setList(res.data.pages || []);
  };
  useEffect(() => { load(); }, []);

  const startEdit = (p: LandingPage) => { setEditing(p); setForm(p); setErr(''); };
  const startNew  = () => { setEditing({ id:0 } as LandingPage); setForm({ name:'', html:'', redirect_url:'', capture_credentials:false }); setErr(''); };

  const save = async () => {
    if (!form.name) { setErr('Name is required.'); return; }
    try {
      if (editing!.id) {
        await axios.put(`/api/phishing/pages/${editing!.id}`, form);
      } else {
        await axios.post('/api/phishing/pages', form);
      }
      setEditing(null); load();
    } catch (e: any) { setErr(e.response?.data?.error || e.message); }
  };

  const del = async (id: number) => {
    await axios.delete(`/api/phishing/pages/${id}`).catch(() => null); load();
  };

  const PLACEHOLDER_HTML = `<!DOCTYPE html>
<html>
<body>
  <h2>Account Verification</h2>
  <form action="" method="POST">
    <label>Username: <input type="text" name="username" /></label><br/>
    <label>Password: <input type="password" name="password" /></label><br/>
    <button type="submit">Verify</button>
  </form>
</body>
</html>`;

  if (editing !== null) {
    return (
      <div style={{ display:'flex', flexDirection:'column', gap:12 }}>
        <div style={{ display:'flex', alignItems:'center', gap:10 }}>
          <button style={btn()} onClick={() => setEditing(null)}>← Back</button>
          <strong>{editing.id ? 'Edit Landing Page' : 'New Landing Page'}</strong>
        </div>
        <Field label="Name"><input style={inp} value={form.name || ''} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} /></Field>
        <Field label="HTML Content">
          <textarea style={{ ...ta, minHeight:280, fontFamily:'monospace', fontSize:12 }}
            value={form.html || ''} placeholder={PLACEHOLDER_HTML}
            onChange={e => setForm(f => ({ ...f, html: e.target.value }))} />
        </Field>
        <Field label="Redirect URL (after form submit)">
          <input style={inp} value={form.redirect_url || ''} onChange={e => setForm(f => ({ ...f, redirect_url: e.target.value }))} placeholder="https://real-site.com/login" />
        </Field>
        <label style={{ display:'flex', alignItems:'center', gap:8, fontSize:13 }}>
          <input type="checkbox" checked={!!form.capture_credentials}
            onChange={e => setForm(f => ({ ...f, capture_credentials: e.target.checked }))} />
          Capture credentials (inject form action pointing to BagaHoldin)
        </label>
        {err && <div style={{ color:'#e57373', fontSize:12 }}>{err}</div>}
        <div style={{ display:'flex', gap:8 }}>
          <button style={btn('primary')} onClick={save}>Save</button>
          <button style={btn()} onClick={() => setEditing(null)}>Cancel</button>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:12 }}>
        <strong>Landing Pages</strong>
        <button style={btn('primary')} onClick={startNew}>+ New Page</button>
      </div>
      <table className="rp-table" style={{ fontSize:12 }}>
        <thead><tr><th>Name</th><th>Redirect URL</th><th>Capture Creds</th><th></th></tr></thead>
        <tbody>
          {list.map(p => (
            <tr key={p.id}>
              <td>{p.name}</td>
              <td style={{ color:'var(--text-dim)', fontFamily:'monospace', fontSize:11 }}>{p.redirect_url || '—'}</td>
              <td>{p.capture_credentials ? '✓' : '—'}</td>
              <td style={{ display:'flex', gap:6 }}>
                <button style={{ ...btn(), padding:'2px 8px' }} onClick={() => startEdit(p)}>Edit</button>
                <button style={{ ...btn('danger'), padding:'2px 8px' }} onClick={() => del(p.id)}>Delete</button>
              </td>
            </tr>
          ))}
          {list.length === 0 && <tr><td colSpan={4} style={{ textAlign:'center', color:'var(--text-dim)' }}>No pages yet.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

// ── Sending Profiles tab ──────────────────────────────────────────────────────

function SMTPTab() {
  const [list, setList] = useState<SMTPProfile[]>([]);
  const [editing, setEditing] = useState<SMTPProfile | null>(null);
  const [form, setForm] = useState<Partial<SMTPProfile>>({ name:'', from_address:'', from_name:'', host:'', port:25, username:'', password:'', tls:'none' });
  const [testTo, setTestTo] = useState('');
  const [testMsg, setTestMsg] = useState('');
  const [testing, setTesting] = useState(false);
  const [err, setErr] = useState('');

  const load = async () => {
    const res = await axios.get('/api/phishing/smtp').catch(() => null);
    if (res) setList(res.data.profiles || []);
  };
  useEffect(() => { load(); }, []);

  const startEdit = (s: SMTPProfile) => { setEditing(s); setForm(s); setErr(''); setTestMsg(''); };
  const startNew  = () => { setEditing({ id:0 } as SMTPProfile); setForm({ name:'', from_address:'', from_name:'', host:'', port:25, username:'', password:'', tls:'none' }); setErr(''); setTestMsg(''); };

  const save = async () => {
    if (!form.name || !form.host || !form.from_address) { setErr('Name, host, and from address are required.'); return; }
    try {
      if (editing!.id) {
        await axios.put(`/api/phishing/smtp/${editing!.id}`, form);
      } else {
        await axios.post('/api/phishing/smtp', form);
      }
      setEditing(null); load();
    } catch (e: any) { setErr(e.response?.data?.error || e.message); }
  };

  const del = async (id: number) => {
    await axios.delete(`/api/phishing/smtp/${id}`).catch(() => null); load();
  };

  const test = async () => {
    if (!testTo) { setTestMsg('Enter a test address.'); return; }
    setTesting(true); setTestMsg('');
    try {
      await axios.post(`/api/phishing/smtp/${editing!.id}/test`, { to: testTo });
      setTestMsg('✓ Test email sent successfully.');
    } catch (e: any) { setTestMsg('✗ ' + (e.response?.data?.error || e.message)); }
    finally { setTesting(false); }
  };

  if (editing !== null) {
    return (
      <div style={{ display:'flex', flexDirection:'column', gap:12 }}>
        <div style={{ display:'flex', alignItems:'center', gap:10 }}>
          <button style={btn()} onClick={() => setEditing(null)}>← Back</button>
          <strong>{editing.id ? 'Edit Profile' : 'New Sending Profile'}</strong>
        </div>
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:10 }}>
          <Field label="Profile Name"><input style={inp} value={form.name || ''} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} /></Field>
          <Field label="From Name"><input style={inp} value={form.from_name || ''} onChange={e => setForm(f => ({ ...f, from_name: e.target.value }))} placeholder="IT Support" /></Field>
          <Field label="From Address"><input style={inp} value={form.from_address || ''} onChange={e => setForm(f => ({ ...f, from_address: e.target.value }))} placeholder="support@company.com" /></Field>
          <Field label="SMTP Host"><input style={inp} value={form.host || ''} onChange={e => setForm(f => ({ ...f, host: e.target.value }))} placeholder="smtp.example.com" /></Field>
          <Field label="Port">
            <input style={inp} type="number" value={form.port || 25} onChange={e => setForm(f => ({ ...f, port: +e.target.value }))} />
          </Field>
          <Field label="Encryption">
            <select style={inp} value={form.tls || 'none'} onChange={e => setForm(f => ({ ...f, tls: e.target.value }))}>
              <option value="none">None</option>
              <option value="starttls">STARTTLS</option>
              <option value="tls">TLS/SSL</option>
            </select>
          </Field>
          <Field label="Username (optional)"><input style={inp} value={form.username || ''} onChange={e => setForm(f => ({ ...f, username: e.target.value }))} autoComplete="off" /></Field>
          <Field label="Password (optional)"><input style={inp} type="password" value={form.password || ''} onChange={e => setForm(f => ({ ...f, password: e.target.value }))} autoComplete="new-password" /></Field>
        </div>
        {err && <div style={{ color:'#e57373', fontSize:12 }}>{err}</div>}
        <div style={{ display:'flex', gap:8 }}>
          <button style={btn('primary')} onClick={save}>Save</button>
          <button style={btn()} onClick={() => setEditing(null)}>Cancel</button>
        </div>
        {editing.id > 0 && (
          <div style={{ borderTop:'1px solid var(--border-base)', paddingTop:12, display:'flex', alignItems:'center', gap:8 }}>
            <input style={{ ...inp, width:240 }} placeholder="test@example.com" value={testTo} onChange={e => setTestTo(e.target.value)} />
            <button style={btn()} onClick={test} disabled={testing}>{testing ? 'Sending…' : 'Send Test Email'}</button>
            {testMsg && <span style={{ fontSize:12, color: testMsg.startsWith('✓') ? '#66bb6a' : '#e57373' }}>{testMsg}</span>}
          </div>
        )}
      </div>
    );
  }

  return (
    <div>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:12 }}>
        <strong>Sending Profiles</strong>
        <button style={btn('primary')} onClick={startNew}>+ New Profile</button>
      </div>
      <table className="rp-table" style={{ fontSize:12 }}>
        <thead><tr><th>Name</th><th>From</th><th>Host</th><th>Port</th><th>TLS</th><th></th></tr></thead>
        <tbody>
          {list.map(s => (
            <tr key={s.id}>
              <td>{s.name}</td>
              <td className="rp-mono" style={{ fontSize:11 }}>{s.from_name ? `${s.from_name} <${s.from_address}>` : s.from_address}</td>
              <td className="rp-mono" style={{ fontSize:11 }}>{s.host}</td>
              <td>{s.port}</td>
              <td>{s.tls}</td>
              <td style={{ display:'flex', gap:6 }}>
                <button style={{ ...btn(), padding:'2px 8px' }} onClick={() => startEdit(s)}>Edit</button>
                <button style={{ ...btn('danger'), padding:'2px 8px' }} onClick={() => del(s.id)}>Delete</button>
              </td>
            </tr>
          ))}
          {list.length === 0 && <tr><td colSpan={6} style={{ textAlign:'center', color:'var(--text-dim)' }}>No profiles yet.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

// ── Users & Groups tab ────────────────────────────────────────────────────────

function GroupsTab() {
  const [groups, setGroups] = useState<TargetGroup[]>([]);
  const [selected, setSelected] = useState<TargetGroup | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [newGroupName, setNewGroupName] = useState('');
  const [newTarget, setNewTarget] = useState({ first_name:'', last_name:'', email:'', position:'' });
  const [addingTarget, setAddingTarget] = useState(false);
  const [importing, setImporting] = useState(false);
  const [importMsg, setImportMsg] = useState('');
  const fileRef = useRef<HTMLInputElement>(null);

  const loadGroups = async () => {
    const res = await axios.get('/api/phishing/groups').catch(() => null);
    if (res) setGroups(res.data.groups || []);
  };
  useEffect(() => { loadGroups(); }, []);

  const loadGroup = async (g: TargetGroup) => {
    const res = await axios.get(`/api/phishing/groups/${g.id}`).catch(() => null);
    if (res) { setSelected(res.data.group); setTargets(res.data.group.targets || []); }
  };

  const createGroup = async () => {
    if (!newGroupName) return;
    await axios.post('/api/phishing/groups', { name: newGroupName }).catch(() => null);
    setNewGroupName(''); loadGroups();
  };

  const deleteGroup = async (id: number) => {
    await axios.delete(`/api/phishing/groups/${id}`).catch(() => null);
    if (selected?.id === id) setSelected(null);
    loadGroups();
  };

  const addTarget = async () => {
    if (!newTarget.email || !selected) return;
    setAddingTarget(true);
    await axios.post(`/api/phishing/groups/${selected.id}/targets`, newTarget).catch(() => null);
    setNewTarget({ first_name:'', last_name:'', email:'', position:'' });
    loadGroup(selected);
    setAddingTarget(false);
  };

  const deleteTargetRow = async (tid: number) => {
    if (!selected) return;
    await axios.delete(`/api/phishing/groups/${selected.id}/targets/${tid}`).catch(() => null);
    setTargets(prev => prev.filter(t => t.id !== tid));
  };

  const handleCSV = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !selected) return;
    e.target.value = '';
    setImporting(true); setImportMsg('');
    const text = await file.text();
    try {
      const res = await axios.post(`/api/phishing/groups/${selected.id}/import`, text, {
        headers: { 'Content-Type': 'text/plain' },
      });
      setImportMsg(`✓ Imported ${res.data.imported} targets.`);
      loadGroup(selected);
    } catch (err: any) {
      setImportMsg('✗ ' + (err.response?.data?.error || err.message));
    } finally { setImporting(false); }
  };

  if (selected) {
    return (
      <div>
        <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:12 }}>
          <button style={btn()} onClick={() => { setSelected(null); loadGroups(); }}>← Back</button>
          <strong>{selected.name}</strong>
          <span style={{ fontSize:12, color:'var(--text-dim)' }}>{targets.length} target{targets.length !== 1 ? 's' : ''}</span>
        </div>

        {/* Add target row */}
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1.5fr 1fr auto', gap:6, marginBottom:8 }}>
          {['first_name','last_name','email','position'].map(k => (
            <input key={k} style={inp} placeholder={k.replace('_',' ')}
              value={(newTarget as any)[k]}
              onChange={e => setNewTarget(p => ({ ...p, [k]: e.target.value }))} />
          ))}
          <button style={btn('primary')} onClick={addTarget} disabled={addingTarget}>Add</button>
        </div>

        <div style={{ display:'flex', gap:8, marginBottom:12, alignItems:'center' }}>
          <label style={{ ...btn(), display:'inline-flex', alignItems:'center', cursor:'pointer' }}>
            {importing ? 'Importing…' : 'Import CSV'}
            <input type="file" accept=".csv,.txt" ref={fileRef} style={{ display:'none' }} onChange={handleCSV} />
          </label>
          <span style={{ fontSize:11, color:'var(--text-dim)' }}>CSV format: first_name, last_name, email, position</span>
          {importMsg && <span style={{ fontSize:12, color: importMsg.startsWith('✓') ? '#66bb6a' : '#e57373' }}>{importMsg}</span>}
        </div>

        <table className="rp-table" style={{ fontSize:12 }}>
          <thead><tr><th>First</th><th>Last</th><th>Email</th><th>Position</th><th></th></tr></thead>
          <tbody>
            {targets.map(t => (
              <tr key={t.id}>
                <td>{t.first_name}</td>
                <td>{t.last_name}</td>
                <td className="rp-mono" style={{ fontSize:11 }}>{t.email}</td>
                <td>{t.position}</td>
                <td><button style={{ ...btn('danger'), padding:'2px 8px' }} onClick={() => deleteTargetRow(t.id)}>Remove</button></td>
              </tr>
            ))}
            {targets.length === 0 && <tr><td colSpan={5} style={{ textAlign:'center', color:'var(--text-dim)' }}>No targets yet.</td></tr>}
          </tbody>
        </table>
      </div>
    );
  }

  return (
    <div>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:12 }}>
        <strong>Users &amp; Groups</strong>
        <div style={{ display:'flex', gap:8 }}>
          <input style={{ ...inp, width:180 }} placeholder="New group name…" value={newGroupName} onChange={e => setNewGroupName(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') createGroup(); }} />
          <button style={btn('primary')} onClick={createGroup}>+ Create Group</button>
        </div>
      </div>
      <table className="rp-table" style={{ fontSize:12 }}>
        <thead><tr><th>Name</th><th>Created</th><th></th></tr></thead>
        <tbody>
          {groups.map(g => (
            <tr key={g.id}>
              <td style={{ cursor:'pointer', color:'var(--cyan)' }} onClick={() => loadGroup(g)}>{g.name}</td>
              <td style={{ fontSize:11, color:'var(--text-dim)' }}>{g.created_at?.slice(0,10) || ''}</td>
              <td style={{ display:'flex', gap:6 }}>
                <button style={{ ...btn(), padding:'2px 8px' }} onClick={() => loadGroup(g)}>Manage</button>
                <button style={{ ...btn('danger'), padding:'2px 8px' }} onClick={() => deleteGroup(g.id)}>Delete</button>
              </td>
            </tr>
          ))}
          {groups.length === 0 && <tr><td colSpan={3} style={{ textAlign:'center', color:'var(--text-dim)' }}>No groups yet.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

// ── Root PhishingPanel ────────────────────────────────────────────────────────

export default function PhishingPanel() {
  const [tab, setTab] = useState<Tab>('campaigns');
  const [smtpList, setSmtpList]     = useState<SMTPProfile[]>([]);
  const [templates, setTemplates]   = useState<EmailTemplate[]>([]);
  const [pages, setPages]           = useState<LandingPage[]>([]);
  const [groups, setGroups]         = useState<TargetGroup[]>([]);

  // Load reference data for the campaign creation form
  useEffect(() => {
    axios.get('/api/phishing/smtp').then(r => setSmtpList(r.data.profiles || [])).catch(() => {});
    axios.get('/api/phishing/templates').then(r => setTemplates(r.data.templates || [])).catch(() => {});
    axios.get('/api/phishing/pages').then(r => setPages(r.data.pages || [])).catch(() => {});
    axios.get('/api/phishing/groups').then(r => setGroups(r.data.groups || [])).catch(() => {});
  }, [tab]);

  const TABS: { id: Tab; label: string }[] = [
    { id: 'campaigns', label: 'Campaigns' },
    { id: 'templates', label: 'Email Templates' },
    { id: 'pages',     label: 'Landing Pages' },
    { id: 'smtp',      label: 'Sending Profiles' },
    { id: 'groups',    label: 'Users & Groups' },
  ];

  return (
    <div className="action-panel" style={{ padding:0, display:'flex', flexDirection:'column', minHeight:420 }}>
      {/* Sub-tab bar */}
      <div style={{ display:'flex', borderBottom:'1px solid var(--border-base)', background:'var(--bg-surface)', flexShrink:0 }}>
        {TABS.map(t => (
          <button key={t.id}
            onClick={() => setTab(t.id)}
            style={{
              padding:'8px 16px', border:'none', borderBottom: tab === t.id ? '2px solid var(--cyan)' : '2px solid transparent',
              background:'none', color: tab === t.id ? 'var(--cyan)' : 'var(--text-dim)',
              cursor:'pointer', fontSize:12, fontWeight: tab === t.id ? 600 : 400,
            }}>
            {t.label}
          </button>
        ))}
      </div>

      {/* Content area */}
      <div style={{ padding:20, flex:1, overflowY:'auto' }}>
        {tab === 'campaigns' && <CampaignsTab smtpList={smtpList} templates={templates} pages={pages} groups={groups} />}
        {tab === 'templates' && <TemplatesTab />}
        {tab === 'pages'     && <PagesTab />}
        {tab === 'smtp'      && <SMTPTab />}
        {tab === 'groups'    && <GroupsTab />}
      </div>
    </div>
  );
}
