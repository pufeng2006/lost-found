const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization'
};
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS }
  });
}
function bad(msg, status = 400) { return json({ error: msg }, status); }
function randomHex(bytes) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return [...a].map((x) => x.toString(16).padStart(2, '0')).join('');
}
function hexToBytes(hex) {
  const a = new Uint8Array(hex.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(hex.substr(i * 2, 2), 16);
  return a;
}
function toHex(buf) {
  return [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, '0')).join('');
}
async function hashText(text, saltHex) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(text), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: hexToBytes(saltHex), iterations: 10000, hash: 'SHA-256' },
    key, 256
  );
  return toHex(bits);
}
async function getUser(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '').trim();
  if (!token) return null;
  const row = await env.DB.prepare(
    'select u.id, u.account, u.nickname from sessions s join users u on u.id = s.user_id where s.token = ?'
  ).bind(token).first();
  return row || null;
}
async function newSession(env, userId) {
  const token = randomHex(32);
  await env.DB.prepare('insert into sessions(token, user_id, created_at) values(?,?,?)')
    .bind(token, userId, Date.now()).run();
  await env.DB.prepare('delete from sessions where created_at < ?')
    .bind(Date.now() - 30 * 86400000).run();
  return token;
}
async function isAdmin(env, account, password) {
  const a = await env.DB.prepare('select value from settings where key = ?').bind('admin_account').first();
  const p = await env.DB.prepare('select value from settings where key = ?').bind('admin_password').first();
  return !!(a && p && account === a.value && password === p.value);
}

export async function onRequest(context) {
  const request = context.request;
  const env = context.env;
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });
  const p = new URL(request.url).pathname.replace(/^\/api/, '');
  try {
    if (p === '/health') return json({ ok: true, time: new Date().toISOString() });

    if (p === '/register' && request.method === 'POST') {
      const b = await request.json();
      const account = String(b.account || '').trim().toLowerCase();
      const password = String(b.password || '');
      const nickname = String(b.nickname || '').trim().slice(0, 30);
      const question = String(b.question || '').trim().slice(0, 80);
      const answer = String(b.answer || '').trim().toLowerCase();

      if (!/^[a-z0-9_]{3,20}$/.test(account)) return bad('账号只能用 3-20 位字母、数字、下划线');
      if (password.length < 6) return bad('密码至少 6 位');
      if (!question || !answer) return bad('请填写密保问题和答案');

      const exists = await env.DB.prepare('select id from users where account = ?').bind(account).first();
      if (exists) return bad('这个账号已经被注册了，换一个吧', 409);

      const id = crypto.randomUUID();
      const salt = randomHex(16);
      const answerSalt = randomHex(16);
      const ph = await hashText(password, salt);
      const ah = await hashText(answer, answerSalt);

      await env.DB.prepare(
        `insert into users(id, account, nickname, password_hash, password_salt,
           question, answer_hash, answer_salt, created_at)
         values(?,?,?,?,?,?,?,?,?)`
      ).bind(id, account, nickname || ('同学' + account.slice(-4)), ph, salt, question, ah, answerSalt, Date.now()).run();

      const token = await newSession(env, id);
      return json({ token, user: { id, account, nickname } });
    }

    if (p === '/login' && request.method === 'POST') {
      const b = await request.json();
      const account = String(b.account || '').trim().toLowerCase();
      const password = String(b.password || '');
      const u = await env.DB.prepare('select * from users where account = ?').bind(account).first();
      if (!u) return bad('账号或密码不对', 401);
      const h = await hashText(password, u.password_salt);
      if (h !== u.password_hash) return bad('账号或密码不对', 401);
      const token = await newSession(env, u.id);
      return json({ token, user: { id: u.id, account: u.account, nickname: u.nickname } });
    }

    if (p === '/logout' && request.method === 'POST') {
      const token = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
      if (token) await env.DB.prepare('delete from sessions where token = ?').bind(token).run();
      return json({ ok: true });
    }

    if (p === '/me' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return bad('请先登录', 401);
      return json({ user });
    }

    if (p === '/items' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return bad('请先登录', 401);
      const rows = await env.DB.prepare(
        `select id, owner_id, owner_name, title, type, category, place, happened_on,
                description, image_url, claim_question, status, report_count, created_at
         from items where status <> 'hidden' order by created_at desc limit 300`
      ).all();
      const list = (rows.results || []).map((r) => ({
        id: r.id, ownerName: r.owner_name, title: r.title, type: r.type,
        category: r.category, place: r.place, time: r.happened_on,
        desc: r.description, image: r.image_url,
        claimQuestion: r.claim_question, needsAnswer: !!r.claim_question,
        isMine: r.owner_id === user.id, reports: r.report_count,
        status: r.status, createdAt: r.created_at
      }));
      return json(list);
    }

    if (p === '/items' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return bad('请先登录', 401);
      const b = await request.json();
      const title = String(b.title || '').trim().slice(0, 60);
      const contact = String(b.contact || '').trim().slice(0, 80);
      if (!title) return bad('请填写物品名称');
      if (!contact) return bad('请留下联系方式');

      const recent = await env.DB.prepare(
        'select count(*) as c from items where owner_id = ? and created_at > ?'
      ).bind(user.id, Date.now() - 600000).first();
      if (recent && recent.c >= 3) return bad('发布太频繁了，请 10 分钟后再发');

      const id = crypto.randomUUID();
      await env.DB.prepare(
        `insert into items(id, owner_id, owner_name, title, type, category, place,
           happened_on, description, contact, image_url, image_key, claim_question,
           claim_answer, status, report_count, created_at)
         values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'open',0,?)`
      ).bind(
        id, user.id, user.nickname || user.account, title,
        b.type === 'found' ? 'found' : 'lost',
        String(b.category || '其他').slice(0, 20),
        String(b.place || '').slice(0, 60),
        String(b.happenedOn || '').slice(0, 20),
        String(b.description || '').slice(0, 1000),
        contact,
        String(b.imageUrl || ''), String(b.imageKey || ''),
        String(b.claimQuestion || '').slice(0, 80),
        String(b.claimAnswer || '').slice(0, 40),
        Date.now()
      ).run();
      return json({ id });
    }

    const m = p.match(/^\/items\/([a-zA-Z0-9-]+)(\/[a-z]+)?$/);
    if (m) {
      const id = m[1];
      const action = m[2] || '';
      const user = await getUser(request, env);
      if (!user) return bad('请先登录', 401);
      const item = await env.DB.prepare('select * from items where id = ?').bind(id).first();
      if (!item) return bad('这条信息不存在', 404);

      if (!action && request.method === 'PATCH') {
        if (item.owner_id !== user.id) return bad('只有发布者本人才能修改', 403);
        const b = await request.json();
        await env.DB.prepare(
          `update items set title=?, category=?, place=?, happened_on=?, description=?,
             contact=?, image_url=?, image_key=? where id=?`
        ).bind(
          String(b.title || item.title).slice(0, 60),
          String(b.category || item.category).slice(0, 20),
          String(b.place || '').slice(0, 60),
          String(b.happenedOn || '').slice(0, 20),
          String(b.description || '').slice(0, 1000),
          String(b.contact || item.contact).slice(0, 80),
          b.imageUrl !== undefined ? String(b.imageUrl) : item.image_url,
          b.imageKey !== undefined ? String(b.imageKey) : item.image_key,
          id
        ).run();
        return json({ ok: true });
      }

      if (!action && request.method === 'DELETE') {
        if (item.owner_id !== user.id) return bad('只有发布者本人才能删除', 403);
        if (item.image_key) { try { await env.PHOTOS.delete(item.image_key); } catch (e) {} }
        await env.DB.prepare('delete from items where id = ?').bind(id).run();
        await env.DB.prepare('delete from reports where item_id = ?').bind(id).run();
        await env.DB.prepare('delete from claim_tries where item_id = ?').bind(id).run();
        return json({ ok: true });
      }

      if (action === '/status' && request.method === 'POST') {
        if (item.owner_id !== user.id) return bad('只有发布者本人才能修改', 403);
        const b = await request.json();
        await env.DB.prepare('update items set status = ? where id = ?')
          .bind(b.status === 'done' ? 'done' : 'open', id).run();
        return json({ ok: true });
      }

      if (action === '/claim' && request.method === 'POST') {
        if (item.status !== 'open') return json({ ok: false, msg: '这条已经处理完了' });
        const b = await request.json();
        const tries = await env.DB.prepare(
          'select count(*) as c from claim_tries where item_id=? and user_id=? and ok=0 and created_at>?'
        ).bind(id, user.id, Date.now() - 600000).first();
        if (tries && tries.c >= 5) return json({ ok: false, msg: '答案已经错了 5 次，请 10 分钟后再试' });

        if (item.claim_question) {
          const ans = String(b.answer || '').trim().toLowerCase();
          if (ans !== String(item.claim_answer || '').trim().toLowerCase()) {
            await env.DB.prepare('insert into claim_tries(item_id,user_id,ok,created_at) values(?,?,0,?)')
              .bind(id, user.id, Date.now()).run();
            return json({ ok: false, msg: '答案不对，再想一想' });
          }
        }
        await env.DB.prepare('insert into claim_tries(item_id,user_id,ok,created_at) values(?,?,1,?)')
          .bind(id, user.id, Date.now()).run();
        return json({ ok: true, contact: item.contact });
      }

      if (action === '/report' && request.method === 'POST') {
        await env.DB.prepare('insert or ignore into reports(item_id,user_id,created_at) values(?,?,?)')
          .bind(id, user.id, Date.now()).run();
        const cnt = await env.DB.prepare('select count(*) as c from reports where item_id=?').bind(id).first();
        await env.DB.prepare('update items set report_count=? where id=?').bind(cnt.c, id).run();
        if (cnt.c >= 3) {
          await env.DB.prepare("update items set status='hidden' where id=? and status='open'").bind(id).run();
        }
        return json({ ok: true });
      }

      return bad('不支持的操作', 405);
    }

    if (p === '/admin/check' && request.method === 'POST') {
      const b = await request.json();
      return json({ ok: await isAdmin(env, String(b.account || ''), String(b.password || '')) });
    }

    if (p === '/admin/reports' && request.method === 'POST') {
      const b = await request.json();
      if (!(await isAdmin(env, String(b.account || ''), String(b.password || '')))) return bad('管理员账号或密码不对', 403);
      const rows = await env.DB.prepare(
        `select id, title, owner_name, report_count, status, image_url, image_key
         from items where report_count > 0 order by report_count desc, created_at desc limit 100`
      ).all();
      return json(rows.results || []);
    }

    if (p === '/admin/delete' && request.method === 'POST') {
      const b = await request.json();
      if (!(await isAdmin(env, String(b.account || ''), String(b.password || '')))) return bad('管理员账号或密码不对', 403);
      const item = await env.DB.prepare('select * from items where id=?').bind(String(b.id || '')).first();
      if (!item) return bad('找不到这条信息', 404);
      if (item.image_key) { try { await env.PHOTOS.delete(item.image_key); } catch (e) {} }
      await env.DB.prepare('delete from items where id=?').bind(item.id).run();
      await env.DB.prepare('delete from reports where item_id=?').bind(item.id).run();
      await env.DB.prepare('delete from claim_tries where item_id=?').bind(item.id).run();
      return json({ ok: true });
    }

    if (p === '/admin/clear-reports' && request.method === 'POST') {
      const b = await request.json();
      if (!(await isAdmin(env, String(b.account || ''), String(b.password || '')))) return bad('管理员账号或密码不对', 403);
      await env.DB.prepare('delete from reports where item_id=?').bind(String(b.id || '')).run();
      await env.DB.prepare(
        "update items set report_count=0, status = case when status='hidden' then 'open' else status end where id=?"
      ).bind(String(b.id || '')).run();
      return json({ ok: true });
    }

    if (p === '/password/question' && request.method === 'POST') {
      const b = await request.json();
      const account = String(b.account || '').trim().toLowerCase();
      const u = await env.DB.prepare('select question from users where account=?').bind(account).first();
      return json({ question: u ? u.question : '' });
    }

    if (p === '/password/reset' && request.method === 'POST') {
      const b = await request.json();
      const account = String(b.account || '').trim().toLowerCase();
      const answer = String(b.answer || '').trim().toLowerCase();
      const np = String(b.newPassword || '');
      if (np.length < 6) return json({ ok: false, msg: '新密码至少 6 位' });

      const fails = await env.DB.prepare(
        'select count(*) as c from reset_tries where account=? and ok=0 and created_at>?'
      ).bind(account, Date.now() - 600000).first();
      if (fails && fails.c >= 5) return json({ ok: false, msg: '尝试次数太多，请 10 分钟后再试' });

      const u = await env.DB.prepare('select * from users where account=?').bind(account).first();
      if (!u) {
        await env.DB.prepare('insert into reset_tries(account,ok,created_at) values(?,0,?)').bind(account, Date.now()).run();
        return json({ ok: false, msg: '账号不存在，或没有设置密保问题' });
      }
      const h = await hashText(answer, u.answer_salt);
      if (h !== u.answer_hash) {
        await env.DB.prepare('insert into reset_tries(account,ok,created_at) values(?,0,?)').bind(account, Date.now()).run();
        return json({ ok: false, msg: '密保答案不对' });
      }

      const salt = randomHex(16);
      const ph = await hashText(np, salt);
      await env.DB.prepare('update users set password_hash=?, password_salt=? where id=?').bind(ph, salt, u.id).run();
      await env.DB.prepare('delete from sessions where user_id=?').bind(u.id).run();
      await env.DB.prepare('insert into reset_tries(account,ok,created_at) values(?,1,?)').bind(account, Date.now()).run();
      return json({ ok: true, msg: '密码已重置' });
    }

    if (p === '/upload' && request.method === 'POST') {
      const user = await getUser(request, env);
      if (!user) return bad('请先登录', 401);
      const form = await request.formData();
      const file = form.get('file');
      if (!file) return bad('没有文件');
      const ext = (file.name || 'photo.jpg').split('.').pop().toLowerCase().replace(/[^a-z0-9]/g, '') || 'jpg';
      const key = Date.now().toString(36) + '-' + randomHex(8) + '.' + ext;
      await env.PHOTOS.put(key, await file.arrayBuffer(), {
        httpMetadata: {
          contentType: file.type || 'image/jpeg',
          cacheControl: 'public, max-age=31536000'
        }
      });
      return json({ url: env.R2_PUBLIC.replace(/\/$/, '') + '/' + key, key });
    }

    return bad('接口不存在', 404);
  } catch (e) {
    return json({ error: e.message || '服务器错误' }, 500);
  }
}
