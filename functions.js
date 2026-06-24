import { hash, compare } from 'bcrypt';
import { SignJWT, jwtVerify } from 'jose';
import { TOTP } from 'otpauth';

// 全局配置
const JWT_SECRET = new TextEncoder().encode('LinkJsonMgr_Secret_20260624_EdgeOne_888888');
const JWT_EXPIRE = 86400;
const DEFAULT_USER_MAX_LINK = 2;
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization'
};

// 通用工具函数
function genEmailCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}
function genTOTPSecret() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let s = '';
  for (let i = 0; i < 16; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}
async function sendEmailCode(email, code, env) {
  console.log(`模拟邮件 ${email} 验证码:${code}`);
  await env.emailCode.put(email, JSON.stringify({ code, exp: Date.now() + 300000 }), { expirationTtl: 300 });
}
async function createToken(user) {
  return new SignJWT({
    uid: user.uid,
    email: user.email,
    isSuper: user.isSuper,
    emailVerified: user.emailVerified,
    maxLinkCount: user.maxLinkCount ?? DEFAULT_USER_MAX_LINK
  })
    .setIssuedAt()
    .setExpirationTime(`${JWT_EXPIRE}s`)
    .sign(JWT_SECRET);
}
async function verifyToken(token) {
  try {
    const { payload } = await jwtVerify(token, JWT_SECRET);
    return payload;
  } catch { return null; }
}
async function getUserLinkCount(uid, env) {
  let count = 0;
  const list = await env.link.list();
  for (const k of list.keys) {
    const d = JSON.parse(await env.link.get(k.name));
    if (d.ownerUid === uid) count++;
  }
  return count;
}

// 统一入口路由分发
export async function onRequest({ request, params, env }) {
  // 跨域预检
  if (request.method === 'OPTIONS') return new Response(null, { headers: corsHeaders });
  const url = new URL(request.url);
  const path = params.path || '';
  const pathArr = path.split('/');

  // ==================== 1. 注册 /register ====================
  if (path === 'register' && request.method === 'POST') {
    try {
      const { email, password } = await request.json();
      if (!email || !password) return Response.json({ code: 400, msg: '邮箱密码不能为空' }, { headers: corsHeaders });
      if (await env.user.get(email)) return Response.json({ code: 400, msg: '邮箱已注册' }, { headers: corsHeaders });
      const uid = Date.now().toString();
      const userData = { uid, email, pwdHash: await hash(password, 10), isSuper: false, emailVerified: false, totpSecret: null, totpTmp: null, maxLinkCount: DEFAULT_USER_MAX_LINK };
      await env.user.put(email, JSON.stringify(userData));
      await sendEmailCode(email, genEmailCode(), env);
      return Response.json({ code: 200, msg: '注册成功，请查收验证码' }, { headers: corsHeaders });
    } catch (e) { return Response.json({ code: 500, msg: e.message }, { headers: corsHeaders }); }
  }

  // ==================== 2. 登录 /login ====================
  if (path === 'login' && request.method === 'POST') {
    try {
      const { email, password, totpCode } = await request.json();
      const userRaw = await env.user.get(email);
      if (!userRaw) return Response.json({ code: 401, msg: '账号不存在' }, { headers: corsHeaders });
      const user = JSON.parse(userRaw);
      if (!await compare(password, user.pwdHash)) return Response.json({ code: 401, msg: '密码错误' }, { headers: corsHeaders });
      if (user.totpSecret) {
        if (!totpCode) return Response.json({ code: 402, msg: '请输入2FA验证码', needTotp: true }, { headers: corsHeaders });
        if (new TOTP({ secret: user.totpSecret }).validate({ token: totpCode, window: 1 }) === null) return Response.json({ code: 401, msg: '2FA验证码错误' }, { headers: corsHeaders });
      }
      const token = await createToken(user);
      return Response.json({ code: 200, token, user: { email: user.email, uid: user.uid, isSuper: user.isSuper, emailVerified: user.emailVerified, hasTotp: !!user.totpSecret, maxLinkCount: user.maxLinkCount } }, { headers: corsHeaders });
    } catch (e) { return Response.json({ code: 500, msg: e.message }, { headers: corsHeaders }); }
  }

  // ==================== 3. 重发验证码 /sendCode ====================
  if (path === 'sendCode' && request.method === 'POST') {
    try {
      const { email } = await request.json();
      if (!await env.user.get(email)) return Response.json({ code: 404, msg: '用户不存在' }, { headers: corsHeaders });
      await sendEmailCode(email, genEmailCode(), env);
      return Response.json({ code: 200, msg: '验证码已发送' }, { headers: corsHeaders });
    } catch (e) { return Response.json({ code: 500, msg: e.message }, { headers: corsHeaders }); }
  }

  // ==================== 4. 邮箱验证 /verifyEmail ====================
  if (path === 'verifyEmail' && request.method === 'POST') {
    try {
      const { email, code } = await request.json();
      const cacheRaw = await env.emailCode.get(email);
      if (!cacheRaw) return Response.json({ code: 400, msg: '验证码过期' }, { headers: corsHeaders });
      const cache = JSON.parse(cacheRaw);
      if (cache.code !== code) return Response.json({ code: 400, msg: '验证码错误' }, { headers: corsHeaders });
      const user = JSON.parse(await env.user.get(email));
      user.emailVerified = true;
      await env.user.put(email, JSON.stringify(user));
      return Response.json({ code: 200, msg: '邮箱验证完成' }, { headers: corsHeaders });
    } catch (e) { return Response.json({ code: 500, msg: e.message }, { headers: corsHeaders }); }
  }

  // ==================== 5. 获取2FA密钥 /getTotpInit ====================
  if (path === 'getTotpInit' && request.method === 'GET') {
    try {
      const auth = request.headers.get('Authorization') || '';
      const token = auth.replace('Bearer ', '');
      const payload = await verifyToken(token);
      if (!payload) return Response.json({ code: 401, msg: '未登录' }, { headers: corsHeaders });
      const user = JSON.parse(await env.user.get(payload.email));
      const secret = genTOTPSecret();
      user.totpTmp = secret;
      await env.user.put(payload.email, JSON.stringify(user));
      const otpUrl = new TOTP({ issuer: 'LinkJSON管理系统', label: payload.email, secret }).toString();
      return Response.json({ code: 200, secret, otpUrl }, { headers: corsHeaders });
    } catch (e) { return Response.json({ code: 500, msg: e.message }, { headers: corsHeaders }); }
  }

  // ==================== 6. 绑定2FA /bindTotp ====================
  if (path === 'bindTotp' && request.method === 'POST') {
    try {
      const auth = request.headers.get('Authorization') || '';
      const token = auth.replace('Bearer ', '');
      const payload = await verifyToken(token);
      if (!payload) return Response.json({ code: 401, msg: '未登录' }, { headers: corsHeaders });
      const { verifyCode } = await request.json();
      const user = JSON.parse(await env.user.get(payload.email));
      if (!user.totpTmp) return Response.json({ code: 400, msg: '未初始化2FA' }, { headers: corsHeaders });
      if (new TOTP({ secret: user.totpTmp }).validate({ token: verifyCode, window: 1 }) === null) return Response.json({ code: 400, msg: '验证码错误' }, { headers: corsHeaders });
      user.totpSecret = user.totpTmp;
      delete user.totpTmp;
      await env.user.put(payload.email, JSON.stringify(user));
      return Response.json({ code: 200, msg: '2FA绑定成功' }, { headers: corsHeaders });
    } catch (e) { return Response.json({ code: 500, msg: e.message }, { headers: corsHeaders }); }
  }

  // ==================== 7. 超管获取全部用户 /allUsers ====================
  if (path === 'allUsers' && request.method === 'GET') {
    try {
      const auth = request.headers.get('Authorization') || '';
      const token = auth.replace('Bearer ', '');
      const payload = await verifyToken(token);
      if (!payload || !payload.isSuper) return Response.json({ code: 403, msg: '仅超管访问' }, { headers: corsHeaders });
      const list = [];
      const userList = await env.user.list();
      for (const k of userList.keys) {
        const u = JSON.parse(await env.user.get(k.name));
        list.push({ email: u.email, uid: u.uid, isSuper: u.isSuper, emailVerified: u.emailVerified, hasTotp: !!u.totpSecret, maxLinkCount: u.maxLinkCount });
      }
      return Response.json({ code: 200, data: list }, { headers: corsHeaders });
    } catch (e) { return Response.json({ code: 500, msg: e.message }, { headers: corsHeaders }); }
  }

  // ==================== 8. 修改用户链接配额 /setUserMaxLink ====================
  if (path === 'setUserMaxLink' && request.method === 'POST') {
    try {
      const auth = request.headers.get('Authorization') || '';
      const token = auth.replace('Bearer ', '');
      const payload = await verifyToken(token);
      if (!payload || !payload.isSuper) return Response.json({ code: 403, msg: '仅超管访问' }, { headers: corsHeaders });
      const { targetEmail, newMax } = await request.json();
      const num = parseInt(newMax);
      if (isNaN(num) || num < 0) return Response.json({ code: 400, msg: '配额必须非负数字' }, { headers: corsHeaders });
      const userRaw = await env.user.get(targetEmail);
      if (!userRaw) return Response.json({ code: 404, msg: '用户不存在' }, { headers: corsHeaders });
      const user = JSON.parse(userRaw);
      user.maxLinkCount = num;
      await env.user.put(targetEmail, JSON.stringify(user));
      return Response.json({ code: 200, msg: '配额修改成功' }, { headers: corsHeaders });
    } catch (e) { return Response.json({ code: 500, msg: e.message }, { headers: corsHeaders }); }
  }

  // ==================== 9. 保存链接 /linkSave ====================
  if (path === 'linkSave' && request.method === 'POST') {
    try {
      const auth = request.headers.get('Authorization') || '';
      const token = auth.replace('Bearer ', '');
      const payload = await verifyToken(token);
      if (!payload) return Response.json({ code: 401, msg: '未登录' }, { headers: corsHeaders });
      if (!payload.emailVerified) return Response.json({ code: 403, msg: '请先验证邮箱' }, { headers: corsHeaders });
      const { linkId, pathName, accessPwd, jsonData } = await request.json();
      if (!pathName || !accessPwd || !jsonData) return Response.json({ code: 400, msg: '参数不全' }, { headers: corsHeaders });
      JSON.parse(jsonData);
      if (!payload.isSuper && !linkId) {
        const curr = await getUserLinkCount(payload.uid, env);
        const max = payload.maxLinkCount ?? DEFAULT_USER_MAX_LINK;
        if (curr >= max) return Response.json({ code: 403, msg: `上限${max}条，无法新增` }, { headers: corsHeaders });
      }
      const linkKey = `link_${pathName}`;
      const linkInfo = { linkId: linkId || Date.now().toString(), ownerUid: payload.uid, ownerEmail: payload.email, pathName, accessPwdHash: await hash(accessPwd, 8), jsonData };
      await env.link.put(linkKey, JSON.stringify(linkInfo));
      return Response.json({ code: 200, msg: '保存成功' }, { headers: corsHeaders });
    } catch (e) { return Response.json({ code: 500, msg: e.message }, { headers: corsHeaders }); }
  }

  // ==================== 10. 删除链接 /linkDel ====================
  if (path === 'linkDel' && request.method === 'POST') {
    try {
      const auth = request.headers.get('Authorization') || '';
      const token = auth.replace('Bearer ', '');
      const payload = await verifyToken(token);
      if (!payload) return Response.json({ code: 401, msg: '未登录' }, { headers: corsHeaders });
      const { pathName } = await request.json();
      const linkKey = `link_${pathName}`;
      const raw = await env.link.get(linkKey);
      if (!raw) return Response.json({ code: 404, msg: '链接不存在' }, { headers: corsHeaders });
      const link = JSON.parse(raw);
      if (link.ownerUid !== payload.uid && !payload.isSuper) return Response.json({ code: 403, msg: '无权删除' }, { headers: corsHeaders });
      await env.link.delete(linkKey);
      return Response.json({ code: 200, msg: '删除成功' }, { headers: corsHeaders });
    } catch (e) { return Response.json({ code: 500, msg: e.message }, { headers: corsHeaders }); }
  }

  // ==================== 11. 获取我的链接列表 /myList ====================
  if (path === 'myList' && request.method === 'GET') {
    try {
      const auth = request.headers.get('Authorization') || '';
      const token = auth.replace('Bearer ', '');
      const payload = await verifyToken(token);
      if (!payload) return Response.json({ code: 401, msg: '未登录' }, { headers: corsHeaders });
      if (!payload.emailVerified) return Response.json({ code: 403, msg: '请验证邮箱' }, { headers: corsHeaders });
      const res = [];
      const all = await env.link.list();
      for (const k of all.keys) {
        const d = JSON.parse(await env.link.get(k.name));
        if (d.ownerUid === payload.uid || payload.isSuper) res.push(d);
      }
      return Response.json({ code: 200, data: res, maxLinkCount: payload.maxLinkCount, isSuper: payload.isSuper }, { headers: corsHeaders });
    } catch (e) { return Response.json({ code: 500, msg: e.message }, { headers: corsHeaders }); }
  }

  // ==================== 12. 公开JSON接口 /out/xxx ====================
  if (pathArr[0] === 'out' && pathArr.length >= 2) {
    try {
      const pathName = pathArr.slice(1).join('/');
      const inputPwd = url.searchParams.get('pwd') || '';
      const linkKey = `link_${pathName}`;
      const raw = await env.link.get(linkKey);
      if (!raw) return Response.json({ code: 404, msg: '链接不存在' }, { status: 404, headers: corsHeaders });
      const link = JSON.parse(raw);
      const ok = await compare(inputPwd, link.accessPwdHash);
      if (!ok) return Response.json({ code: 403, msg: '密码错误' }, { status: 403, headers: corsHeaders });
      const jsonObj = JSON.parse(link.jsonData);
      return Response.json(jsonObj, { headers: { 'Content-Type': 'application/json' } });
    } catch (e) { return Response.json({ code: 500, msg: '读取异常' }, { status: 500, headers: corsHeaders }); }
  }

  // 无匹配路由
  return Response.json({ code: 404, msg: '接口不存在' }, { status: 404, headers: corsHeaders });
}