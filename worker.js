import { hash, compare } from 'bcrypt';
import { SignJWT, jwtVerify } from 'jose';
import { TOTP } from 'otpauth';

// 全局配置
const JWT_SECRET = new TextEncoder().encode('LinkJsonMgr_Secret_20260624_EdgeOne_888888');
const JWT_EXPIRE = 86400;
const DEFAULT_USER_MAX_LINK = 2;

// KV 命名空间绑定（EdgeOne后台创建3个KV：user、link、emailCode）
const KV_USER = EDGEONE_KV_NAMESPACE.user;
const KV_LINK = EDGEONE_KV_NAMESPACE.link;
const KV_EMAIL_CODE = EDGEONE_KV_NAMESPACE.emailCode;

// 生成6位数字验证码
function genEmailCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// 生成TOTP16位密钥
function genTOTPSecret() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let s = '';
  for (let i = 0; i < 16; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}

// 模拟发送邮箱验证码（生产替换企业邮件/腾讯云邮件API）
async function sendEmailCode(email, code) {
  console.log(`邮件发送模拟：${email}，验证码：${code}`);
  const cacheData = JSON.stringify({ code, exp: Date.now() + 300000 });
  await KV_EMAIL_CODE.put(email, cacheData, { expirationTtl: 300 });
}

// JWT 签发
async function createToken(user) {
  return await new SignJWT({
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

// JWT 校验
async function verifyToken(token) {
  try {
    const { payload } = await jwtVerify(token, JWT_SECRET);
    return payload;
  } catch (err)
    return null;
  }
}

// 统计用户已有链接数量
async function getUserLinkCount(ownerUid) {
  let count = 0;
  const list = await KV_LINK.list();
  for (const item of list.keys) {
    const raw = await KV_LINK.get(item.name);
    const data = JSON.parse(raw);
    if (data.ownerUid === ownerUid) count++;
  }
  return count;
}

// 主入口分发
export default async function handler(event) {
  const req = event.request;
  const url = new URL(req.url);
  const path = url.pathname;
  const method = req.method;

  // 跨域统一头
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization'
  };

  // 预检OPTIONS直接放行
  if (method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  // 1. 用户注册 POST /api/auth/register
  if (path === '/api/auth/register' && method === 'POST') {
    try {
      const { email, password } = await req.json();
      if (!email || !password || email.trim() === '' || password.trim() === '') {
        return Response.json({ code: 400, msg: '邮箱和密码不能为空' }, { headers: corsHeaders });
      }
      const existRaw = await KV_USER.get(email);
      if (existRaw) {
        return Response.json({ code: 400, msg: '该邮箱已注册' }, { headers: corsHeaders });
      }
      const uid = Date.now().toString();
      const pwdHash = await hash(password, 10);
      const userData = {
        uid,
        email,
        pwdHash,
        isSuper: false,
        emailVerified: false,
        totpSecret: null,
        totpTmp: null,
        maxLinkCount: DEFAULT_USER_MAX_LINK
      };
      await KV_USER.put(email, JSON.stringify(userData));
      const code = genEmailCode();
      await sendEmailCode(email, code);
      return Response.json({ code: 200, msg: '注册成功，请收取邮箱验证码完成验证' }, { headers: corsHeaders });
    } catch (e) {
      return Response.json({ code: 500, msg: '注册失败：' + e.message }, { headers: corsHeaders });
    }
  }

  // 2. 重发邮箱验证码 POST /api/auth/sendCode
  if (path === '/api/auth/sendCode' && method === 'POST') {
    try {
      const { email } = await req.json();
      const userRaw = await KV_USER.get(email);
      if (!userRaw) return Response.json({ code: 404, msg: '用户不存在' }, { headers: corsHeaders });
      const code = genEmailCode();
      await sendEmailCode(email, code);
      return Response.json({ code: 200, msg: '验证码已发送（有效期5分钟）' }, { headers: corsHeaders });
    } catch (e) {
      return Response.json({ code: 500, msg: '发送失败：' + e.message }, { headers: corsHeaders });
    }
  }

  // 3. 邮箱验证 POST /api/auth/verifyEmail
  if (path === '/api/auth/verifyEmail' && method === 'POST') {
    try {
      const { email, code } = await req.json();
      const cacheRaw = await KV_EMAIL_CODE.get(email);
      if (!cacheRaw) return Response.json({ code: 400, msg: '验证码已过期，请重新发送' }, { headers: corsHeaders });
      const cache = JSON.parse(cacheRaw);
      if (cache.code !== code) return Response.json({ code: 400, msg: '验证码错误' }, { headers: corsHeaders });
      const userRaw = await KV_USER.get(email);
      const user = JSON.parse(userRaw);
      user.emailVerified = true;
      await KV_USER.put(email, JSON.stringify(user));
      return Response.json({ code: 200, msg: '邮箱验证完成，全部功能解锁' }, { headers: corsHeaders });
    } catch (e) {
      return Response.json({ code: 500, msg: '验证失败：' + e.message }, { headers: corsHeaders });
    }
  }

  // 4. 用户登录 POST /api/auth/login
  if (path === '/api/auth/login' && method === 'POST') {
    try {
      const { email, password, totpCode } = await req.json();
      const userRaw = await KV_USER.get(email);
      if (!userRaw) return Response.json({ code: 401, msg: '账号不存在' }, { headers: corsHeaders });
      const user = JSON.parse(userRaw);
      const passOk = await compare(password, user.pwdHash);
      if (!passOk) return Response.json({ code: 401, msg: '密码错误' }, { headers: corsHeaders });
      // 判断是否需要2FA
      if (user.totpSecret) {
        if (!totpCode || totpCode.trim() === '') {
          return Response.json({ code: 402, msg: '请输入2FA验证码', needTotp: true }, { headers: corsHeaders });
        }
        const totp = new TOTP({ secret: user.totpSecret });
        const valid = totp.validate({ token: totpCode, window: 1 });
        if (valid === null) return Response.json({ code: 401, msg: '2FA验证码错误' }, { headers: corsHeaders });
      }
      const token = await createToken(user);
      return Response.json({
        code: 200,
        token,
        user: {
          email: user.email,
          uid: user.uid,
          isSuper: user.isSuper,
          emailVerified: user.emailVerified,
          hasTotp: !!user.totpSecret,
          maxLinkCount: user.maxLinkCount ?? DEFAULT_USER_MAX_LINK
        }
      }, { headers: corsHeaders });
    } catch (e) {
      return Response.json({ code: 500, msg: '登录异常：' + e.message }, { headers: corsHeaders });
    }
  }

  // 5. 获取2FA初始化密钥 GET /api/auth/getTotpInit
  if (path === '/api/auth/getTotpInit' && method === 'GET') {
    try {
      const authHeader = req.headers.get('Authorization') || '';
      const tokenStr = authHeader.replace('Bearer ', '');
      const payload = await verifyToken(tokenStr);
      if (!payload) return Response.json({ code: 401, msg: '未登录' }, { headers: corsHeaders });
      const userRaw = await KV_USER.get(payload.email);
      const user = JSON.parse(userRaw);
      const secret = genTOTPSecret();
      user.totpTmp = secret;
      await KV_USER.put(payload.email, JSON.stringify(user));
      const otpUrl = new TOTP({
        issuer: 'LinkJSON管理系统',
        label: payload.email,
        secret
      }).toString();
      return Response.json({ code: 200, secret, otpUrl }, { headers: corsHeaders });
    } catch (e) {
      return Response.json({ code: 500, msg: '获取2FA密钥失败：' + e.message }, { headers: corsHeaders });
    }
  }

  // 6. 绑定2FA POST /api/auth/bindTotp
  if (path === '/api/auth/bindTotp' && method === 'POST') {
    try {
      const authHeader = req.headers.get('Authorization') || '';
      const tokenStr = authHeader.replace('Bearer ', '');
      const payload = await verifyToken(tokenStr);
      if (!payload) return Response.json({ code: 401, msg: '未登录' }, { headers: corsHeaders });
      const { verifyCode } = await req.json();
      const userRaw = await KV_USER.get(payload.email);
      const user = JSON.parse(userRaw);
      if (!user.totpTmp) return Response.json({ code: 400, msg: '未初始化2FA' }, { headers: corsHeaders });
      const totp = new TOTP({ secret: user.totpTmp });
      const valid = totp.validate({ token: verifyCode, window: 1 });
      if (valid === null) return Response.json({ code: 400, msg: '验证码校验失败' }, { headers: corsHeaders });
      user.totpSecret = user.totpTmp;
      user.totpTmp = null;
      await KV_USER.put(payload.email, JSON.stringify(user));
      return Response.json({ code: 200, msg: '2FA绑定成功' }, { headers: corsHeaders });
    } catch (e) {
      return Response.json({ code: 500, msg: '绑定失败：' + e.message }, { headers: corsHeaders });
    }
  }

  // 7. 超级管理员获取全部用户 GET /api/admin/allUsers
  if (path === '/api/admin/allUsers' && method === 'GET') {
    try {
      const authHeader = req.headers.get('Authorization') || '';
      const tokenStr = authHeader.replace('Bearer ', '');
      const payload = await verifyToken(tokenStr);
      if (!payload || !payload.isSuper) return Response.json({ code: 403, msg: '仅超级管理员访问' }, { headers: corsHeaders });
      const list = [];
      const userList = await KV_USER.list();
      for (const item of userList.keys) {
        const uRaw = await KV_USER.get(item.name);
        const u = JSON.parse(uRaw);
        list.push({
          email: u.email,
          uid: u.uid,
          isSuper: u.isSuper,
          emailVerified: u.emailVerified,
          hasTotp: !!u.totpSecret,
          maxLinkCount: u.maxLinkCount ?? DEFAULT_USER_MAX_LINK
        });
      }
      return Response.json({ code: 200, data: list }, { headers: corsHeaders });
    } catch (e) {
      return Response.json({ code: 500, msg: '获取用户列表失败：' + e.message }, { headers: corsHeaders });
    }
  }

  // 8. 管理员修改用户链接配额 POST /api/admin/setUserMaxLink
  if (path === '/api/admin/setUserMaxLink' && method === 'POST') {
    try {
      const authHeader = req.headers.get('Authorization') || '';
      const tokenStr = authHeader.replace('Bearer ', '');
      const payload = await verifyToken(tokenStr);
      if (!payload || !payload.isSuper) return Response.json({ code: 403, msg: '仅超级管理员访问' }, { headers: corsHeaders });
      const { targetEmail, newMax } = await req.json();
      const num = parseInt(newMax);
      if (isNaN(num) || num < 0) return Response.json({ code: 400, msg: '配额必须是非负数字' }, { headers: corsHeaders });
      const userRaw = await KV_USER.get(targetEmail);
      if (!userRaw) return Response.json({ code: 404, msg: '目标用户不存在' }, { headers: corsHeaders });
      const user = JSON.parse(userRaw);
      user.maxLinkCount = num;
      await KV_USER.put(targetEmail, JSON.stringify(user));
      return Response.json({ code: 200, msg: '用户链接配额修改成功' }, { headers: corsHeaders });
    } catch (e) {
      return Response.json({ code: 500, msg: '修改配额失败：' + e.message }, { headers: corsHeaders });
    }
  }

  // 9. 保存/编辑链接 POST /api/link/save
  if (path === '/api/link/save' && method === 'POST') {
    try {
      const authHeader = req.headers.get('Authorization') || '';
      const tokenStr = authHeader.replace('Bearer ', '');
      const payload = await verifyToken(tokenStr);
      if (!payload) return Response.json({ code: 401, msg: '未登录' }, { headers: corsHeaders });
      if (!payload.emailVerified) return Response.json({ code: 403, msg: '请先完成邮箱验证' }, { headers: corsHeaders });
      const { linkId, pathName, accessPwd, jsonData } = await req.json();
      if (!pathName || !accessPwd || !jsonData) return Response.json({ code: 400, msg: '路径、密码、JSON内容不能为空' }, { headers: corsHeaders });
      JSON.parse(jsonData);
      // 普通用户新建校验数量
      if (!payload.isSuper && !linkId) {
        const currCount = await getUserLinkCount(payload.uid);
        const max = payload.maxLinkCount ?? DEFAULT_USER_MAX_LINK;
        if (currCount >= max) {
          return Response.json({ code: 403, msg: `链接上限${max}条，无法新增，请联系管理员提升配额` }, { headers: corsHeaders });
        }
      }
      const linkKey = `link_${pathName}`;
      const linkInfo = {
        linkId: linkId || Date.now().toString(),
        ownerUid: payload.uid,
        ownerEmail: payload.email,
        pathName,
        accessPwdHash: await hash(accessPwd, 8),
        jsonData
      };
      await KV_LINK.put(linkKey, JSON.stringify(linkInfo));
      return Response.json({ code: 200, msg: '链接保存成功' }, { headers: corsHeaders });
    } catch (e) {
      return Response.json({ code: 500, msg: '保存链接失败：' + e.message }, { headers: corsHeaders });
    }
  }

  // 10. 删除链接 POST /api/link/del
  if (path === '/api/link/del' && method === 'POST') {
    try {
      const authHeader = req.headers.get('Authorization') || '';
      const tokenStr = authHeader.replace('Bearer ', '');
      const payload = await verifyToken(tokenStr);
      if (!payload) return Response.json({ code: 401, msg: '未登录' }, { headers: corsHeaders });
      const { pathName } = await req.json();
      const linkKey = `link_${pathName}`;
      const raw = await KV_LINK.get(linkKey);
      if (!raw) return Response.json({ code: 404, msg: '链接不存在' }, { headers: corsHeaders });
      const link = JSON.parse(raw);
      // 仅所有者或超管可删
      if (link.ownerUid !== payload.uid && !payload.isSuper) {
        return Response.json({ code: 403, msg: '无权删除他人链接' }, { headers: corsHeaders });
      }
      await KV_LINK.delete(linkKey);
      return Response.json({ code: 200, msg: '链接已删除' }, { headers: corsHeaders });
    } catch (e) {
      return Response.json({ code: 500, msg: '删除失败：' + e.message }, { headers: corsHeaders });
    }
  }

  // 11. 获取我的链接列表 GET /api/link/myList
  if (path === '/api/link/myList' && method === 'GET') {
    try {
      const authHeader = req.headers.get('Authorization') || '';
      const tokenStr = authHeader.replace('Bearer ', '');
      const payload = await verifyToken(tokenStr);
      if (!payload) return Response.json({ code: 401, msg: '未登录' }, { headers: corsHeaders });
      if (!payload.emailVerified) return Response.json({ code: 403, msg: '请先完成邮箱验证' }, { headers: corsHeaders });
      const result = [];
      const allLinks = await KV_LINK.list();
      for (const item of allLinks.keys) {
        const raw = await KV_LINK.get(item.name);
        const data = JSON.parse(raw);
        if (data.ownerUid === payload.uid || payload.isSuper) {
          result.push(data);
        }
      }
      return Response.json({
        code: 200,
        data: result,
        maxLinkCount: payload.maxLinkCount ?? DEFAULT_USER_MAX_LINK,
        isSuper: payload.isSuper
      }, { headers: corsHeaders });
    } catch (e) {
      return Response.json({ code: 500, msg: '获取链接列表失败：' + e.message }, { headers: corsHeaders });
    }
  }

  // 12. 公开JSON访问接口 /api/out/{pathName}
  if (path.startsWith('/api/out/')) {
    try {
      const pathName = path.replace('/api/out/', '');
      const linkKey = `link_${pathName}`;
      const raw = await KV_LINK.get(linkKey);
      if (!raw) return Response.json({ code: 404, msg: '链接不存在' }, { status: 404, headers: corsHeaders });
      const link = JSON.parse(raw);
      const inputPwd = url.searchParams.get('pwd') || '';
      const pwdOk = await compare(inputPwd, link.accessPwdHash);
      if (!pwdOk) return Response.json({ code: 403, msg: '访问密码错误' }, { status: 403, headers: corsHeaders });
      const jsonObj = JSON.parse(link.jsonData);
      return Response.json(jsonObj, { headers: { 'Content-Type': 'application/json' } });
    } catch (e) {
      return Response.json({ code: 500, msg: '数据读取异常' }, { status: 500, headers: corsHeaders });
    }
  }

  // 404兜底
  return Response.json({ code: 404, msg: '接口地址不存在' }, { status: 404, headers: corsHeaders });
}