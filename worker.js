import { hash, compare } from 'bcrypt';
import { SignJWT, jwtVerify } from 'jose';
import { TOTP } from 'otpauth';

// 配置项
const JWT_SECRET = new TextEncoder().encode('YOUR_RANDOM_LONG_SECRET_KEY_123456');
const JWT_EXPIRE = 86400; // 1天会话
const KV_USER = EDGEONE_KV_NAMESPACE.user;
const KV_LINK = EDGEONE_KV_NAMESPACE.link;
const KV_EMAIL_CODE = EDGEONE_KV_NAMESPACE.emailCode;
// 普通用户默认链接上限
const DEFAULT_USER_MAX_LINK = 2;

// 工具函数：生成6位邮箱验证码
function genEmailCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// 工具：生成TOTP密钥
function genTOTPSecret() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let s = '';
  for(let i=0;i<16;i++) s += chars[chars.length * Math.random() | 0];
  return s;
}

// 发送模拟邮箱验证码（生产替换真实邮件接口）
async function sendEmailCode(email, code) {
  console.log(`【模拟邮件】发送至${email}，验证码：${code}`);
  await KV_EMAIL_CODE.put(email, JSON.stringify({code, exp: Date.now() + 300000}), {expirationTtl: 300});
}

// JWT签发
async function createToken(user) {
  return new SignJWT({
    uid: user.uid,
    email: user.email,
    isSuper: user.isSuper,
    emailVerified: user.emailVerified,
    maxLinkCount: user.maxLinkCount
  })
    .setIssuedAt()
    .setExpirationTime(`${JWT_EXPIRE}s`)
    .sign(JWT_SECRET);
}

// JWT校验
async function verifyToken(token) {
  try {
    const { payload } = await jwtVerify(token, JWT_SECRET);
    return payload;
  } catch {
    return null;
  }
}

// 获取用户名下已有链接数量
async function getUserLinkCount(ownerUid) {
  let count = 0;
  const list = await KV_LINK.list();
  for (const item of list.keys) {
    const data = JSON.parse(await KV_LINK.get(item.name));
    if (data.ownerUid === ownerUid) count++;
  }
  return count;
}

// 路由分发
export default async function handler(event) {
  const req = event.request;
  const url = new URL(req.url);
  const path = url.pathname;
  const method = req.method;

  // 跨域头
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization'
  };
  if (method === 'OPTIONS') return new Response(null, {headers: corsHeaders});

  // 1. 注册接口 POST /api/auth/register
  if (path === '/api/auth/register' && method === 'POST') {
    const {email, password} = await req.json();
    if (!email || !password) return Response.json({code:400,msg:'邮箱密码不能为空'}, {headers:corsHeaders});
    const exist = await KV_USER.get(email);
    if (exist) return Response.json({code:400,msg:'邮箱已注册'}, {headers:corsHeaders});
    const uid = Date.now().toString();
    const pwdHash = await hash(password, 10);
    const userData = {
      uid,
      email,
      pwdHash,
      isSuper: false,
      emailVerified: false,
      totpSecret: null,
      maxLinkCount: DEFAULT_USER_MAX_LINK // 默认2条上限
    };
    await KV_USER.put(email, JSON.stringify(userData));
    const code = genEmailCode();
    await sendEmailCode(email, code);
    return Response.json({code:200,msg:'注册成功，请查收邮箱验证码'}, {headers:corsHeaders});
  }

  // 2. 发送邮箱验证码 POST /api/auth/sendCode
  if (path === '/api/auth/sendCode' && method === 'POST') {
    const {email} = await req.json();
    const userRaw = await KV_USER.get(email);
    if (!userRaw) return Response.json({code:404,msg:'用户不存在'}, {headers:corsHeaders});
    const code = genEmailCode();
    await sendEmailCode(email, code);
    return Response.json({code:200,msg:'验证码已发送'}, {headers:corsHeaders});
  }

  // 3. 邮箱验证 POST /api/auth/verifyEmail
  if (path === '/api/auth/verifyEmail' && method === 'POST') {
    const {email, code} = await req.json();
    const cacheRaw = await KV_EMAIL_CODE.get(email);
    if (!cacheRaw) return Response.json({code:400,msg:'验证码过期或不存在'}, {headers:corsHeaders});
    const cache = JSON.parse(cacheRaw);
    if (cache.code !== code) return Response.json({code:400,msg:'验证码错误'}, {headers:corsHeaders});
    const userRaw = await KV_USER.get(email);
    const user = JSON.parse(userRaw);
    user.emailVerified = true;
    await KV_USER.put(email, JSON.stringify(user));
    return Response.json({code:200,msg:'邮箱验证成功，功能已解锁'}, {headers:corsHeaders});
  }

  // 4. 登录接口 POST /api/auth/login
  if (path === '/api/auth/login' && method === 'POST') {
    const {email, password, totpCode} = await req.json();
    const userRaw = await KV_USER.get(email);
    if (!userRaw) return Response.json({code:401,msg:'账号不存在'}, {headers:corsHeaders});
    const user = JSON.parse(userRaw);
    const passOk = await compare(password, user.pwdHash);
    if (!passOk) return Response.json({code:401,msg:'密码错误'}, {headers:corsHeaders});
    // 存在2FA则校验
    if (user.totpSecret) {
      if (!totpCode) return Response.json({code:402,msg:'请输入2FA验证码',needTotp:true}, {headers:corsHeaders});
      const totp = new TOTP({secret: user.totpSecret});
      const valid = totp.validate({token: totpCode, window:1});
      if (valid === null) return Response.json({code:401,msg:'2FA验证码错误'}, {headers:corsHeaders});
    }
    const token = await createToken(user);
    return Response.json({
      code:200,
      token,
      user: {
        email: user.email,
        uid: user.uid,
        isSuper: user.isSuper,
        emailVerified: user.emailVerified,
        hasTotp: !!user.totpSecret,
        maxLinkCount: user.maxLinkCount
      }
    }, {headers:corsHeaders});
  }

  // 5. 绑定2FA POST /api/auth/bindTotp
  if (path === '/api/auth/bindTotp' && method === 'POST') {
    const auth = req.headers.get('Authorization')?.replace('Bearer ','');
    const payload = await verifyToken(auth);
    if (!payload) return Response.json({code:401,msg:'未登录'}, {headers:corsHeaders});
    const {verifyCode} = await req.json();
    const userRaw = await KV_USER.get(payload.email);
    const user = JSON.parse(userRaw);
    if (!user.totpTmp) return Response.json({code:400,msg:'未初始化2FA'}, {headers:corsHeaders});
    const totp = new TOTP({secret: user.totpTmp});
    const valid = totp.validate({token: verifyCode, window:1});
    if (valid === null) return Response.json({code:400,msg:'验证码校验失败'}, {headers:corsHeaders});
    user.totpSecret = user.totpTmp;
    delete user.totpTmp;
    await KV_USER.put(payload.email, JSON.stringify(user));
    return Response.json({code:200,msg:'2FA绑定成功'}, {headers:corsHeaders});
  }

  // 6. 获取2FA初始化密钥 GET /api/auth/getTotpInit
  if (path === '/api/auth/getTotpInit' && method === 'GET') {
    const auth = req.headers.get('Authorization')?.replace('Bearer ','');
    const payload = await verifyToken(auth);
    if (!payload) return Response.json({code:401,msg:'未登录'}, {headers:corsHeaders});
    const userRaw = await KV_USER.get(payload.email);
    const user = JSON.parse(userRaw);
    const secret = genTOTPSecret();
    user.totpTmp = secret;
    await KV_USER.put(payload.email, JSON.stringify(user));
    const otpUrl = new TOTP({
      issuer: 'LinkJsonManager',
      label: payload.email,
      secret
    }).toString();
    return Response.json({code:200,secret,otpUrl}, {headers:corsHeaders});
  }

  // 7. 超级管理员：获取全部用户 GET /api/admin/allUsers
  if (path === '/api/admin/allUsers' && method === 'GET') {
    const auth = req.headers.get('Authorization')?.replace('Bearer ','');
    const payload = await verifyToken(auth);
    if (!payload || !payload.isSuper) return Response.json({code:403,msg:'无权限'}, {headers:corsHeaders});
    const list = [];
    const userList = await KV_USER.list();
    for (const item of userList.keys) {
      const u = JSON.parse(await KV_USER.get(item.name));
      list.push({
        email: u.email,
        uid: u.uid,
        isSuper: u.isSuper,
        emailVerified: u.emailVerified,
        hasTotp: !!u.totpSecret,
        maxLinkCount: u.maxLinkCount
      });
    }
    return Response.json({code:200,data:list}, {headers:corsHeaders});
  }

  // 8. 管理员修改用户链接配额 POST /api/admin/setUserMaxLink
  if (path === '/api/admin/setUserMaxLink' && method === 'POST') {
    const auth = req.headers.get('Authorization')?.replace('Bearer ','');
    const payload = await verifyToken(auth);
    if (!payload || !payload.isSuper) return Response.json({code:403,msg:'仅超级管理员可操作'}, {headers:corsHeaders});
    const {targetEmail, newMax} = await req.json();
    const userRaw = await KV_USER.get(targetEmail);
    if (!userRaw) return Response.json({code:404,msg:'用户不存在'}, {headers:corsHeaders});
    const user = JSON.parse(userRaw);
    user.maxLinkCount = Number(newMax);
    await KV_USER.put(targetEmail, JSON.stringify(user));
    return Response.json({code:200,msg:'用户链接上限修改成功'}, {headers:corsHeaders});
  }

  // 9. 链接管理 - 创建/编辑 POST /api/link/save
  if (path === '/api/link/save' && method === 'POST') {
    const auth = req.headers.get('Authorization')?.replace('Bearer ','');
    const payload = await verifyToken(auth);
    if (!payload) return Response.json({code:401,msg:'未登录'}, {headers:corsHeaders});
    if (!payload.emailVerified) return Response.json({code:403,msg:'请先完成邮箱验证'}, {headers:corsHeaders});
    const {linkId, pathName, accessPwd, jsonData} = await req.json();

    // 超级管理员无数量限制
    if (!payload.isSuper) {
      const currentCount = await getUserLinkCount(payload.uid);
      // 新增链接才校验，编辑已有链接不占用配额
      if (!linkId) {
        if (currentCount >= payload.maxLinkCount) {
          return Response.json({
            code:403,
            msg:`链接数量已达上限(${payload.maxLinkCount}条)，请联系管理员提升配额`
          }, {headers:corsHeaders});
        }
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
    return Response.json({code:200,msg:'链接保存成功'}, {headers:corsHeaders});
  }

  // 10. 获取用户自己的链接 /api/link/myList
  if (path === '/api/link/myList' && method === 'GET') {
    const auth = req.headers.get('Authorization')?.replace('Bearer ','');
    const payload = await verifyToken(auth);
    if (!payload) return Response.json({code:401,msg:'未登录'}, {headers:corsHeaders});
    if (!payload.emailVerified) return Response.json({code:403,msg:'请先完成邮箱验证'}, {headers:corsHeaders});
    const res = [];
    const links = await KV_LINK.list();
    for (const k of links.keys) {
      const d = JSON.parse(await KV_LINK.get(k.name));
      if (d.ownerUid === payload.uid || payload.isSuper) res.push(d);
    }
    return Response.json({code:200,data:res,maxLinkCount:payload.maxLinkCount,isSuper:payload.isSuper}, {headers:corsHeaders});
  }

  // 11. 公开JSON访问接口 /api/out/{pathName}
  if (path.startsWith('/api/out/')) {
    const pathName = path.replace('/api/out/','');
    const linkKey = `link_${pathName}`;
    const linkRaw = await KV_LINK.get(linkKey);
    if (!linkRaw) return Response.json({code:404,msg:'链接不存在'}, {status:404,headers:corsHeaders});
    const link = JSON.parse(linkRaw);
    const inputPwd = url.searchParams.get('pwd');
    const pwdOk = await compare(inputPwd, link.accessPwdHash);
    if (!pwdOk) return Response.json({code:403,msg:'访问密码错误'}, {status:403,headers:corsHeaders});
    return Response.json(JSON.parse(link.jsonData), {headers:{'Content-Type':'application/json'}});
  }

  return Response.json({code:404,msg:'接口不存在'}, {status:404,headers:corsHeaders});
}