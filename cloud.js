/* TITAN cloud — يتصل بـ Firebase عبر REST بدون أي مكتبة خارجية */
(function () {
  var C = window.TITAN_CFG || {};
  var AUTH = 'https://identitytoolkit.googleapis.com/v1/';
  var TOKEN_URL = 'https://securetoken.googleapis.com/v1/token';
  var SKEY = 'titan_session_v1';

  function configured() {
    return !!(C.apiKey && C.projectId && String(C.apiKey).indexOf('PASTE') < 0 && String(C.projectId).indexOf('PASTE') < 0);
  }
  function docs() {
    return 'https://firestore.googleapis.com/v1/projects/' + encodeURIComponent(C.projectId) + '/databases/(default)/documents';
  }

  /* ---------- رسائل الأخطاء بالعربية ---------- */
  var AR = {
    EMAIL_EXISTS: 'هذا البريد مسجّل مسبقاً، سجّل الدخول بدلاً من إنشاء حساب.',
    INVALID_EMAIL: 'البريد الإلكتروني غير صحيح.',
    WEAK_PASSWORD: 'كلمة السر ضعيفة، استعمل 6 أحرف على الأقل.',
    EMAIL_NOT_FOUND: 'البريد أو كلمة السر غير صحيحة.',
    INVALID_PASSWORD: 'البريد أو كلمة السر غير صحيحة.',
    INVALID_LOGIN_CREDENTIALS: 'البريد أو كلمة السر غير صحيحة.',
    USER_DISABLED: 'هذا الحساب موقوف.',
    TOO_MANY_ATTEMPTS_TRY_LATER: 'محاولات كثيرة، انتظر قليلاً ثم أعد المحاولة.',
    TAKEN: 'اسم الرابط مستعمل من محل آخر، اختر اسماً مختلفاً.',
    DENIED: 'لا توجد صلاحية. سجّل الخروج ثم ادخل من جديد.',
    NETWORK: 'تعذّر الاتصال بالإنترنت. تأكد من الشبكة وأعد المحاولة.',
    NOT_FOUND: 'غير موجود.',
    SESSION: 'انتهت الجلسة، سجّل الدخول من جديد.',
    CONFIG: 'لم يُضبط الاتصال بقاعدة البيانات بعد.'
  };
  function mkErr(code, raw) {
    var e = new Error(AR[code] || ('حدث خطأ (' + (raw || code) + ')'));
    e.code = code; return e;
  }
  function authErr(msg) {
    var m = String(msg || '').split(' ')[0].replace(/:$/, '');
    return mkErr(AR[m] ? m : 'OTHER', msg);
  }

  /* ---------- طلبات عامة ---------- */
  function req(url, opts) {
    return fetch(url, opts).catch(function () { throw mkErr('NETWORK'); });
  }
  function jsonOrEmpty(r) { return r.json().catch(function () { return {}; }); }

  /* ---------- الجلسة ---------- */
  function getSession() { try { return JSON.parse(localStorage.getItem(SKEY) || 'null'); } catch (e) { return null; } }
  function setSession(s) { try { if (s) localStorage.setItem(SKEY, JSON.stringify(s)); else localStorage.removeItem(SKEY); } catch (e) {} }
  function fromAuth(j) {
    return { idToken: j.idToken, refreshToken: j.refreshToken, uid: j.localId, email: j.email, exp: Date.now() + (parseInt(j.expiresIn, 10) || 3600) * 1000 };
  }

  function authCall(path, body) {
    if (!configured()) return Promise.reject(mkErr('CONFIG'));
    return req(AUTH + path + '?key=' + encodeURIComponent(C.apiKey), {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    }).then(function (r) {
      return jsonOrEmpty(r).then(function (j) {
        if (!r.ok) throw authErr(j && j.error && j.error.message);
        return j;
      });
    });
  }

  function signUp(email, password) {
    return authCall('accounts:signUp', { email: email, password: password, returnSecureToken: true }).then(function (j) { var s = fromAuth(j); setSession(s); return s; });
  }
  function signIn(email, password) {
    return authCall('accounts:signInWithPassword', { email: email, password: password, returnSecureToken: true }).then(function (j) { var s = fromAuth(j); setSession(s); return s; });
  }
  function resetPassword(email) {
    return authCall('accounts:sendOobCode', { requestType: 'PASSWORD_RESET', email: email });
  }
  function signOut() { setSession(null); }

  var refreshing = null;
  function refresh() {
    var s = getSession();
    if (!s || !s.refreshToken) return Promise.reject(mkErr('SESSION'));
    if (refreshing) return refreshing;
    refreshing = req(TOKEN_URL + '?key=' + encodeURIComponent(C.apiKey), {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=refresh_token&refresh_token=' + encodeURIComponent(s.refreshToken)
    }).then(function (r) {
      return jsonOrEmpty(r).then(function (j) {
        refreshing = null;
        if (!r.ok || !j.id_token) { setSession(null); throw mkErr('SESSION'); }
        var ns = { idToken: j.id_token, refreshToken: j.refresh_token || s.refreshToken, uid: j.user_id || s.uid, email: s.email, exp: Date.now() + (parseInt(j.expires_in, 10) || 3600) * 1000 };
        setSession(ns); return ns;
      });
    }, function (e) { refreshing = null; throw e; });
    return refreshing;
  }
  function freshSession() {
    var s = getSession();
    if (!s) return Promise.reject(mkErr('SESSION'));
    if (s.exp - Date.now() > 60000) return Promise.resolve(s);
    return refresh();
  }

  /* ---------- Firestore ---------- */
  function toFields(o) {
    var f = {};
    Object.keys(o).forEach(function (k) { f[k] = { stringValue: String(o[k] == null ? '' : o[k]) }; });
    return { fields: f };
  }
  function fromDoc(d) {
    var o = {}, f = (d && d.fields) || {};
    Object.keys(f).forEach(function (k) { o[k] = f[k].stringValue != null ? f[k].stringValue : ''; });
    return o;
  }
  function fsError(r, j) {
    var st = j && j.error && j.error.status;
    if (r.status === 404 || st === 'NOT_FOUND') return mkErr('NOT_FOUND');
    if (r.status === 409 || st === 'ALREADY_EXISTS') return mkErr('TAKEN');
    if (r.status === 401 || st === 'UNAUTHENTICATED') return mkErr('SESSION');
    if (r.status === 403 || st === 'PERMISSION_DENIED') return mkErr('DENIED');
    return mkErr('OTHER', (j && j.error && j.error.message) || r.status);
  }

  // بدون تسجيل دخول (للمتجر العام)
  function getPublic(path) {
    if (!configured()) return Promise.reject(mkErr('CONFIG'));
    return req(docs() + '/' + path, { cache: 'no-store' }).then(function (r) {
      return jsonOrEmpty(r).then(function (j) { if (!r.ok) throw fsError(r, j); return fromDoc(j); });
    });
  }

  function authed(method, url, bodyObj, retried) {
    return freshSession().then(function (s) {
      var o = { method: method, headers: { 'Authorization': 'Bearer ' + s.idToken } };
      if (bodyObj) { o.headers['Content-Type'] = 'application/json'; o.body = JSON.stringify(bodyObj); }
      return req(url, o).then(function (r) {
        return jsonOrEmpty(r).then(function (j) {
          if (r.status === 401 && !retried) {
            var cur = getSession(); if (cur) { cur.exp = 0; setSession(cur); }
            return authed(method, url, bodyObj, true);
          }
          if (!r.ok) throw fsError(r, j);
          return j;
        });
      });
    });
  }

  function getMine(path) { return authed('GET', docs() + '/' + path).then(fromDoc); }
  function createDoc(col, id, obj) { return authed('POST', docs() + '/' + col + '?documentId=' + encodeURIComponent(id), toFields(obj)).then(fromDoc); }
  function patchDoc(path, obj) {
    var mask = Object.keys(obj).map(function (k) { return 'updateMask.fieldPaths=' + encodeURIComponent(k); }).join('&');
    return authed('PATCH', docs() + '/' + path + '?' + mask, toFields(obj)).then(fromDoc);
  }

  function deleteDoc(path) { return authed('DELETE', docs() + '/' + path).then(function () { return true; }); }

  function parseRun(arr) {
    return (Array.isArray(arr) ? arr : []).filter(function (x) { return x && x.document; }).map(function (x) {
      var o = fromDoc(x.document); o._id = x.document.name.split('/').pop(); return o;
    });
  }
  // صور موديل واحد (قراءة عامة بدون تسجيل دخول)
  function itemsByModel(slug, mk, limit) {
    if (!configured()) return Promise.reject(mkErr('CONFIG'));
    var q = { from: [{ collectionId: 'items' }], where: { fieldFilter: { field: { fieldPath: 'mk' }, op: 'EQUAL', value: { stringValue: mk } } }, limit: limit || 40 };
    return req(docs() + '/shops/' + encodeURIComponent(slug) + ':runQuery', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ structuredQuery: q }), cache: 'no-store'
    }).then(function (r) {
      return jsonOrEmpty(r).then(function (j) { if (!r.ok) throw fsError(r, j); return parseRun(j); });
    });
  }
  // مفتاح الموديل: يجب أن يكون واحداً في التطبيق والمتجر
  function mk(brandId, model) { return String(brandId) + '|' + String(model).toLowerCase().replace(/\s+/g, ' ').trim(); }

  window.TitanCloud = {
    deleteDoc: deleteDoc, itemsByModel: itemsByModel, mk: mk,
    configured: configured, session: getSession,
    signUp: signUp, signIn: signIn, signOut: signOut, resetPassword: resetPassword,
    getPublic: getPublic, getMine: getMine, createDoc: createDoc, patchDoc: patchDoc
  };
})();
