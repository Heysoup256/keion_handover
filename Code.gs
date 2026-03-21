/**
 * 軽音部 引き継ぎ資料 認証・権限付与システム (バックエンド API)
 * 
 * === Script Properties に設定が必要な値 ===
 * GOOGLE_CLIENT_ID : Google Cloud Console で作成した OAuth 2.0 クライアント ID
 * PASSWORD_HASH    : 後輩に共有するパスワードの SHA-256 ハッシュ
 * DRIVE_IDS        : 権限を付与したい Drive のファイル/フォルダ ID（カンマ区切り）
 * SITES_FILE_ID    : 権限を付与したい Google Sites のファイル ID
 * ALLOWED_DOMAINS  : (任意) 許可するメールドメイン（例: gmail.com, example.ac.jp）
 * MAX_ATTEMPTS     : (任意) パスワード間違えの最大試行回数（デフォルト: 5）
 * LOCKOUT_MINUTES  : (任意) ロックアウト時間（分）（デフォルト: 30）
 */

// ============================================================
// Web App エントリーポイント
// ============================================================

/**
 * GET リクエスト時の処理
 * (このシステムは POST 専用のため、直接アクセスされた場合は警告を出す)
 */
function doGet(e) {
  var html = '<h2>アクセスエラー</h2><p>このページは認証用のバックエンドです。直接アクセスすることはできません。</p><p>指定された公式のアプリケーション URL (例: Vercel などでホスティングされたページ) からアクセスしてください。</p>';
  return HtmlService.createHtmlOutput(html)
    .setTitle('アクセスエラー - 軽音部 引き継ぎシステム')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1');
}

/**
 * POST リクエスト時の処理 (フロントエンドの HTML フォームからデータを受け取る)
 */
function doPost(e) {
  // フロントエンドから渡されるパラメータ
  var idToken = e.parameter.id_token;
  var password = e.parameter.password;
  var returnUrl = e.parameter.return_url;
  
  var template = HtmlService.createTemplateFromFile('Index');
  template.success = false;
  template.email = '';
  template.returnUrl = returnUrl || '';
  
  try {
    if (!idToken || !password) {
      throw new Error('必要なデータが不足しています。');
    }

    // 1. JWT (ID Token) の検証とメールアドレスの取得
    var tokenPayload = verifyIdToken_(idToken);
    var email = tokenPayload.email;
    template.email = email;

    // 2. パスワード・制限等の検証と権限付与の実行
    var result = verifyAndGrantAccess_(email, password);
    
    template.success = result.success;
    template.message = result.message;

  } catch (error) {
    console.error('doPost error:', error);
    template.success = false;
    template.message = error.message;
  }

  // 結果画面 (Index.html) をレンダリングして返す
  return template.evaluate()
    .setTitle(template.success ? '成功 - アクセス権付与' : 'エラー - 認証失敗')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1, maximum-scale=1');
}

// ============================================================
// ID トークン検証ロジック
// ============================================================

/**
 * Google の tokeninfo エンドポイントを使って ID トークンを検証する
 * ※ GAS 本体には JWT 検証機能がないため、Google の公開 API を利用する
 */
function verifyIdToken_(idToken) {
  var url = 'https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(idToken);
  var response = UrlFetchApp.fetch(url, { muteHttpExceptions: true });
  
  if (response.getResponseCode() !== 200) {
    console.error('Token verification failed:', response.getContentText());
    throw new Error('Google の認証トークンが無効、または期限切れです。ブラウザの戻るボタンを押し、最初からやり直してください。');
  }
  
  var payload = JSON.parse(response.getContentText());
  var clientId = getProperty_('GOOGLE_CLIENT_ID');
  
  if (!clientId) {
    throw new Error('システムエラー: サーバー側に GOOGLE_CLIENT_ID が設定されていません。管理者に連絡してください。');
  }
  
  // Aud (想定されるクライアント) が一致するか確認
  if (payload.aud !== clientId) {
    console.error('Client ID mismatch. Expected:', clientId, 'Got:', payload.aud);
    throw new Error('不正なクライアントからのアクセスです。');
  }
  
  // メールアドレスが確認済みかチェック
  if (payload.email_verified !== 'true' && payload.email_verified !== true) {
    throw new Error('確認済みの Google アカウントではありません。');
  }
  
  return payload;
}

// ============================================================
// 認証・権限付与 メインロジック
// ============================================================

function verifyAndGrantAccess_(email, password) {
  // --- レートリミット (ブルートフォース対策) ---
  var rateCheck = checkRateLimit_(email);
  if (!rateCheck.allowed) {
    logAttempt_(email, false, 'レート制限超過');
    return { success: false, message: rateCheck.message };
  }

  // --- ドメイン制限チェック ---
  var domainCheck = checkDomain_(email);
  if (!domainCheck.allowed) {
    recordAttempt_(email, false);
    logAttempt_(email, false, 'ドメイン制限');
    return { success: false, message: domainCheck.message };
  }

  // --- パスワード照合 ---
  var inputHash = hashPassword_(password);
  var storedHash = getProperty_('PASSWORD_HASH');
  if (inputHash !== storedHash) {
    recordAttempt_(email, false);
    var remaining = getRemainingAttempts_(email);
    logAttempt_(email, false, 'パスワード不一致');
    return {
      success: false,
      message: 'パスワードが正しくありません。\n' + (remaining > 0 ? '（残り ' + remaining + ' 回）' : '')
    };
  }

  // --- すでに権限付与済みかチェック ---
  if (isAlreadyGranted_(email)) {
    logAttempt_(email, true, '付与済み（スキップ）');
    return { 
      success: true, 
      message: 'すでに Google Drive と Google Sites への\nアクセス権が付与されています。'
    };
  }

  // --- 権限の付与 ---
  var grantResult = grantPermissions_(email);
  if (!grantResult.success) {
    logAttempt_(email, false, '権限付与エラー: ' + grantResult.message);
    return { success: false, message: grantResult.message };
  }

  // --- 成功時の処理 ---
  recordAttempt_(email, true); // 失敗カウントリセット
  recordGrantedEmail_(email);
  logAttempt_(email, true, '権限付与成功');

  return {
    success: true,
    message: 'Google Drive および Google Sites の\nアクセス権を付与しました！'
  };
}

// ============================================================
// サポート関数群
// ============================================================

function checkRateLimit_(email) {
  var props = PropertiesService.getScriptProperties();
  var key = 'ratelimit_' + email;
  var data = props.getProperty(key);
  if (!data) return { allowed: true };
  
  var record = JSON.parse(data);
  var maxAttempts = parseInt(getProperty_('MAX_ATTEMPTS') || '5');
  var lockoutMinutes = parseInt(getProperty_('LOCKOUT_MINUTES') || '30');
  var lockoutMs = lockoutMinutes * 60 * 1000;
  
  // ロックアウト時間経過後ならリセット
  if (record.lockedUntil && Date.now() > record.lockedUntil) {
    props.deleteProperty(key);
    return { allowed: true };
  }
  
  // ロックアウト中
  if (record.lockedUntil && Date.now() <= record.lockedUntil) {
    var remainMin = Math.ceil((record.lockedUntil - Date.now()) / 60000);
    return { allowed: false, message: '試行回数の上限に達しました。\n' + remainMin + ' 分後に再度お試しください。' };
  }
  
  // 規定回数未満ならOK
  if (record.failCount < maxAttempts) {
    return { allowed: true };
  }
  
  // 規定回数に達したためロックアウト開始
  record.lockedUntil = Date.now() + lockoutMs;
  props.setProperty(key, JSON.stringify(record));
  return { allowed: false, message: '試行回数の上限に達しました。\n' + lockoutMinutes + ' 分後に再度お試しください。' };
}

function recordAttempt_(email, success) {
  var props = PropertiesService.getScriptProperties();
  var key = 'ratelimit_' + email;
  if (success) {
    props.deleteProperty(key); // 成功したらリセット
    return;
  }
  var data = props.getProperty(key);
  var record = data ? JSON.parse(data) : { failCount: 0 };
  record.failCount++;
  record.lastAttempt = Date.now();
  props.setProperty(key, JSON.stringify(record));
}

function getRemainingAttempts_(email) {
  var props = PropertiesService.getScriptProperties();
  var key = 'ratelimit_' + email;
  var data = props.getProperty(key);
  var maxAttempts = parseInt(getProperty_('MAX_ATTEMPTS') || '5');
  if (!data) return maxAttempts - 1; // 今失敗したので -1
  return Math.max(0, maxAttempts - JSON.parse(data).failCount);
}

function checkDomain_(email) {
  var domainsStr = getProperty_('ALLOWED_DOMAINS');
  if (!domainsStr || domainsStr.trim() === '') return { allowed: true };
  var allowedDomains = domainsStr.split(',').map(function(d) { return d.trim().toLowerCase(); });
  var emailDomain = email.split('@')[1].toLowerCase();
  if (allowedDomains.indexOf(emailDomain) === -1) {
    return { allowed: false, message: 'このドメインのアドレスは許可されていません。' };
  }
  return { allowed: true };
}

function grantPermissions_(email) {
  var errors = [];
  
  // 1. Google Drive ファイル/フォルダの権限付与
  var driveIdsStr = getProperty_('DRIVE_IDS');
  if (driveIdsStr && driveIdsStr.trim() !== '') {
    var driveIds = driveIdsStr.split(',').map(function(id) { return id.trim(); });
    driveIds.forEach(function(id) {
      if (!id) return;
      try {
        // 先にファイルとして取得を試みる
        try {
          var file = DriveApp.getFileById(id);
          file.addEditor(email);
        } catch (_) {
          // ファイルでなければフォルダとして取得
          var folder = DriveApp.getFolderById(id);
          folder.addEditor(email);
        }
      } catch (e) {
        console.error('Drive Permission Error for ID ' + id + ': ' + e.message);
        errors.push('Drive ID: ' + id);
      }
    });
  }
  
  // 2. Google Sites の権限付与
  var sitesFileId = getProperty_('SITES_FILE_ID');
  if (sitesFileId && sitesFileId.trim() !== '') {
    try {
      var siteFile = DriveApp.getFileById(sitesFileId.trim());
      siteFile.addEditor(email);
    } catch (e) {
      console.error('Sites Permission Error: ' + e.message);
      errors.push('Sites');
    }
  }

  if (errors.length > 0) {
    return { success: false, message: '一部のファイルの権限付与に失敗しました' };
  }
  
  return { success: true };
}

function isAlreadyGranted_(email) {
  var grantedStr = PropertiesService.getScriptProperties().getProperty('granted_emails');
  if (!grantedStr) return false;
  var grantedList = JSON.parse(grantedStr);
  return grantedList.indexOf(email.toLowerCase()) !== -1;
}

function recordGrantedEmail_(email) {
  var props = PropertiesService.getScriptProperties();
  var grantedStr = props.getProperty('granted_emails');
  var list = grantedStr ? JSON.parse(grantedStr) : [];
  list.push(email.toLowerCase());
  props.setProperty('granted_emails', JSON.stringify(list));
}

function hashPassword_(password) {
  var rawHash = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, password, Utilities.Charset.UTF_8);
  var txtHash = '';
  for (var i = 0; i < rawHash.length; i++) {
    var hashVal = rawHash[i];
    if (hashVal < 0) { hashVal += 256; }
    if (hashVal.toString(16).length == 1) { txtHash += '0'; }
    txtHash += hashVal.toString(16);
  }
  return txtHash;
}

function logAttempt_(email, success, detail) {
  try {
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    if (!ss) return;
    var sheet = ss.getSheetByName('ログ');
    if (!sheet) {
      sheet = ss.insertSheet('ログ');
      sheet.appendRow(['日時', 'メール・アカウント', '結果', '詳細']);
      sheet.getRange(1, 1, 1, 4).setFontWeight('bold');
      sheet.setFrozenRows(1);
    }
    sheet.appendRow([new Date(), email || '不明', success ? '✅ 成功' : '❌ 失敗', detail]);
  } catch (e) {
    console.error('Logging failed:', e);
  }
}

/**
 * 開発者向けヘルパー：パスワードのハッシュ値を生成する
 */
function generatePasswordHash(password) {
  var hash = hashPassword_(password || 'ここにパスワードを入力');
  console.log('SHA-256: ' + hash);
  return hash;
}

function getProperty_(key) {
  return PropertiesService.getScriptProperties().getProperty(key);
}

/**
 * 開発者向けヘルパー：すべての権限を一括で許可させるためのダミー関数。
 * 外部通信 (UrlFetchApp) と Drive アクセス (DriveApp) の両方をトリガーします。
 * GAS エディタからこの関数を選択して「実行」を押すことで確実に承認ポップアップを発生させます。
 */
function setupPermissions() {
  try {
    UrlFetchApp.fetch('https://www.google.com', { muteHttpExceptions: true });
    DriveApp.getFiles();
    console.log('すべての必要な権限（外部通信、Driveアクセス）が正常に承認されました！');
  } catch (e) {
    console.error('権限の承認に失敗したか、エラーが発生しました: ' + e.message);
  }
}
