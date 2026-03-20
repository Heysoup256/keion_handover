/**
 * 軽音部 引き継ぎ資料 認証システム (完全 GAS 完結・サーバーサイド OAuth)
 * 
 * === Script Properties に設定が必要な値 ===
 * GOOGLE_CLIENT_ID     : Google Cloud Console で作成した OAuth 2.0 クライアント ID
 * GOOGLE_CLIENT_SECRET : 上記に対応するクライアント シークレット
 * PASSWORD_HASH        : 共有パスワードの SHA-256 ハッシュ
 * DRIVE_IDS            : 権限付与対象のファイル/フォルダ ID（カンマ区切り）
 * SITES_FILE_ID        : Google Sites のファイル ID
 * ALLOWED_DOMAINS      : (任意) 許可するメールドメイン
 * MAX_ATTEMPTS         : (任意) 最大試行回数（デフォルト: 5）
 * LOCKOUT_MINUTES      : (任意) ロックアウト時間（分）（デフォルト: 30）
 */

// ============================================================
// Web App エントリーポイント
// ============================================================

/**
 * GET リクエスト時の処理
 * - `code` がなければ: Google ログインページを表示（Step 1）
 * - `code` があれば: OAuth コールバックとして処理し、パスワード入力画面を表示（Step 2）
 */
function doGet(e) {
  // --- 初期設定チェック ---
  if (!getProperty_('GOOGLE_CLIENT_ID') || !getProperty_('GOOGLE_CLIENT_SECRET')) {
    return HtmlService.createHtmlOutput('システムエラー: 初期設定 (クライアントID / シークレット) が完了していません。管理者にお問い合わせください。');
  }

  var template = HtmlService.createTemplateFromFile('Index');
  
  // --- OAuth コールバックの場合 ---
  if (e.parameter.code) {
    return handleOAuthCallback_(e.parameter.code, e.parameter.state, template);
  }

  // --- 通常のアクセスの場合 (Step 1: ログイン要求) ---
  var stateToken = Utilities.getUuid();
  // State トークンを 15 分間有効として保存（CSRF 対策）
  PropertiesService.getScriptProperties().setProperty('oauth_state_' + stateToken, String(Date.now() + 15 * 60 * 1000));
  
  template.step = 1;
  template.oauthUrl = getOAuthUrl_(stateToken);
  
  return evaluateTemplate_(template, '軽音部 引き継ぎ資料 アクセス申請');
}

/**
 * POST リクエスト時の処理
 * - パスワード入力画面（Step 2）からのフォーム送信を受け取り、認証・権限付与を行う
 */
function doPost(e) {
  var password = e.parameter.password;
  var sessionToken = e.parameter.sessionToken;
  
  var template = HtmlService.createTemplateFromFile('Index');
  template.step = 3;
  template.email = '';
  
  try {
    if (!password || !sessionToken) {
      throw new Error('必要なデータが不足しています。');
    }

    // 1. セッション検証（OAuth 後に発行されたワンタイムトークン）
    var props = PropertiesService.getScriptProperties();
    var sessionKey = 'auth_session_' + sessionToken;
    var sessionStr = props.getProperty(sessionKey);
    
    if (!sessionStr) {
      throw new Error('セッションがタイムアウトしたか、不正なリクエストです。最初からやり直してください。');
    }
    
    // セッションを即座に破棄（一度しか使用できない）
    props.deleteProperty(sessionKey);
    
    var sessionData = JSON.parse(sessionStr);
    if (Date.now() > sessionData.expires) {
      throw new Error('セッションの有効期限が切れました。最初からログインし直してください。');
    }
    
    var email = sessionData.email;

    // 2. パスワード認証と権限付与の実行
    var result = verifyAndGrantAccess_(email, password);
    
    template.success = result.success;
    template.message = result.message;
    template.email = email;

  } catch (error) {
    console.error('doPost error:', error);
    template.success = false;
    template.message = error.message;
  }

  return evaluateTemplate_(template, template.success ? '成功 - アクセス権付与' : 'エラー - 認証失敗');
}

// ============================================================
// Google サーバーサイド OAuth 処理
// ============================================================

/**
 * Google の OAuth 認証用 URL を生成する
 */
function getOAuthUrl_(stateToken) {
  var authUrl = 'https://accounts.google.com/o/oauth2/v2/auth';
  var params = [
    'client_id=' + encodeURIComponent(getProperty_('GOOGLE_CLIENT_ID')),
    'redirect_uri=' + encodeURIComponent(ScriptApp.getService().getUrl()), // 自身 (GAS) の URL
    'response_type=code',
    'scope=email profile openid',
    'state=' + encodeURIComponent(stateToken),
    'access_type=online',
    // 'prompt=select_account' // アカウント選択画面を強制（必要に応じて有効化）
  ];
  return authUrl + '?' + params.join('&');
}

/**
 * OAuth のコールバックを受け取り、トークンを交換して Step 2 の画面を返す
 */
function handleOAuthCallback_(code, state, template) {
  var props = PropertiesService.getScriptProperties();
  
  // 1. State 検証 (CSRF 対策)
  var stateKey = 'oauth_state_' + state;
  var stateExpiry = props.getProperty(stateKey);
  
  if (!stateExpiry) {
    template.step = 3;
    template.success = false;
    template.email = '';
    template.message = 'セッションが見つかりません。最初からやり直してください。';
    return evaluateTemplate_(template, 'エラー');
  }
  
  props.deleteProperty(stateKey); // 消費
  
  if (Date.now() > parseInt(stateExpiry)) {
    template.step = 3;
    template.success = false;
    template.email = '';
    template.message = '認証の有効期限が切れました。最初からやり直してください。';
    return evaluateTemplate_(template, 'エラー');
  }

  // 2. 認可コード (code) を ID トークンに交換
  var payload = {
    code: code,
    client_id: getProperty_('GOOGLE_CLIENT_ID'),
    client_secret: getProperty_('GOOGLE_CLIENT_SECRET'),
    redirect_uri: ScriptApp.getService().getUrl(),
    grant_type: 'authorization_code'
  };
  
  try {
    var response = UrlFetchApp.fetch('https://oauth2.googleapis.com/token', {
      method: 'post',
      payload: payload,
      muteHttpExceptions: true
    });
    
    if (response.getResponseCode() !== 200) {
      console.error('Token API Error:', response.getContentText());
      throw new Error('Google との認証に失敗しました。');
    }
    
    var tokenData = JSON.parse(response.getContentText());
    
    // 3. ID トークンのデコード (署名の検証は GoogleのHTTPS通信を信頼するため省略可。直接取得しているため安全)
    var idTokenParts = tokenData.id_token.split('.');
    var idTokenPayload = JSON.parse(Utilities.newBlob(Utilities.base64DecodeWebSafe(idTokenParts[1])).getDataAsString());
    
    var email = idTokenPayload.email;
    var name = idTokenPayload.name || email;
    
    // 4. パスワード画面用の一時セッション (15分有効) を作成
    var sessionToken = Utilities.getUuid();
    var sessionData = { 
      email: email, 
      name: name,
      expires: Date.now() + 15 * 60 * 1000 
    };
    props.setProperty('auth_session_' + sessionToken, JSON.stringify(sessionData));
    
    // 5. Step 2 (パスワード入力) のテンプレートを返す
    template.step = 2;
    template.sessionToken = sessionToken;
    template.userEmail = email;
    template.userName = name;
    
    return evaluateTemplate_(template, 'パスワードの入力 - 軽音部 引き継ぎ資料');
    
  } catch (err) {
    console.error('OAuth Callback error:', err);
    template.step = 3;
    template.success = false;
    template.email = '';
    template.message = 'システムエラー: ' + err.message;
    return evaluateTemplate_(template, 'システムエラー');
  }
}

/**
 * テンプレートを評価して HtmlOutput を生成する共通関数
 */
function evaluateTemplate_(template, title) {
  return template.evaluate()
    .setTitle(title)
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1, maximum-scale=1');
}

// ============================================================
// 認証・権限付与 メインロジック
// ============================================================

/**
 * パスワード検証・制限チェック・権限付与を行う
 * @param {string} email
 * @param {string} password
 * @returns {Object} { success: boolean, message: string }
 */
function verifyAndGrantAccess_(email, password) {
  // 1. レート制限チェック
  var rateCheck = checkRateLimit_(email);
  if (!rateCheck.allowed) {
    logAttempt_(email, false, 'レート制限超過');
    return { success: false, message: rateCheck.message };
  }

  // 2. ドメイン制限チェック
  var domainCheck = checkDomain_(email);
  if (!domainCheck.allowed) {
    recordAttempt_(email, false);
    logAttempt_(email, false, 'ドメイン制限');
    return { success: false, message: domainCheck.message };
  }

  // 3. パスワード照合
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

  // 4. 付与済みチェック
  if (isAlreadyGranted_(email)) {
    logAttempt_(email, true, '付与済み（スキップ）');
    return { 
      success: true, 
      message: 'すでに Google Drive と Google Sites への\nアクセス権が付与されています。'
    };
  }

  // 5. 権限付与
  var grantResult = grantPermissions_(email);
  if (!grantResult.success) {
    logAttempt_(email, false, '権限付与エラー: ' + grantResult.message);
    return { success: false, message: grantResult.message };
  }

  // 6. 成功記録
  recordAttempt_(email, true);
  recordGrantedEmail_(email);
  logAttempt_(email, true, '権限付与成功');

  return {
    success: true,
    message: 'Google Drive および Google Sites の\nアクセス権を付与しました！'
  };
}


// ============================================================
// レート制限
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

  if (record.lockedUntil && Date.now() > record.lockedUntil) {
    props.deleteProperty(key);
    return { allowed: true };
  }

  if (record.lockedUntil && Date.now() <= record.lockedUntil) {
    var remainMin = Math.ceil((record.lockedUntil - Date.now()) / 60000);
    return { allowed: false, message: '試行回数の上限に達しました。\n' + remainMin + '分後に再試行してください。' };
  }

  if (record.failCount < maxAttempts) {
    return { allowed: true };
  }

  record.lockedUntil = Date.now() + lockoutMs;
  props.setProperty(key, JSON.stringify(record));
  return { allowed: false, message: '試行回数の上限に達しました。\n' + lockoutMinutes + '分後に再試行してください。' };
}

function recordAttempt_(email, success) {
  var props = PropertiesService.getScriptProperties();
  var key = 'ratelimit_' + email;
  if (success) {
    props.deleteProperty(key);
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
  if (!data) return maxAttempts - 1;
  var record = JSON.parse(data);
  return Math.max(0, maxAttempts - record.failCount);
}

// ============================================================
// ドメイン制限
// ============================================================
function checkDomain_(email) {
  var domainsStr = getProperty_('ALLOWED_DOMAINS');
  if (!domainsStr || domainsStr.trim() === '') return { allowed: true };

  var allowedDomains = domainsStr.split(',').map(function(d) { return d.trim().toLowerCase(); });
  var emailDomain = email.split('@')[1].toLowerCase();

  if (allowedDomains.indexOf(emailDomain) === -1) {
    return { allowed: false, message: 'このメールアドレスのドメインは許可されていません。' };
  }
  return { allowed: true };
}

// ============================================================
// 権限付与
// ============================================================
function grantPermissions_(email) {
  var errors = [];
  var driveIdsStr = getProperty_('DRIVE_IDS');
  
  if (driveIdsStr && driveIdsStr.trim() !== '') {
    var driveIds = driveIdsStr.split(',').map(function(id) { return id.trim(); });
    driveIds.forEach(function(id) {
      try {
        try {
          DriveApp.getFileById(id).addEditor(email);
        } catch (fileErr) {
          DriveApp.getFolderById(id).addEditor(email);
        }
      } catch (e) {
        console.error('Failed to grant access for ID ' + id + ': ' + e);
        errors.push('Drive ID: ' + id);
      }
    });
  }

  var sitesFileId = getProperty_('SITES_FILE_ID');
  if (sitesFileId && sitesFileId.trim() !== '') {
    try {
      DriveApp.getFileById(sitesFileId.trim()).addEditor(email);
    } catch (e) {
      console.error('Failed to grant access for Sites: ' + e);
      errors.push('Sites');
    }
  }

  if (errors.length > 0) {
    return { success: false, message: '一部のファイルへの権限付与に失敗しました\n（' + errors.join(', ') + '）。' };
  }
  return { success: true };
}

// ============================================================
// 付与済み記録 & パスワード & ログ
// ============================================================
function isAlreadyGranted_(email) {
  var granted = PropertiesService.getScriptProperties().getProperty('granted_emails');
  if (!granted) return false;
  return JSON.parse(granted).indexOf(email.toLowerCase()) !== -1;
}

function recordGrantedEmail_(email) {
  var props = PropertiesService.getScriptProperties();
  var granted = props.getProperty('granted_emails');
  var list = granted ? JSON.parse(granted) : [];
  list.push(email.toLowerCase());
  props.setProperty('granted_emails', JSON.stringify(list));
}

function hashPassword_(password) {
  var rawHash = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, password, Utilities.Charset.UTF_8);
  return rawHash.map(function(byte) {
    return ('0' + ((byte < 0) ? byte + 256 : byte).toString(16)).slice(-2);
  }).join('');
}

function logAttempt_(email, success, detail) {
  try {
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    if (!ss) return;

    var sheet = ss.getSheetByName('ログ');
    if (!sheet) {
      sheet = ss.insertSheet('ログ');
      sheet.appendRow(['日時', 'メールアドレス', '結果', '詳細']);
      sheet.getRange(1, 1, 1, 4).setFontWeight('bold');
      sheet.setFrozenRows(1);
      sheet.setColumnWidths(1, 4, [180, 250, 80, 300]);
    }

    sheet.appendRow([new Date(), email || '（不明）', success ? '✅ 成功' : '❌ 失敗', detail]);
  } catch (e) {
    console.error('logAttempt_ error:', e);
  }
}

function getProperty_(key) {
  return PropertiesService.getScriptProperties().getProperty(key);
}

// ============================================================
// ユーティリティ・クリーンアップ
// ============================================================

/**パスワードハッシュを手動生成するヘルパー関数 */
function generatePasswordHash(password) {
  if (!password || password === 'ここにパスワードを入力') password = 'ここにパスワードを入力';
  var hash = hashPassword_(password);
  console.log('SHA-256 ハッシュ:\n' + hash);
  return hash;
}

/** 期限切れのセッションやState情報を掃除（トリガーで定期実行を推奨） */
function cleanupExpiredSessions() {
  var props = PropertiesService.getScriptProperties();
  var allProps = props.getProperties();
  var now = Date.now();
  var cleaned = 0;

  Object.keys(allProps).forEach(function(key) {
    if (key.indexOf('oauth_state_') === 0 || key.indexOf('auth_session_') === 0) {
      var data = allProps[key];
      var expiry = 0;
      if (key.indexOf('auth_session_') === 0) {
        expiry = JSON.parse(data).expires;
      } else {
        expiry = parseInt(data);
      }
      
      if (now > expiry) {
        props.deleteProperty(key);
        cleaned++;
      }
    }
  });
  console.log('クリーンアップ完了: ' + cleaned + ' 件削除しました。');
}
