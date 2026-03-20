/**
 * 軽音部 引き継ぎ資料 認証・権限付与システム (バックエンド)
 * 
 * === Script Properties に設定が必要な値 ===
 * GOOGLE_CLIENT_ID : Google Cloud Console で作成した OAuth 2.0 クライアント ID
 * PASSWORD_HASH    : 共有パスワードの SHA-256 ハッシュ（generatePasswordHash() で生成）
 * DRIVE_IDS        : 権限付与対象のファイル/フォルダ ID（カンマ区切り）
 * SITES_FILE_ID    : Google Sites のファイル ID
 * ALLOWED_DOMAINS  : (任意) 許可するメールドメイン（カンマ区切り、空なら制限なし）
 * MAX_ATTEMPTS     : (任意) 最大試行回数（デフォルト: 5）
 * LOCKOUT_MINUTES  : (任意) ロックアウト時間（分）（デフォルト: 30）
 */

// ============================================================
// Web App エントリーポイント
// ============================================================

/**
 * GET リクエスト時の処理
 * 本システムは GitHub Pages をフロントエンドとするため、直接アクセスされた場合は警告を表示します。
 */
function doGet(e) {
  var template = HtmlService.createTemplateFromFile('Index');
  template.success = false;
  template.email = '';
  template.message = 'このURLには直接アクセスできません。\nGitHub Pages の認証画面からお進みください。';
  
  return template.evaluate()
    .setTitle('エラー - 軽音部 引き継ぎ資料')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1');
}

/**
 * POST リクエスト時の処理（GitHub Pages のフォームから送信される）
 * @param {Object} e - POST されたデータ (e.parameter)
 */
function doPost(e) {
  var idToken = e.parameter.id_token;
  var password = e.parameter.password;
  
  var template = HtmlService.createTemplateFromFile('Index');
  template.email = '';
  
  try {
    if (!idToken || !password) {
      throw new Error('必要なデータが不足しています。');
    }

    // 1. 認証と権限付与のメイン処理
    var result = verifyAndGrantAccess_(idToken, password);
    
    // 2. 結果をテンプレートに設定
    template.success = result.success;
    template.message = result.message;
    if (result.email) {
      template.email = result.email;
    }

  } catch (error) {
    console.error('doPost error:', error);
    template.success = false;
    template.message = 'システムエラーが発生しました: ' + error.message;
  }

  // 結果 HTML を返却する
  return template.evaluate()
    .setTitle(template.success ? '成功 - アクセス権付与' : 'エラー - 認証失敗')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1');
}

// ============================================================
// 認証・権限付与 メインロジック
// ============================================================

/**
 * ID Token とパスワードを検証し、権限を付与する
 * @param {string} idToken
 * @param {string} password
 * @returns {Object} { success: boolean, message: string, email?: string }
 */
function verifyAndGrantAccess_(idToken, password) {
  // 1. ID Token を Google API で検証
  var userInfo = verifyIdToken_(idToken);
  if (!userInfo.success) {
    logAttempt_(null, false, 'ID Token 検証失敗: ' + userInfo.message);
    return { success: false, message: userInfo.message };
  }
  var email = userInfo.email;

  // 2. レート制限チェック
  var rateCheck = checkRateLimit_(email);
  if (!rateCheck.allowed) {
    logAttempt_(email, false, 'レート制限超過');
    return { success: false, message: rateCheck.message, email: email };
  }

  // 3. ドメイン制限チェック
  var domainCheck = checkDomain_(email);
  if (!domainCheck.allowed) {
    recordAttempt_(email, false);
    logAttempt_(email, false, 'ドメイン制限');
    return { success: false, message: domainCheck.message, email: email };
  }

  // 4. パスワード照合（SHA-256 ハッシュ比較）
  var inputHash = hashPassword_(password);
  var storedHash = getProperty_('PASSWORD_HASH');
  if (inputHash !== storedHash) {
    recordAttempt_(email, false);
    var remaining = getRemainingAttempts_(email);
    logAttempt_(email, false, 'パスワード不一致');
    return {
      success: false,
      message: 'パスワードが正しくありません。\n' + (remaining > 0 ? '（残り ' + remaining + ' 回）' : ''),
      email: email
    };
  }

  // 5. 既に権限付与済みかチェック
  if (isAlreadyGranted_(email)) {
    logAttempt_(email, true, '付与済み（スキップ）');
    return { 
      success: true, 
      message: 'すでに Google Drive と Google Sites への\nアクセス権が付与されています。',
      email: email 
    };
  }

  // 6. 権限付与
  var grantResult = grantPermissions_(email);
  if (!grantResult.success) {
    logAttempt_(email, false, '権限付与エラー: ' + grantResult.message);
    return { success: false, message: grantResult.message, email: email };
  }

  // 7. 成功記録
  recordAttempt_(email, true);
  recordGrantedEmail_(email);
  logAttempt_(email, true, '権限付与成功');

  return {
    success: true,
    message: 'Google Drive および Google Sites の\nアクセス権を付与しました！',
    email: email
  };
}

// ============================================================
// ID Token 検証
// ============================================================

/**
 * Google ID Token をサーバーサイドで検証する
 * @param {string} idToken
 * @returns {Object} { success, email, name, message }
 */
function verifyIdToken_(idToken) {
  try {
    var url = 'https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(idToken);
    var response = UrlFetchApp.fetch(url, { muteHttpExceptions: true });
    var code = response.getResponseCode();

    if (code !== 200) {
      return { success: false, message: 'Google 認証に失敗しました。もう一度ログインし直してください。' };
    }

    var payload = JSON.parse(response.getContentText());
    var clientId = getProperty_('GOOGLE_CLIENT_ID');

    // aud (audience) がこのアプリのクライアント ID と一致するか検証（悪用防止）
    if (payload.aud !== clientId) {
      console.error('Audience mismatch: expected ' + clientId + ', got ' + payload.aud);
      return { success: false, message: '不正な認証トークンです。Client IDの不一致。' };
    }

    // トークンの有効期限チェック（リプレイ攻撃防止）
    var now = Math.floor(Date.now() / 1000);
    if (parseInt(payload.exp) < now) {
      return { success: false, message: '認証トークンの有効期限が切れています。もう一度ログインしてください。' };
    }

    return {
      success: true,
      email: payload.email,
      name: payload.name || payload.email,
    };
  } catch (e) {
    console.error('verifyIdToken_ error:', e);
    return { success: false, message: 'トークン検証中にサーバーエラーが発生しました。' };
  }
}

// ============================================================
// レート制限
// ============================================================

/**
 * レート制限チェック
 * @param {string} email
 * @returns {Object} { allowed: boolean, message?: string }
 */
function checkRateLimit_(email) {
  var props = PropertiesService.getScriptProperties();
  var key = 'ratelimit_' + email;
  var data = props.getProperty(key);

  if (!data) {
    return { allowed: true };
  }

  var record = JSON.parse(data);
  var maxAttempts = parseInt(getProperty_('MAX_ATTEMPTS') || '5');
  var lockoutMinutes = parseInt(getProperty_('LOCKOUT_MINUTES') || '30');
  var lockoutMs = lockoutMinutes * 60 * 1000;

  // ロックアウト期間が過ぎていればリセット
  if (record.lockedUntil && Date.now() > record.lockedUntil) {
    props.deleteProperty(key);
    return { allowed: true };
  }

  // ロックアウト中
  if (record.lockedUntil && Date.now() <= record.lockedUntil) {
    var remainMin = Math.ceil((record.lockedUntil - Date.now()) / 60000);
    return {
      allowed: false,
      message: '試行回数の上限に達しました。\n' + remainMin + '分後に再試行してください。'
    };
  }

  // 失敗回数がまだ上限未満
  if (record.failCount < maxAttempts) {
    return { allowed: true };
  }

  // 上限到達 → ロックアウト開始
  record.lockedUntil = Date.now() + lockoutMs;
  props.setProperty(key, JSON.stringify(record));
  return {
    allowed: false,
    message: '試行回数の上限に達しました。\n' + lockoutMinutes + '分後に再試行してください。'
  };
}

/**
 * 試行を記録
 * @param {string} email
 * @param {boolean} success
 */
function recordAttempt_(email, success) {
  var props = PropertiesService.getScriptProperties();
  var key = 'ratelimit_' + email;

  if (success) {
    // 成功したらレート制限をリセット
    props.deleteProperty(key);
    return;
  }

  var data = props.getProperty(key);
  var record = data ? JSON.parse(data) : { failCount: 0 };
  record.failCount++;
  record.lastAttempt = Date.now();
  props.setProperty(key, JSON.stringify(record));
}

/**
 * 残り試行回数を取得
 * @param {string} email
 * @returns {number}
 */
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

/**
 * メールのドメインが許可リストに含まれるかチェック
 * @param {string} email
 * @returns {Object} { allowed: boolean, message?: string }
 */
function checkDomain_(email) {
  var domainsStr = getProperty_('ALLOWED_DOMAINS');
  if (!domainsStr || domainsStr.trim() === '') {
    return { allowed: true }; // 制限なし
  }

  var allowedDomains = domainsStr.split(',').map(function(d) { return d.trim().toLowerCase(); });
  var emailDomain = email.split('@')[1].toLowerCase();

  if (allowedDomains.indexOf(emailDomain) === -1) {
    return {
      allowed: false,
      message: 'このメールアドレスのドメインは許可されていません。'
    };
  }
  return { allowed: true };
}

// ============================================================
// 権限付与
// ============================================================

/**
 * Google Drive ファイル/フォルダおよび Sites に権限を付与
 * @param {string} email
 * @returns {Object} { success: boolean, message?: string }
 */
function grantPermissions_(email) {
  var errors = [];

  // Drive ファイル/フォルダに権限付与
  var driveIdsStr = getProperty_('DRIVE_IDS');
  if (driveIdsStr && driveIdsStr.trim() !== '') {
    var driveIds = driveIdsStr.split(',').map(function(id) { return id.trim(); });
    driveIds.forEach(function(id) {
      try {
        // まずファイルとして試す
        try {
          var file = DriveApp.getFileById(id);
          file.addEditor(email);
          console.log('Granted editor to ' + email + ' for file: ' + id);
        } catch (fileErr) {
          // ファイルでなければフォルダとして試す
          var folder = DriveApp.getFolderById(id);
          folder.addEditor(email);
          console.log('Granted editor to ' + email + ' for folder: ' + id);
        }
      } catch (e) {
        console.error('Failed to grant access for ID ' + id + ': ' + e);
        errors.push('Drive ID: ' + id);
      }
    });
  }

  // Google Sites に権限付与
  var sitesFileId = getProperty_('SITES_FILE_ID');
  if (sitesFileId && sitesFileId.trim() !== '') {
    try {
      var sitesFile = DriveApp.getFileById(sitesFileId.trim());
      sitesFile.addEditor(email);
      console.log('Granted editor to ' + email + ' for Sites: ' + sitesFileId);
    } catch (e) {
      console.error('Failed to grant access for Sites: ' + e);
      errors.push('Sites');
    }
  }

  if (errors.length > 0) {
    return {
      success: false,
      message: '一部のファイルへの権限付与に失敗しました\n（' + errors.join(', ') + '）。\n管理者に連絡してください。'
    };
  }

  return { success: true };
}

// ============================================================
// 付与済み記録
// ============================================================

/**
 * 権限付与済みかチェック
 * @param {string} email
 * @returns {boolean}
 */
function isAlreadyGranted_(email) {
  var props = PropertiesService.getScriptProperties();
  var granted = props.getProperty('granted_emails');
  if (!granted) return false;
  var list = JSON.parse(granted);
  return list.indexOf(email.toLowerCase()) !== -1;
}

/**
 * 権限付与済みメールアドレスを記録
 * @param {string} email
 */
function recordGrantedEmail_(email) {
  var props = PropertiesService.getScriptProperties();
  var granted = props.getProperty('granted_emails');
  var list = granted ? JSON.parse(granted) : [];
  list.push(email.toLowerCase());
  props.setProperty('granted_emails', JSON.stringify(list));
}

// ============================================================
// パスワードハッシュ
// ============================================================

/**
 * パスワードを SHA-256 でハッシュ化する
 * @param {string} password
 * @returns {string} hex-encoded SHA-256 hash
 */
function hashPassword_(password) {
  var rawHash = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, password, Utilities.Charset.UTF_8);
  return rawHash.map(function(byte) {
    var v = (byte < 0) ? byte + 256 : byte;
    return ('0' + v.toString(16)).slice(-2);
  }).join('');
}

// ============================================================
// スプレッドシートへのログ記録
// ============================================================

/**
 * 認証試行をバインド先のスプレッドシートにログ記録する
 * @param {string|null} email
 * @param {boolean} success
 * @param {string} detail
 */
function logAttempt_(email, success, detail) {
  try {
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    if (!ss) {
      console.log('スプレッドシートにバインドされていません。ログをスキップします。');
      return;
    }

    var sheet = ss.getSheetByName('ログ');
    if (!sheet) {
      sheet = ss.insertSheet('ログ');
      sheet.appendRow(['日時', 'メールアドレス', '結果', '詳細']);
      sheet.getRange(1, 1, 1, 4).setFontWeight('bold');
      sheet.setFrozenRows(1);
      sheet.setColumnWidth(1, 180);
      sheet.setColumnWidth(2, 250);
      sheet.setColumnWidth(3, 80);
      sheet.setColumnWidth(4, 300);
    }

    sheet.appendRow([
      new Date(),
      email || '（不明）',
      success ? '✅ 成功' : '❌ 失敗',
      detail
    ]);
  } catch (e) {
    console.error('logAttempt_ error:', e);
  }
}

// ============================================================
// ユーティリティ
// ============================================================

function getProperty_(key) {
  return PropertiesService.getScriptProperties().getProperty(key);
}

// ============================================================
// セットアップ用ヘルパー（手動実行用）
// ============================================================

function generatePasswordHash(password) {
  if (!password || password === 'ここにパスワードを入力') {
    password = 'ここにパスワードを入力';
  }
  var hash = hashPassword_(password);
  console.log('=== パスワードハッシュ生成 ===');
  console.log('入力: ' + password);
  console.log('SHA-256 ハッシュ: ' + hash);
  console.log('');
  console.log('↑ このハッシュ値を Script Properties の PASSWORD_HASH に設定してください。');
  return hash;
}

function checkSetup() {
  var props = PropertiesService.getScriptProperties().getProperties();
  var required = ['GOOGLE_CLIENT_ID', 'PASSWORD_HASH', 'DRIVE_IDS', 'SITES_FILE_ID'];
  var missing = [];

  required.forEach(function(key) {
    if (!props[key] || props[key].trim() === '') {
      missing.push(key);
    }
  });

  if (missing.length > 0) {
    console.log('⚠️ 以下の Script Properties が未設定です:\n' + missing.join(', '));
  } else {
    console.log('✅ 必須の Script Properties はすべて設定されています。');
  }

  console.log('\n--- 現在の設定 ---');
  Object.keys(props).forEach(function(key) {
    if (key === 'PASSWORD_HASH') {
      console.log(key + ': ' + props[key].substring(0, 8) + '...');
    } else if (key.indexOf('ratelimit_') === 0 || key === 'granted_emails') {
      // ランタイムデータはスキップ
    } else {
      console.log(key + ': ' + props[key]);
    }
  });
}
