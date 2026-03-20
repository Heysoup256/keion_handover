/**
 * 軽音部 引き継ぎ資料 認証・権限付与システム
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
 * GET リクエストを処理し、認証ページを返す
 */
function doGet() {
  const template = HtmlService.createTemplateFromFile('Index');
  template.clientId = getProperty_('GOOGLE_CLIENT_ID');

  // CSRF 対策用の nonce トークンを生成・保存
  const nonce = generateNonce_();
  template.nonce = nonce;

  return template.evaluate()
    .setTitle('軽音部 引き継ぎ資料 アクセス申請')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1');
}

// ============================================================
// 認証・権限付与
// ============================================================

/**
 * メイン認証関数 — クライアントから呼び出される
 * @param {string} idToken - Google Sign-In から取得した ID Token
 * @param {string} password - ユーザーが入力した共有パスワード
 * @param {string} nonce - CSRF 対策用の nonce トークン
 * @returns {Object} { success: boolean, message: string }
 */
function verifyAndGrantAccess(idToken, password, nonce) {
  try {
    // 0. Nonce 検証（リプレイ攻撃対策）
    if (!verifyNonce_(nonce)) {
      return { success: false, message: '無効なリクエストです。ページを再読み込みしてください。' };
    }

    // 1. ID Token を Google API で検証
    const userInfo = verifyIdToken_(idToken);
    if (!userInfo.success) {
      logAttempt_(null, false, 'ID Token 検証失敗');
      return { success: false, message: userInfo.message };
    }
    const email = userInfo.email;

    // 2. レート制限チェック
    const rateCheck = checkRateLimit_(email);
    if (!rateCheck.allowed) {
      logAttempt_(email, false, 'レート制限超過');
      return { success: false, message: rateCheck.message };
    }

    // 3. ドメイン制限チェック
    const domainCheck = checkDomain_(email);
    if (!domainCheck.allowed) {
      recordAttempt_(email, false);
      logAttempt_(email, false, 'ドメイン制限');
      return { success: false, message: domainCheck.message };
    }

    // 4. パスワード照合（SHA-256 ハッシュ比較）
    const inputHash = hashPassword_(password);
    const storedHash = getProperty_('PASSWORD_HASH');
    if (inputHash !== storedHash) {
      recordAttempt_(email, false);
      const remaining = getRemainingAttempts_(email);
      logAttempt_(email, false, 'パスワード不一致');
      return {
        success: false,
        message: 'パスワードが正しくありません。' +
          (remaining > 0 ? '（残り ' + remaining + ' 回）' : '')
      };
    }

    // 5. 既に権限付与済みかチェック
    if (isAlreadyGranted_(email)) {
      logAttempt_(email, true, '付与済み（スキップ）');
      return { success: true, message: 'すでにアクセス権が付与されています。' };
    }

    // 6. 権限付与
    const grantResult = grantPermissions_(email);
    if (!grantResult.success) {
      logAttempt_(email, false, '権限付与エラー: ' + grantResult.message);
      return { success: false, message: grantResult.message };
    }

    // 7. 成功記録
    recordAttempt_(email, true);
    recordGrantedEmail_(email);
    logAttempt_(email, true, '権限付与成功');

    return {
      success: true,
      message: 'アクセス権を付与しました！\nGoogle Drive および Google Sites にアクセスできるようになりました。'
    };

  } catch (e) {
    console.error('verifyAndGrantAccess error:', e);
    logAttempt_(null, false, 'システムエラー: ' + e.message);
    return { success: false, message: '予期しないエラーが発生しました。管理者に連絡してください。' };
  }
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
    const url = 'https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(idToken);
    const response = UrlFetchApp.fetch(url, { muteHttpExceptions: true });
    const code = response.getResponseCode();

    if (code !== 200) {
      return { success: false, message: 'Google 認証に失敗しました。もう一度お試しください。' };
    }

    const payload = JSON.parse(response.getContentText());
    const clientId = getProperty_('GOOGLE_CLIENT_ID');

    // aud (audience) がこのアプリのクライアント ID と一致するか検証
    if (payload.aud !== clientId) {
      return { success: false, message: '不正な認証トークンです。' };
    }

    // トークンの有効期限チェック
    const now = Math.floor(Date.now() / 1000);
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
    return { success: false, message: 'トークン検証中にエラーが発生しました。' };
  }
}

// ============================================================
// Nonce トークン（CSRF 対策）
// ============================================================

/**
 * nonce トークンを生成し、Script Properties に保存
 * @returns {string} nonce
 */
function generateNonce_() {
  const nonce = Utilities.getUuid();
  const props = PropertiesService.getScriptProperties();
  const key = 'nonce_' + nonce;
  // 有効期限: 10分
  const expiry = Date.now() + 10 * 60 * 1000;
  props.setProperty(key, String(expiry));
  return nonce;
}

/**
 * nonce トークンを検証し、使用済みとして削除する（ワンタイムトークン）
 * @param {string} nonce
 * @returns {boolean}
 */
function verifyNonce_(nonce) {
  if (!nonce) return false;
  const props = PropertiesService.getScriptProperties();
  const key = 'nonce_' + nonce;
  const expiry = props.getProperty(key);

  if (!expiry) return false;

  // 使用済みとして即削除（ワンタイム）
  props.deleteProperty(key);

  // 有効期限チェック
  if (Date.now() > parseInt(expiry)) return false;

  return true;
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
  const props = PropertiesService.getScriptProperties();
  const key = 'ratelimit_' + email;
  const data = props.getProperty(key);

  if (!data) {
    return { allowed: true };
  }

  const record = JSON.parse(data);
  const maxAttempts = parseInt(getProperty_('MAX_ATTEMPTS') || '5');
  const lockoutMinutes = parseInt(getProperty_('LOCKOUT_MINUTES') || '30');
  const lockoutMs = lockoutMinutes * 60 * 1000;

  // ロックアウト期間が過ぎていればリセット
  if (record.lockedUntil && Date.now() > record.lockedUntil) {
    props.deleteProperty(key);
    return { allowed: true };
  }

  // ロックアウト中
  if (record.lockedUntil && Date.now() <= record.lockedUntil) {
    const remainMin = Math.ceil((record.lockedUntil - Date.now()) / 60000);
    return {
      allowed: false,
      message: '試行回数の上限に達しました。' + remainMin + '分後に再試行してください。'
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
    message: '試行回数の上限に達しました。' + lockoutMinutes + '分後に再試行してください。'
  };
}

/**
 * 試行を記録
 * @param {string} email
 * @param {boolean} success
 */
function recordAttempt_(email, success) {
  const props = PropertiesService.getScriptProperties();
  const key = 'ratelimit_' + email;

  if (success) {
    // 成功したらレート制限をリセット
    props.deleteProperty(key);
    return;
  }

  const data = props.getProperty(key);
  let record = data ? JSON.parse(data) : { failCount: 0 };
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
  const props = PropertiesService.getScriptProperties();
  const key = 'ratelimit_' + email;
  const data = props.getProperty(key);
  const maxAttempts = parseInt(getProperty_('MAX_ATTEMPTS') || '5');

  if (!data) return maxAttempts - 1;
  const record = JSON.parse(data);
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
  const domainsStr = getProperty_('ALLOWED_DOMAINS');
  if (!domainsStr || domainsStr.trim() === '') {
    return { allowed: true }; // 制限なし
  }

  const allowedDomains = domainsStr.split(',').map(function(d) { return d.trim().toLowerCase(); });
  const emailDomain = email.split('@')[1].toLowerCase();

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
  const errors = [];

  // Drive ファイル/フォルダに権限付与
  const driveIdsStr = getProperty_('DRIVE_IDS');
  if (driveIdsStr && driveIdsStr.trim() !== '') {
    const driveIds = driveIdsStr.split(',').map(function(id) { return id.trim(); });
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
        errors.push(id);
      }
    });
  }

  // Google Sites に権限付与（Sites も Drive ファイルとして管理されている）
  const sitesFileId = getProperty_('SITES_FILE_ID');
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
      message: '一部のファイルへの権限付与に失敗しました（' + errors.join(', ') + '）。管理者に連絡してください。'
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
  const props = PropertiesService.getScriptProperties();
  const granted = props.getProperty('granted_emails');
  if (!granted) return false;
  const list = JSON.parse(granted);
  return list.indexOf(email.toLowerCase()) !== -1;
}

/**
 * 権限付与済みメールアドレスを記録
 * @param {string} email
 */
function recordGrantedEmail_(email) {
  const props = PropertiesService.getScriptProperties();
  const granted = props.getProperty('granted_emails');
  const list = granted ? JSON.parse(granted) : [];
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
  const rawHash = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, password, Utilities.Charset.UTF_8);
  return rawHash.map(function(byte) {
    // 符号なしバイトに変換して16進数文字列に
    var v = (byte < 0) ? byte + 256 : byte;
    return ('0' + v.toString(16)).slice(-2);
  }).join('');
}

// ============================================================
// スプレッドシートへのログ記録
// ============================================================

/**
 * 認証試行をバインド先のスプレッドシートにログ記録する。
 * 「ログ」シートがなければ自動作成する。
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
      // ヘッダー行を太字に
      sheet.getRange(1, 1, 1, 4).setFontWeight('bold');
      sheet.setFrozenRows(1);
      // 列幅を調整
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

/**
 * Script Properties から値を取得
 * @param {string} key
 * @returns {string|null}
 */
function getProperty_(key) {
  return PropertiesService.getScriptProperties().getProperty(key);
}

// ============================================================
// セットアップ用ヘルパー（手動実行用）
// ============================================================

/**
 * パスワードの SHA-256 ハッシュを生成するヘルパー関数。
 * GAS エディタで手動実行して、出力されたハッシュを
 * Script Properties の PASSWORD_HASH に設定してください。
 * 
 * 使用方法:
 *   1. 関数名の右の▶で実行（引数を変更してから）
 *   2. または GAS エディタのコンソールで generatePasswordHash('あなたのパスワード') を実行
 * 
 * @param {string} password - ハッシュ化したいパスワード
 */
function generatePasswordHash(password) {
  if (!password || password === 'ここにパスワードを入力') {
    password = 'ここにパスワードを入力';  // デモ用
  }
  var hash = hashPassword_(password);
  console.log('=== パスワードハッシュ生成 ===');
  console.log('入力: ' + password);
  console.log('SHA-256 ハッシュ: ' + hash);
  console.log('');
  console.log('↑ このハッシュ値を Script Properties の PASSWORD_HASH に設定してください。');
  return hash;
}

/**
 * 初期設定を確認するヘルパー関数。
 * GAS エディタで手動実行して、現在の Script Properties を確認できます。
 */
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
    console.log('⚠️ 以下の Script Properties が未設定です:');
    console.log(missing.join(', '));
    console.log('\nGAS エディタ → プロジェクトの設定 → スクリプト プロパティ で設定してください。');
  } else {
    console.log('✅ 必須の Script Properties はすべて設定されています。');
  }

  console.log('\n--- 現在の設定 ---');
  Object.keys(props).forEach(function(key) {
    // 秘匿情報は一部マスク
    if (key === 'PASSWORD_HASH') {
      var val = props[key];
      console.log(key + ': ' + val.substring(0, 8) + '...');
    } else if (key.indexOf('ratelimit_') === 0 || key === 'granted_emails' || key.indexOf('nonce_') === 0) {
      // ランタイムデータはスキップ
    } else {
      console.log(key + ': ' + props[key]);
    }
  });

  // 付与済みメール一覧
  var granted = props['granted_emails'];
  if (granted) {
    console.log('\n--- 権限付与済みメールアドレス ---');
    JSON.parse(granted).forEach(function(e) { console.log('  ' + e); });
  }

  // スプレッドシートバインド確認
  try {
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    if (ss) {
      console.log('\n✅ スプレッドシートにバインドされています: ' + ss.getName());
    }
  } catch (e) {
    console.log('\n⚠️ スプレッドシートにバインドされていません。ログ記録は無効です。');
  }
}

/**
 * 期限切れの nonce トークンをクリーンアップする。
 * 必要に応じてトリガーで定期実行してください。
 */
function cleanupExpiredNonces() {
  var props = PropertiesService.getScriptProperties();
  var allProps = props.getProperties();
  var now = Date.now();
  var cleaned = 0;

  Object.keys(allProps).forEach(function(key) {
    if (key.indexOf('nonce_') === 0) {
      var expiry = parseInt(allProps[key]);
      if (now > expiry) {
        props.deleteProperty(key);
        cleaned++;
      }
    }
  });

  console.log('クリーンアップ完了: ' + cleaned + ' 件の期限切れ nonce を削除しました。');
}
