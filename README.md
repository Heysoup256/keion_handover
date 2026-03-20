# GAS 認証・権限付与システム — 軽音部 引き継ぎ資料

後輩のメールアドレスが事前にわからなくても、**Google Sign-In + 共有パスワード** で引き継ぎ資料（Google Sites + Drive）のアクセス権を付与できる Web アプリです。

---

## 目次

1. [前提条件](#前提条件)
2. [Step 1: GAS プロジェクト作成（スプレッドシートにバインド）](#step-1-gas-プロジェクト作成スプレッドシートにバインド)
3. [Step 2: OAuth クライアント ID の取得](#step-2-oauth-クライアント-id-の取得)
4. [Step 3: clasp で GAS にアップロード](#step-3-clasp-で-gas-にアップロード)
5. [Step 4: Script Properties の設定](#step-4-script-properties-の設定)
6. [Step 5: Web アプリとしてデプロイ](#step-5-web-アプリとしてデプロイ)
7. [Step 6: OAuth 設定の更新](#step-6-oauth-設定の更新)
8. [Step 7: 動作テスト](#step-7-動作テスト)
9. [GitHub でコードを管理する](#github-でコードを管理する)
10. [セキュリティ対策](#セキュリティ対策)
11. [メンテナンス](#メンテナンス)

---

## 前提条件

- Google アカウント
- Node.js (v16 以上) ※ clasp 使用時のみ
- git ※ GitHub 管理時のみ

---

## Step 1: GAS プロジェクト作成（スプレッドシートにバインド）

認証ログをスプレッドシートに自動記録するため、**スプレッドシートにバインドして**作成します。

1. [Google Drive](https://drive.google.com/) を開く
2. **新規 → Google スプレッドシート** で新しいスプレッドシートを作成
3. スプレッドシートに適当な名前をつける（例: `軽音部 引き継ぎ認証システム`）
4. メニューバーの **拡張機能 → Apps Script** をクリック
5. GAS エディタが開くので、プロジェクト名を設定（例: `keion-auth`）

> ⚠️ この時点では、中身の編集は不要です。clasp で後からアップロードします。

---

## Step 2: OAuth クライアント ID の取得

Google Sign-In を使うために、Google Cloud Console で OAuth クライアント ID を作成する必要があります。

### 2-1. GAS プロジェクトの GCP プロジェクト番号を確認

1. GAS エディタを開く
2. 左サイドバーの **⚙ プロジェクトの設定** をクリック
3. **Google Cloud Platform (GCP) プロジェクト** のセクションを確認
   - デフォルトのプロジェクト番号が表示されています

GAS エディタからGCPダッシュボードへのリンクが無い場合:
1. [Google Cloud Console](https://console.cloud.google.com/) にアクセス
2. 上部のプロジェクトセレクターを確認

### 2-2. OAuth 同意画面の設定

> ❗**初回のみ必要な作業です。**

1. [Google Cloud Console](https://console.cloud.google.com/) を開く
2. 上部のプロジェクトセレクターで、GAS に紐づいたプロジェクトを選択
3. 左メニュー → **APIとサービス → OAuth 同意画面**
4. **User Type** で **外部** を選択 → **作成**
5. 以下を入力:
   - **アプリ名**: `軽音部 引き継ぎ認証` (任意)
   - **ユーザーサポートメール**: 自分のメールアドレス
   - **デベロッパーの連絡先情報**: 自分のメールアドレス
6. **保存して次へ** を繰り返し、最後まで進む
7. **公開ステータス** で **テスト → 本番** に変更（※ 後輩が使えるようにするため）

### 2-3. OAuth クライアント ID の作成

1. 左メニュー → **APIとサービス → 認証情報**
2. 上部の **＋ 認証情報を作成 → OAuth クライアント ID**
3. 以下を設定:
   - **アプリケーションの種類**: `ウェブ アプリケーション`
   - **名前**: `軽音部認証アプリ` (任意)
   - **承認済みの JavaScript 生成元**: 以下を追加
     ```
     https://script.google.com
     ```
     ※ デプロイ後にデプロイURLのオリジンも追加します（Step 6）
4. **作成** をクリック
5. 表示される **クライアント ID** をコピーしてメモ
   - 形式: `xxxxxxxxxxxx-xxxxxxxxxxxxxxxx.apps.googleusercontent.com`

---

## Step 3: clasp で GAS にアップロード

### 3-1. clasp のインストール

```bash
npm install -g @google/clasp
```

### 3-2. clasp にログイン

```bash
clasp login
```

ブラウザが開くので、GAS プロジェクトのオーナーの Google アカウントでログインします。

### 3-3. GAS プロジェクトの Script ID を取得

1. GAS エディタを開く（Step 1 で作成したプロジェクト）
2. 左サイドバーの **⚙ プロジェクトの設定**
3. **スクリプト ID** をコピー

### 3-4. clasp プロジェクトと紐づけ

このリポジトリのルートディレクトリで以下を実行:

```bash
cd keion_handover
clasp clone <スクリプトID>
```

これで `.clasp.json` が生成されます。

> ⚠️ `.clasp.json` にはスクリプト ID が入っているため、`.gitignore` で除外しています（秘匿情報のため）。

もし既に `.clasp.json` が無い状態から始める場合は、手動で作成しても OK:

```json
{
  "scriptId": "ここにスクリプトIDを貼る",
  "rootDir": "."
}
```

### 3-5. GAS にコードをアップロード (push)

```bash
clasp push
```

> 「Manifest file has been updated. Do you want to push and overwrite?」と聞かれたら `y` を入力。

`.claspignore` に記載されたファイル（`README.md`, `.gitignore` 等）はアップロードされません。
`Code.gs` と `Index.html` のみが GAS にアップロードされます。

### 3-6. GAS エディタで確認

```bash
clasp open
```

ブラウザで GAS エディタが開くので、`Code.gs` と `Index.html` がアップロードされていることを確認してください。

---

## Step 4: Script Properties の設定

GAS エディタ → **⚙ プロジェクトの設定** → **スクリプト プロパティ** に以下を追加:

| プロパティ名 | 値 | 必須 |
|---|---|:---:|
| `GOOGLE_CLIENT_ID` | Step 2 で取得したクライアント ID | ✅ |
| `PASSWORD_HASH` | 下記の手順で生成した SHA-256 ハッシュ | ✅ |
| `DRIVE_IDS` | 共有するファイル/フォルダの ID（カンマ区切り） | ✅ |
| `SITES_FILE_ID` | Google Sites のファイル ID | ✅ |
| `ALLOWED_DOMAINS` | 許可するメールドメイン（カンマ区切り） | |
| `MAX_ATTEMPTS` | 最大試行回数（デフォルト: 5） | |
| `LOCKOUT_MINUTES` | ロックアウト時間/分（デフォルト: 30） | |

### パスワードハッシュの生成方法

1. GAS エディタで `Code.gs` を開く
2. 関数セレクターで `generatePasswordHash` を選択
3. ▶ ボタンをクリックして実行
4. 「実行ログ」にハッシュ値が出力される
5. そのハッシュ値を `PASSWORD_HASH` として設定

> ⚠️ デフォルトでは `ここにパスワードを入力` のハッシュが生成されます。
> 実際のパスワードを使うには、関数内の引数を書き換えてから実行してください:
> ```javascript
> generatePasswordHash('実際のパスワード')
> ```

### ファイル/フォルダ ID の取得方法

**Google Sites のファイル ID:**
```
https://sites.google.com/d/XXXXXXXXXXXXX/p/...
//                          ↑ これがファイル ID
```

**Google Drive のファイル/フォルダ ID:**
```
https://drive.google.com/file/d/XXXXXXXXXXXXX/view
https://drive.google.com/drive/folders/XXXXXXXXXXXXX
//                                      ↑ これが ID
```

### 設定確認

GAS エディタで `checkSetup()` を実行して、設定が正しいか確認してください。

---

## Step 5: Web アプリとしてデプロイ

### GAS エディタからデプロイ

1. GAS エディタ → **デプロイ → 新しいデプロイ**
2. **種類の選択** → ⚙ → **ウェブアプリ**
3. 以下を設定:
   - **説明**: `軽音部 引き継ぎ資料 認証システム` (任意)
   - **次のユーザーとして実行**: **自分**
   - **アクセスできるユーザー**: **全員**
4. **デプロイ** をクリック
5. 表示される **ウェブアプリ URL** をコピー

### clasp からデプロイ（コマンドライン）

```bash
clasp deploy --description "v1.0"
```

> ⚠️ 初回は GAS エディタからデプロイすることを推奨します（アクセス権の設定が GUI で確認しやすいため）。

---

## Step 6: OAuth 設定の更新

デプロイ URL を取得したら、**Google Cloud Console** に戻って OAuth 設定を更新します。

1. [Google Cloud Console](https://console.cloud.google.com/) → **APIとサービス → 認証情報**
2. Step 2 で作成した OAuth クライアント ID をクリック
3. **承認済みの JavaScript 生成元** に以下を追加:
   ```
   https://script.google.com
   ```
   ※ 通常 `https://script.google.com` だけで動作しますが、うまくいかない場合はデプロイ URL から
   オリジン部分（`https://script.google.com` まで）を追加してください。

---

## Step 7: 動作テスト

1. **別の Google アカウント**（テスト用）でデプロイ URL にアクセス
2. 「Google でログイン」ボタンをクリック
3. Google アカウントを選択（メールアドレスが自動取得される）
4. 共有パスワードを入力 → 「アクセス権を申請」
5. 成功メッセージが表示されれば完了 🎉
6. バインド先のスプレッドシートに「ログ」シートが作成され、試行が記録されていることを確認

---

## GitHub でコードを管理する

### 初期セットアップ

```bash
cd keion_handover

# Git 初期化
git init

# 全ファイルをステージング
git add .

# 初回コミット
git commit -m "feat: 認証・権限付与システム初期実装"

# GitHub リポジトリを作成（GitHub CLI の場合）
gh repo create keion_handover --public --source=. --push

# GitHub CLI がない場合は、GitHub のWebサイトで空リポジトリを作成してから:
git remote add origin https://github.com/あなたのID/keion_handover.git
git branch -M main
git push -u origin main
```

### 安全に公開できる理由

以下のファイルは `.gitignore` で除外、または Script Properties に分離しているため、GitHub にプッシュしても秘匿情報は漏れません:

| 秘匿情報 | 保管場所 | Git管理 |
|---|---|:---:|
| OAuth クライアント ID | Script Properties (`GOOGLE_CLIENT_ID`) | ❌ 除外 |
| パスワードハッシュ | Script Properties (`PASSWORD_HASH`) | ❌ 除外 |
| ファイル/フォルダ ID | Script Properties (`DRIVE_IDS`, `SITES_FILE_ID`) | ❌ 除外 |
| スクリプト ID | `.clasp.json` | ❌ `.gitignore` で除外 |

### 日常的なワークフロー

```bash
# 1. コードを編集

# 2. GAS にアップロード
clasp push

# 3. GAS エディタで動作確認
clasp open

# 4. Git にコミット
git add .
git commit -m "fix: 〇〇を修正"

# 5. GitHub にプッシュ
git push
```

### コードを変更した後の再デプロイ

`clasp push` でコードを更新した後、**デプロイを更新**する必要があります:

```bash
# デプロイ一覧を確認
clasp deployments

# 既存のデプロイを更新（デプロイIDを指定）
clasp deploy --deploymentId <デプロイID> --description "v1.1 - 〇〇を修正"
```

または GAS エディタで:
1. **デプロイ → デプロイを管理**
2. 既存デプロイの ✏️（編集）アイコンをクリック
3. バージョンを **新しいバージョン** に変更
4. **デプロイ** をクリック

---

## セキュリティ対策

| 対策 | 説明 |
|---|---|
| サーバーサイド ID Token 検証 | Google API で検証、`aud` チェック、有効期限チェック |
| パスワードハッシュ化 | SHA-256 ハッシュとして保存、平文をコードに含まない |
| Nonce トークン (CSRF対策) | リプレイ攻撃防止のワンタイムトークン |
| レート制限 | 同一メールアドレスに対する試行回数制限 + ロックアウト |
| ドメイン制限 | 特定ドメインのメールのみ許可可能 |
| 権限付与済み記録 | 二重付与を防止 |
| 秘匿情報の分離 | Script Properties に格納、コードに秘匿情報なし |

---

## メンテナンス

### 期限切れ nonce のクリーンアップ

`cleanupExpiredNonces()` を定期的に実行（トリガー設定推奨）して、期限切れの nonce トークンを削除してください。

GAS エディタでトリガーを設定する場合:
1. 左サイドバー → **⏰ トリガー**
2. **＋ トリガーを追加**
3. 関数: `cleanupExpiredNonces` / イベント: 時間主導型 / 毎日

### ログの確認

バインド先のスプレッドシートの「ログ」シートで認証試行の履歴を確認できます。
