# 軽音部 引き継ぎ資料アクセス認証システム

このプロジェクトは、軽音部の後輩に対して、Google Drive や Google Sites へのアクセス権限を自動かつ安全に付与するためのシステムです。

**設計の特徴（Vercel/Netlify + GAS 連携版）:**
- **URL の秘匿性**: Vercel/Netlify が生成するランダムで推測不可能な URL を利用します。
- **リポジトリの完全非公開 (Private)**: GitHub でリポジトリを Private に設定できるため、あなたのコードを世界に公開する必要がありません。
- **最高の UX と安定稼働**: Google Identity Services (GIS) によるワンクリックログインを採用しつつ、GAS 固有の「複数アカウントログイン時の無限リダイレクトバグ（`/exec` の問題）」をフロントエンドとバックエンドを分離することで完全に回避しています。

---

## セットアップ手順

セットアップは「バックエンド (GAS)」→「フロントエンド (Vercel/Netlify)」の順に行います。

### Step 1: GAS のデプロイ (バックエンドの準備)

1. Google Drive 上で新規スプレッドシートを開き、**「拡張機能」 > 「Apps Script」** を開きます。
2. リポジトリ内の `Code.gs` と `Index.html` の中身をコピーして貼り付けます。
3. 右上の歯車アイコン ⚙️（プロジェクトの設定）を開き、一番下の「スクリプト プロパティ」に以下を登録します。
   - `PASSWORD_HASH`: 後輩に教えるパスワードの SHA-256 ハッシュ（※ `generatePasswordHash` 関数を実行して取得）
   - `DRIVE_IDS`: 権限付与対象の Drive ファイル/フォルダ ID（カンマ区切り）
   - `SITES_FILE_ID`: 権限付与対象の Google Sites ファイル ID
4. 「デプロイ」 > 「新しいデプロイ」から「ウェブアプリ」としてデプロイします。
   - 実行ユーザー: **自分**
   - アクセスできるユーザー: **全員**
5. 発行された **ウェブアプリの URL** (`https://script.google.com/macros/s/.../exec`) をコピーして控えます。

### Step 2: Google Cloud Console で OAuth 設定

1. [Google Cloud Console](https://console.cloud.google.com/) にアクセスし、「API とサービス」 > 「認証情報」を開きます。
2. **「＋認証情報を作成」 > 「OAuth クライアント ID」**（ウェブアプリケーション）を作成します。
3. 発行された **クライアント ID** をコピーして控えます。
4. ※この時点ではまだ「承認済みの JavaScript 生成元」は空のままで進めてください。
5. （省略可）GAS エディタに戻り、スクリプトプロパティに `GOOGLE_CLIENT_ID` としてこのクライアントIDを設定します。

### Step 3: フロントエンドコードの設定と Push

1. 手元（ローカル）にある `frontend/index.html` のソースコードをエディタで開きます。
2. コードの後半 `<script>` タグ内にある以下の2箇所を、先ほど取得した文字列に書き換えます。
   - `const GAS_EXEC_URL = 'https://script.google.com/.../exec';`
   - `const GOOGLE_CLIENT_ID = '3879...apps.googleusercontent.com';`
3. このリポジトリを自分の GitHub にプッシュします。**（※リポジトリは「Private（非公開）」に設定してください！）**

### Step 4: Vercel (または Netlify) へのデプロイ

1. **Vercel** (`vercel.com`) にアクセスし、GitHub アカウントでログイン・連携します。
2. 「Add New Project」から、Push した今回のお使いの GitHub リポジトリ（Private）を選択します。
3. プロジェクト設定で、**Root Directory (ルートディレクトリ)** の項目を `frontend` に変更します。
4. 「Deploy」ボタンを押します。これで推測不可能な URL（例: `https://keion-auth-xxx.vercel.app`）付きであなた専用の認証ページが世界に公開されます。（※コード自体は見えません）
5. デプロイ完了後、発行された Vercel の URL をコピーします。

### Step 5: Google Cloud Console の最終設定（重要）

1. 再び GCP の「OAuth クライアント ID」の設定画面を開きます。
2. **「承認済みの JavaScript 生成元」** (Authorized JavaScript origins) に、手順 4-5 でコピーした **Vercel の URL** (例: `https://keion-auth-xxx.vercel.app`) を登録し、「保存」を押します。
   *(※末尾のスラッシュは入れないでください)*

---

## 運用方法

- これですべての準備が完了です。Vercel の URL にアクセスし、「Google でログイン」→ パスワード入力 の流れをテストしてください。
- 後輩には、完成した **Vercel の URL** と、自分で設定した **共有パスワード** の2つを伝えるだけで引き継ぎが完了します！

※ GAS のコード（バックエンド）を変更した場合は、必ず GAS 上で「デプロイを管理」から**新バージョンとしてデプロイ**し直す必要があります。URLは変わりません。
