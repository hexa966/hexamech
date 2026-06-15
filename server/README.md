# Hexamech secure backend

This server lets the quotation app keep the same employee username/password login while Firebase Realtime Database rules stay fully locked.

## What changes

- Employees still open the quotation app and sign in with the same usernames/passwords.
- The browser no longer talks directly to Firebase.
- This server verifies the quotation app user, then reads/writes Firebase privately using Firebase Admin credentials.
- Firebase Realtime Database rules can be changed to:

```json
{
  "rules": {
    ".read": false,
    ".write": false
  }
}
```

## Setup

1. Install dependencies:

```bash
npm install
```

2. Copy `.env.example` to `.env`.

3. In Firebase Console, open `Project settings > Service accounts > Generate new private key`.

4. Save that JSON file somewhere private on the server, not inside this project folder.

5. Set these values in `.env`:

```env
GOOGLE_APPLICATION_CREDENTIALS=C:\secure\path\service-account.json
FIREBASE_DATABASE_URL=https://hexamech-2c6f5-default-rtdb.firebaseio.com
FIREBASE_DATA_PATH=/hexamech/data
SESSION_SECRET=use-a-long-random-secret-here
```

6. Start the server:

```bash
npm start
```

7. Open the app from the server URL, for example:

```text
http://localhost:3000
```

## If the app stays on GitHub Pages

Deploy this server to a hosting provider first, then point the static app to that backend URL:

```js
localStorage.setItem('hx_api_base', 'https://your-backend-url.com');
location.reload();
```

For that setup, also set `CORS_ORIGIN` on the server:

```env
CORS_ORIGIN=https://hexa966.github.io
```

## Important

Never put the Firebase service account JSON, private key, or admin secret into `index.html`. Keep those only on the server.
