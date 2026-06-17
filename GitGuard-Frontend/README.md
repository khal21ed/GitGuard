# GitGuard Frontend

A simple React frontend for scanning GitHub repositories with the GitGuard backend.

## Setup

Install dependencies:

```bash
npm install
```

Run the dev server:

```bash
npm run dev
```

By default the app calls:

```text
https://localhost:7221
```

To point at a different backend, create `.env.local`:

```text
VITE_API_BASE_URL=https://localhost:7221
```
