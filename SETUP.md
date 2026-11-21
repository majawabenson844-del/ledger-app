# Shared financial dashboard setup

The app is a static website. It authenticates invited users with Supabase, encrypts the ledger in the browser, and syncs only encrypted data to one shared database row.

**Public sign-ups are disabled in this Supabase project. Keep them disabled; the app deliberately refuses to open while they are enabled.**

## 1. Configure Supabase

1. In Supabase, open **SQL Editor**, create a query, paste in [`supabase-setup.sql`](./supabase-setup.sql), and run it.
2. Open **Authentication → Sign In / Providers** and keep email/password sign-in enabled.
3. Keep **Allow new users to sign up** turned off. This is important: the database allows signed-in users to access the shared ledger, so accounts must only be created by invitation. The app checks this setting and will stay locked if sign-ups are enabled.
4. Review **Authentication → Users** and remove any accounts that should not have access. Then use **Invite user** to invite yourself and each person who should use the dashboard. Invited users should set their own account passwords from their invitation email.
5. In **Authentication → URL Configuration**, set the site URL and allowed redirect URL to the deployed dashboard URL in step 3. Add the URL with and without its trailing slash if needed for password-reset links.

`supabase-config.js` contains the Supabase project URL and publishable key provided for the browser app. Publishable keys are designed to be public; never put a `service_role` or secret key in this app or repository.

## 2. Publish from GitHub

1. Add these dashboard files to the root of `https://github.com/majawabenson844-del/ledger-app`: `index.html`, `styles.css`, `script.js`, `supabase-config.js`, and `.github/workflows/deploy.yml`.
2. In the repository, open **Settings → Pages** and set the build and deployment source to **GitHub Actions**. The repository is currently private; GitHub Pages availability and whether its site can be public depend on your GitHub plan and Pages visibility settings. If Pages will not publish a public site from this private repository, use Netlify with the repository or make a dedicated app-only repository public instead.
3. Push the files to the `main` or `master` branch, or run **Actions → Deploy private ledger app → Run workflow**.
4. Wait for the deployment to finish. GitHub Pages will show the shareable site URL in the workflow run or under **Settings → Pages**. For this repository, it is normally `https://majawabenson844-del.github.io/ledger-app/`.
5. Add that final URL to Supabase's **Authentication → URL Configuration** as the site URL and an allowed redirect URL.

The deployment workflow copies only the four app files into the published site; it does not publish other spreadsheets, PDFs, or files in the workspace.

## 3. First use and shared access

1. Open the published HTTPS link and sign in with an invited email account.
2. On first use, create a strong shared passphrase of at least 10 characters. Share it only with invited users over a separate, trusted channel.
3. Other invited users sign in with their own account and enter the same shared passphrase.
4. Use **Encrypted backup** regularly and store the downloaded file somewhere safe.

The passphrase is never sent to Supabase. Forgetting it means the encrypted cloud data cannot be recovered. The dashboard uses revision checks to avoid silently overwriting another user's update; when a newer edit arrives, use **Reload shared updates** before continuing. Live update notices use Supabase Realtime.

### Privacy notes

- The Supabase database stores encrypted ledger contents. Signed-in invited users who know the shared passphrase can decrypt and edit the same ledger.
- Keep public sign-ups disabled and invite only trusted people. Anyone who can sign in to this Supabase project and knows the shared passphrase can access the ledger.
- CSV exports are unencrypted and may contain private information.
- GitHub Pages serves a public link. The app itself requires invited-account sign-in and the shared passphrase.
