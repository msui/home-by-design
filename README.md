# home-by-design

A private, password-protected single-page site.

`index.html` is encrypted. GitHub only stores ciphertext, and the page decrypts in the browser after the right password is entered. Visitors can tick **Remember on this device** to skip the prompt next time.

## Edit the site

The readable source is never committed. You recreate it from `index.html` with the password:

```sh
export SITE_PASSWORD='the-password'
node tools/crypt.mjs decrypt index.html private/guide.html   # get the source
# ...edit private/guide.html...
node tools/crypt.mjs encrypt private/guide.html index.html   # re-encrypt
git add index.html && git commit -m "Update site"
```

`private/` is git-ignored. Requires Node 18 or later.

## Change the password

Decrypt with the old password, then encrypt with the new one. Visitors who chose "remember" will be asked for the new password.

## Deploy on GitHub Pages

Settings → Pages → Source: *Deploy from a branch*, `main`, `/ (root)`.

## How it works

The page uses AES-256-GCM encryption with a key derived through PBKDF2-SHA256 (600,000 iterations). The encryption is real, but its strength depends entirely on the password: anyone can download the file and try passwords offline.
