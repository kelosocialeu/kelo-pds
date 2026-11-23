# Kelo PDS deliberately stays very close to upstream.
# Pin the image so database/application changes are reviewed before upgrades.
FROM ghcr.io/bluesky-social/pds:0.4.219

# Disable the upstream OAuth hCaptcha configuration.
# envStr() treats empty values as undefined, so OAuthProvider receives no hCaptcha config.
ENV PDS_HCAPTCHA_SITE_KEY="" \
    PDS_HCAPTCHA_SECRET_KEY="" \
    PDS_HCAPTCHA_TOKEN_SALT=""

# QR rendering for the Kelo ID OAuth authorization screen.
RUN npm install --prefix /opt/kelo-pds-qrcode --omit=dev --ignore-scripts qrcode@1.5.4

# Preserve the OAuth compatibility fix for same-site browser requests.
RUN sed -i "s/\['same-origin', 'cross-site', 'none'\]/['same-origin', 'same-site', 'cross-site', 'none']/" /app/node_modules/.pnpm/@atproto+oauth-provider@0.16.0/node_modules/@atproto/oauth-provider/dist/router/create-authorization-page-middleware.js

# Kelo Social email templates and branding.
COPY custom-mail/dist-templates/ /app/node_modules/.pnpm/@atproto+pds@0.4.219/node_modules/@atproto/pds/dist/mailer/templates/

# Kelo ID proofs are signed and verified only inside the PDS.
# The signing key is derived from the existing PDS_JWT_SECRET.
# Replay markers live on the existing persistent /pds volume.
COPY custom-pds/kelo-proof.js /app/node_modules/.pnpm/@atproto+pds@0.4.219/node_modules/@atproto/pds/dist/account-manager/kelo-proof.js
COPY custom-pds/kelo-oauth-qr.js /app/node_modules/.pnpm/@atproto+pds@0.4.219/node_modules/@atproto/pds/dist/kelo-oauth-qr.js
COPY custom-pds/kelo-oauth-qr.test.js /tmp/kelo-oauth-qr.test.js
RUN node --check /app/node_modules/.pnpm/@atproto+pds@0.4.219/node_modules/@atproto/pds/dist/kelo-oauth-qr.js && node /tmp/kelo-oauth-qr.test.js /app/node_modules/.pnpm/@atproto+pds@0.4.219/node_modules/@atproto/pds/dist/kelo-oauth-qr.js && rm /tmp/kelo-oauth-qr.test.js
COPY custom-pds/patch-login.js /tmp/patch-login.js
COPY custom-pds/patch-api.js /tmp/patch-api.js
RUN node /tmp/patch-login.js /app/node_modules/.pnpm/@atproto+pds@0.4.219/node_modules/@atproto/pds/dist/account-manager/account-manager.js \
    && node /tmp/patch-api.js /app/node_modules/.pnpm/@atproto+pds@0.4.219/node_modules/@atproto/pds/dist/index.js \
    && rm /tmp/patch-login.js /tmp/patch-api.js

EXPOSE 10000
