# Kelo PDS deliberately stays very close to upstream.
# Pin the image so database/application changes are reviewed before upgrades.
FROM ghcr.io/bluesky-social/pds:0.4.219

# Disable the upstream OAuth hCaptcha configuration.
# envStr() treats empty values as undefined, so OAuthProvider receives no hCaptcha config.
ENV PDS_HCAPTCHA_SITE_KEY="" \
    PDS_HCAPTCHA_SECRET_KEY="" \
    PDS_HCAPTCHA_TOKEN_SALT=""

# Preserve the OAuth compatibility fix for same-site browser requests.
RUN sed -i "s/\['same-origin', 'cross-site', 'none'\]/['same-origin', 'same-site', 'cross-site', 'none']/" /app/node_modules/.pnpm/@atproto+oauth-provider@0.16.0/node_modules/@atproto/oauth-provider/dist/router/create-authorization-page-middleware.js

# E-mails Kelo Social (logo + textes en français)
COPY custom-mail/dist-templates/ /app/node_modules/.pnpm/@atproto+pds@0.4.219/node_modules/@atproto/pds/dist/mailer/templates/

# Kelo ID password proofs: keep the signing secret on the PDS and persist replay
# protection on the existing /pds volume. The patch scripts fail the build if
# the pinned upstream bundle no longer matches the reviewed integration point.
COPY custom-pds/kelo-proof.js /app/node_modules/.pnpm/@atproto+pds@0.4.219/node_modules/@atproto/pds/dist/account-manager/kelo-proof.js
COPY custom-pds/patch-login.js /tmp/patch-login.js
COPY custom-pds/patch-api.js /tmp/patch-api.js
RUN node /tmp/patch-login.js /app/node_modules/.pnpm/@atproto+pds@0.4.219/node_modules/@atproto/pds/dist/account-manager/account-manager.js \
    && node /tmp/patch-api.js /app/node_modules/.pnpm/@atproto+pds@0.4.219/node_modules/@atproto/pds/dist/index.js \
    && rm /tmp/patch-login.js /tmp/patch-api.js


EXPOSE 10000
