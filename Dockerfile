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

EXPOSE 10000
