# Kelo PDS deliberately stays very close to upstream.
# Pin the image so database/application changes are reviewed before upgrades.
FROM ghcr.io/bluesky-social/pds:0.4.219

# Render routes traffic to the port configured by PDS_PORT.
EXPOSE 10000
