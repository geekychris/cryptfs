# Solr with Encrypted Index using gocryptfs
# The Solr index is stored in a gocryptfs-encrypted directory.
# The host-mounted volume only ever contains ciphertext.
FROM solr:9

USER root

# Install gocryptfs (FUSE-based encrypted filesystem)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gocryptfs \
    fuse3 \
    && rm -rf /var/lib/apt/lists/*

# Allow non-root FUSE mounts
RUN echo "user_allow_other" >> /etc/fuse.conf

# Create directories for encrypted/decrypted data
RUN mkdir -p /data/encrypted /data/decrypted \
    && chown -R solr:solr /data

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 8983

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
