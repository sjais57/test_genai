function _M:connect()
    local sock, err = ngx.socket.tcp()
    if not sock then
        return nil, "failed to create socket: " .. (err or "unknown")
    end
    sock:settimeout(self.conf.request_timeout or 1000)

    local ok, cerr = sock:connect(self.host, self.port)
    if not ok then
        return nil, "failed to connect: " .. (cerr or "unknown")
    end

    -- SSL/TLS handling
    if self.conf.ssl then
        local ssock, serr = ssl.wrap(sock, {
            mode        = "client",
            protocol    = (self.conf.ssl_opts and self.conf.ssl_opts.protocol) or "tlsv1_2",
            verify      = (self.conf.ssl_opts and self.conf.ssl_opts.verify) or "none",
            cafile      = self.conf.ssl_opts and self.conf.ssl_opts.cafile,
            certificate = self.conf.ssl_opts and self.conf.ssl_opts.certificate,
            key         = self.conf.ssl_opts and self.conf.ssl_opts.key,
        })

        if not ssock then
            return nil, "failed to wrap TLS: " .. (serr or "unknown")
        end

        local ok, herr = ssock:dohandshake()
        if not ok then
            return nil, "TLS handshake failed: " .. (herr or "unknown")
        end

        self.sock = ssock
        return ssock
    end

    -- default: plaintext
    self.sock = sock
    return sock
end
