local sock = ngx.socket.tcp()
sock:settimeout(self.request_timeout)

local ok, err = sock:connect(self.host, self.port)
if not ok then
    return nil, "failed to connect: " .. err
end

-- wrap with TLS if enabled
if self.conf and self.conf.ssl then
    local ssl = require("ngx.ssl")
    local ssock, serr = ssl.wrap(sock, {
        mode       = "client",
        protocol   = (self.conf.ssl_opts and self.conf.ssl_opts.protocol) or "tlsv1_2",
        verify     = (self.conf.ssl_opts and self.conf.ssl_opts.verify) or "none",
        cafile     = self.conf.ssl_opts and self.conf.ssl_opts.cafile,
        certificate= self.conf.ssl_opts and self.conf.ssl_opts.certificate,
        key        = self.conf.ssl_opts and self.conf.ssl_opts.key,
    })

    if not ssock then
        return nil, "failed to wrap TLS: " .. (serr or "unknown")
    end

    local ok, herr = ssock:dohandshake()
    if not ok then
        return nil, "failed TLS handshake: " .. (herr or "unknown")
    end

    self.sock = ssock
else
    self.sock = sock
end
