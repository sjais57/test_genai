if self.config.ssl and times == 0 then
    -- optional: load custom CA
    if self.config.ssl_cafile then
        local ok, err = sock:sslhandshake(false, self.host, self.config.ssl_verify, self.config.ssl_cafile)
        if not ok then
            return nil, "failed SSL handshake with CA at " .. self.config.ssl_cafile ..
                        " err: " .. err, true
        end
    else
        local ok, err = sock:sslhandshake(false, self.host, self.config.ssl_verify)
        if not ok then
            return nil, "failed SSL handshake with " ..
                        self.host .. ":" .. tostring(self.port) ..
                        " err:" .. err, true
        end
    end

    -- optional: client cert/key for mTLS
    if self.config.ssl_cert and self.config.ssl_key then
        local ok, err = sock:setclientcert(self.config.ssl_cert, self.config.ssl_key)
        if not ok then
            return nil, "failed to set client cert/key: " .. (err or "unknown"), true
        end
    end
end
