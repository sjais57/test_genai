-- Add this function to handle SSL connections
local function create_ssl_connection(host, port, config)
    local sock = ngx.socket.tcp()
    sock:settimeout(config.socket_timeout or 3000) -- 3 seconds default
    
    -- Handle SSL
    if config.ssl then
        local ssl_ok, ssl_err = sock:sslhandshake(nil, host, config.ssl_verify)
        if not ssl_ok then
            return nil, "SSL handshake failed: " .. (ssl_err or "unknown error")
        end
    end
    
    local ok, err = sock:connect(host, port)
    if not ok then
        return nil, "failed to connect to " .. host .. ":" .. port .. ": " .. err
    end
    
    -- Handle SASL authentication if enabled
    if config.sasl then
        local auth_ok, auth_err = authenticate_sasl(sock, config)
        if not auth_ok then
            return nil, "SASL authentication failed: " .. (auth_err or "unknown error")
        end
    end
    
    return sock
end

-- SASL authentication function
local function authenticate_sasl(sock, config)
    -- Implement SASL authentication based on mechanism
    if config.sasl_mechanism == "PLAIN" then
        -- Implement PLAIN authentication
        local auth_message = "\0" .. config.sasl_username .. "\0" .. config.sasl_password
        -- Send SASL authentication request
        -- This is a simplified version - you'll need to implement the full SASL handshake
    end
    -- Add other mechanisms: SCRAM-SHA-256, SCRAM-SHA-512
    return true
end
