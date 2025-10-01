local response   = require "resty.kafka.response"
local request    = require "resty.kafka.request"
local to_int32   = response.to_int32
local setmetatable = setmetatable
local tcp        = ngx.socket.tcp
local pid        = ngx.worker.pid
local tostring   = tostring
local sasl       = require "resty.kafka.sasl"

local M = {}
local mt = { __index = M }

-- socket send/receive helper
local function _sock_send_recieve(sock, request)
    local bytes, err = sock:send(request:package())
    if not bytes then
        return nil, err, true
    end

    local len, err = sock:receive(4)
    if not len then
        if err == "timeout" then
            sock:close()
        end
        return nil, err, true
    end

    local data, err = sock:receive(to_int32(len))
    if not data then
        if err == "timeout" then
            sock:close()
        end
        return nil, err, true
    end

    return response:new(data, request.api_version), nil, true
end

-- SASL Handshake
local function _sasl_handshake(sock, brk)
    local cli_id = "worker" .. pid()
    local req = request:new(request.SaslHandshakeRequest, 0, cli_id, request.API_VERSION_V1)

    req:string(brk.auth.mechanism)

    local resp, err = _sock_send_recieve(sock, req, brk.config)
    if not resp then
        return nil, err
    end

    local err_code = resp:int16()
    if err_code ~= 0 then
        local error_msg = resp:string()
        return nil, error_msg
    end
    return true
end

-- SASL Authentication
local function sasl_auth(sock, brk)
    local cli_id = "worker" .. pid()
    local req = request:new(request.SaslAuthenticateRequest, 0, cli_id, request.API_VERSION_V1)

    local ok, msg = sasl.encode(brk.auth.mechanism, nil, brk.auth.user, brk.auth.password, sock)
    if not ok then
        return nil, msg
    end
    req:bytes(msg)

    local resp, err = _sock_send_recieve(sock, req, brk.config)
    if not resp then
        return nil, err
    end

    local err_code = resp:int16()
    local error_msg = resp:string()
    local auth_bytes = resp:bytes()

    if err_code ~= 0 then
        return nil, error_msg
    end
    return true
end

-- SSL/TLS setup with file-based certificates
local function setup_ssl_connection(sock, config, host)
    if not config.ssl then
        return true
    end

    -- Set SSL options using file paths
    if config.ssl_ca_location then
        local ok, err = sock:setoption("ssl_verify", config.ssl_verify and 1 or 0)
        if not ok then
            ngx.log(ngx.WARN, "failed to set SSL verify: ", err)
        end
        
        local ok, err = sock:setoption("ssl_ca_cert", config.ssl_ca_location)
        if not ok then
            return nil, "failed to set SSL CA certificate: " .. (err or "unknown error")
        end
    end

    if config.ssl_certificate_location then
        local ok, err = sock:setoption("ssl_cert", config.ssl_certificate_location)
        if not ok then
            return nil, "failed to set SSL client certificate: " .. (err or "unknown error")
        end
    end

    if config.ssl_key_location then
        local ok, err = sock:setoption("ssl_key", config.ssl_key_location)
        if not ok then
            return nil, "failed to set SSL client key: " .. (err or "unknown error")
        end
    end

    -- Set SSL protocol if specified
    if config.ssl_protocol then
        local ok, err = sock:setoption("ssl_protocol", config.ssl_protocol)
        if not ok then
            ngx.log(ngx.WARN, "failed to set SSL protocol: ", err)
        end
    end

    -- Set key password if provided
    if config.ssl_key_password then
        local ok, err = sock:setoption("ssl_key_password", config.ssl_key_password)
        if not ok then
            ngx.log(ngx.WARN, "failed to set SSL key password: ", err)
        end
    end

    -- Perform SSL handshake
    local ssl_ok, ssl_err
    if config.ssl_verify then
        ssl_ok, ssl_err = sock:sslhandshake(true, host, true)
    else
        ssl_ok, ssl_err = sock:sslhandshake(nil, host, false)
    end

    if not ssl_ok then
        return nil, "SSL handshake failed with " .. host .. ": " .. (ssl_err or "unknown error")
    end

    ngx.log(ngx.INFO, "SSL handshake successful with ", host)
    return true
end

-- Broker constructor
function M.new(self, host, port, socket_config, sasl_config)
    return setmetatable({
        host   = host,
        port   = port,
        config = socket_config,
        auth   = sasl_config,
    }, mt)
end

-- Send / Receive request
function M.send_receive(self, request)
    local sock, err = tcp()
    if not sock then
        return nil, err, true
    end

    sock:settimeout(self.config.socket_timeout)

    local ok, err = sock:connect(self.host, self.port)
    if not ok then
        return nil, err, true
    end

    local times, err = sock:getreusedtimes()
    if not times then
        return nil, err
    end

    -- SSL handshake if enabled (only on new connections)
    if self.config.ssl and times == 0 then
        local ssl_ok, ssl_err = setup_ssl_connection(sock, self.config, self.host)
        if not ssl_ok then
            sock:close()
            return nil, ssl_err, true
        end
    end

    -- SASL authentication if enabled (only on new connections)
    if self.auth and times == 0 then
        local ok, err = sasl_auth(sock, self)
        if not ok then
            sock:close()
            return nil, "failed to do SASL " .. self.auth.mechanism .. " auth with " ..
                        self.host .. ":" .. tostring(self.port) .. " err:" .. err, true
        end
    end

    local data, err, retryable = _sock_send_recieve(sock, request)
    sock:setkeepalive(self.config.keepalive_timeout, self.config.keepalive_size)

    return data, err, retryable
end

return M
