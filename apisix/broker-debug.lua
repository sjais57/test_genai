local response     = require "resty.kafka.response"
local request      = require "resty.kafka.request"
local to_int32     = response.to_int32
local setmetatable = setmetatable
local tcp          = ngx.socket.tcp
local pid          = ngx.worker.pid
local tostring     = tostring
local sasl         = require "resty.kafka.sasl"

local LOG_PREFIX   = "[kafka-broker][debug] "

local M = {}
local mt = { __index = M }

-- socket send/receive helper
local function _sock_send_recieve(sock, req, brk)
    ngx.log(ngx.INFO, LOG_PREFIX, "_sock_send_recieve: api=", req.api_key,
            ", api_version=", req.api_version)

    local bytes, err = sock:send(req:package())
    if not bytes then
        ngx.log(ngx.ERR, LOG_PREFIX, "_sock_send_recieve: send failed: ", err)
        return nil, err, true
    end

    local len, err = sock:receive(4)
    if not len then
        ngx.log(ngx.ERR, LOG_PREFIX, "_sock_send_recieve: receive length failed: ", err)
        if err == "timeout" then
            sock:close()
        end
        return nil, err, true
    end

    local resp_len = to_int32(len)
    ngx.log(ngx.INFO, LOG_PREFIX, "_sock_send_recieve: response length=", resp_len)

    local data, err = sock:receive(resp_len)
    if not data then
        ngx.log(ngx.ERR, LOG_PREFIX, "_sock_send_recieve: receive body failed: ", err)
        if err == "timeout" then
            sock:close()
        end
        return nil, err, true
    end

    ngx.log(ngx.INFO, LOG_PREFIX, "_sock_send_recieve: response received for broker=",
            brk and brk.host or "nil", ":", brk and brk.port or "nil")

    return response:new(data, req.api_version), nil, true
end

-- SASL Handshake
local function _sasl_handshake(sock, brk)
    ngx.log(ngx.INFO, LOG_PREFIX, "_sasl_handshake: starting, mechanism=", brk.auth and brk.auth.mechanism or "nil")

    local cli_id = "worker" .. pid()
    local req = request:new(request.SaslHandshakeRequest, 0, cli_id, request.API_VERSION_V1)
    req:string(brk.auth.mechanism)

    local resp, err = _sock_send_recieve(sock, req, brk)
    if not resp then
        ngx.log(ngx.ERR, LOG_PREFIX, "_sasl_handshake: handshake failed: ", err)
        return nil, err
    end

    local err_code = resp:int16()
    ngx.log(ngx.INFO, LOG_PREFIX, "_sasl_handshake: err_code=", err_code)
    if err_code ~= 0 then
        local error_msg = resp:string()
        ngx.log(ngx.ERR, LOG_PREFIX, "_sasl_handshake: non-zero err_code, msg=", error_msg)
        return nil, error_msg
    end

    ngx.log(ngx.INFO, LOG_PREFIX, "_sasl_handshake: success")
    return true
end

-- SASL Authentication
local function sasl_auth(sock, brk)
    ngx.log(ngx.INFO, LOG_PREFIX, "sasl_auth: starting, mechanism=", brk.auth and brk.auth.mechanism or "nil")

    local cli_id = "worker" .. pid()
    local req = request:new(request.SaslAuthenticateRequest, 0, cli_id, request.API_VERSION_V1)

    local ok, msg = sasl.encode(brk.auth.mechanism, nil, brk.auth.user, brk.auth.password, sock)
    if not ok then
        ngx.log(ngx.ERR, LOG_PREFIX, "sasl_auth: sasl.encode failed: ", msg)
        return nil, msg
    end
    req:bytes(msg)

    local resp, err = _sock_send_recieve(sock, req, brk)
    if not resp then
        ngx.log(ngx.ERR, LOG_PREFIX, "sasl_auth: send_receive failed: ", err)
        return nil, err
    end

    local err_code = resp:int16()
    local error_msg = resp:string()
    local auth_bytes = resp:bytes()

    ngx.log(ngx.INFO, LOG_PREFIX, "sasl_auth: err_code=", err_code,
            ", error_msg=", error_msg or "nil",
            ", auth_bytes_len=", auth_bytes and #auth_bytes or 0)

    if err_code ~= 0 then
        ngx.log(ngx.ERR, LOG_PREFIX, "sasl_auth: authentication failed: ", error_msg)
        return nil, error_msg
    end
    ngx.log(ngx.INFO, LOG_PREFIX, "sasl_auth: success")
    return true
end

-- Broker constructor
function M.new(self, host, port, socket_config, sasl_config)
    ngx.log(ngx.INFO, LOG_PREFIX, "M.new: host=", host, ", port=", port,
            ", ssl=", socket_config and socket_config.ssl or false,
            ", sasl=", sasl_config and true or false)

    return setmetatable({
        host   = host,
        port   = port,
        config = socket_config,
        auth   = sasl_config,
    }, mt)
end

-- Send / Receive request
function M.send_receive(self, req)
    ngx.log(ngx.INFO, LOG_PREFIX, "send_receive: start, host=", self.host, ", port=", self.port)

    local sock, err = tcp()
    if not sock then
        ngx.log(ngx.ERR, LOG_PREFIX, "send_receive: failed to create socket: ", err)
        return nil, err, true
    end

    local timeout = self.config and self.config.socket_timeout or 30000
    ngx.log(ngx.INFO, LOG_PREFIX, "send_receive: setting timeout=", timeout)
    sock:settimeout(timeout)

    ngx.log(ngx.INFO, LOG_PREFIX, "send_receive: connecting to ", self.host, ":", self.port)
    local ok, err = sock:connect(self.host, self.port)
    if not ok then
        ngx.log(ngx.ERR, LOG_PREFIX, "send_receive: connect failed: ", err)
        return nil, err, true
    end

    local times, err = sock:getreusedtimes()
    if not times then
        ngx.log(ngx.ERR, LOG_PREFIX, "send_receive: getreusedtimes failed: ", err)
        return nil, err
    end

    ngx.log(ngx.INFO, LOG_PREFIX, "send_receive: socket reused times=", times,
            ", ssl=", self.config and self.config.ssl or false,
            ", ssl_verify=", self.config and self.config.ssl_verify or false)

    -- SSL handshake if enabled
    if self.config and self.config.ssl and times == 0 then
        ngx.log(ngx.INFO, LOG_PREFIX, "send_receive: performing SSL handshake, ca=",
                self.config.ssl_ca_location or "nil")

        local ok_ssl, err_ssl = sock:sslhandshake(
            false,
            self.host,
            self.config.ssl_verify,
            self.config.ssl_ca_location
        )
        if not ok_ssl then
            ngx.log(ngx.ERR, LOG_PREFIX, "send_receive: SSL handshake failed with ",
                    self.host, ":", tostring(self.port), " err:", err_ssl)
            return nil, "failed to do SSL handshake with " ..
                self.host .. ":" .. tostring(self.port) .. " err:" .. err_ssl, true
        end

        ngx.log(ngx.INFO, LOG_PREFIX, "send_receive: SSL handshake success")

        -- optional client cert
        if self.config.ssl_certificate_location and self.config.ssl_key_location then
            ngx.log(ngx.INFO, LOG_PREFIX, "send_receive: setting client cert & key")
            local okc, errc = sock:setclientcert(self.config.ssl_certificate_location,
                                                 self.config.ssl_key_location,
                                                 self.config.ssl_key_password)
            if not okc then
                ngx.log(ngx.ERR, LOG_PREFIX, "send_receive: failed to set client cert/key: ", errc)
                return nil, "failed to set client cert/key: " .. (errc or "unknown"), true
            end
        end
    end

    -- SASL authentication if enabled
    if self.auth and times == 0 then
        ngx.log(ngx.INFO, LOG_PREFIX, "send_receive: SASL auth enabled, mechanism=",
                self.auth.mechanism or "nil")

        local ok_hs, err_hs = _sasl_handshake(sock, self)
        if not ok_hs then
            ngx.log(ngx.ERR, LOG_PREFIX, "send_receive: SASL handshake failed: ", err_hs)
            return nil, "failed to do SASL handshake with " ..
                        self.host .. ":" .. tostring(self.port) .. " err:" .. err_hs, true
        end

        local ok_auth, err_auth = sasl_auth(sock, self)
        if not ok_auth then
            ngx.log(ngx.ERR, LOG_PREFIX, "send_receive: SASL auth failed: ", err_auth)
            return nil, "failed to do SASL " .. self.auth.mechanism .. " auth with " ..
                        self.host .. ":" .. tostring(self.port) .. " err:" .. err_auth, true
        end
    end

    ngx.log(ngx.INFO, LOG_PREFIX, "send_receive: sending request now")
    local data, err, retryable = _sock_send_recieve(sock, req, self)

    ngx.log(ngx.INFO, LOG_PREFIX, "send_receive: _sock_send_recieve returned, err=", err or "nil",
            ", retryable=", tostring(retryable))

    sock:setkeepalive(self.config.keepalive_timeout, self.config.keepalive_size)
    ngx.log(ngx.INFO, LOG_PREFIX, "send_receive: setkeepalive done")

    return data, err, retryable
end

return M
