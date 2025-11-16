local response     = require "resty.kafka.response"
local request      = require "resty.kafka.request"
local to_int32     = response.to_int32
local setmetatable = setmetatable
local tcp          = ngx.socket.tcp
local pid          = ngx.worker.pid
local tostring     = tostring
local sasl         = require "resty.kafka.sasl"

local ngx_log      = ngx.log
local ERR          = ngx.ERR
local INFO         = ngx.INFO
local DEBUG        = ngx.DEBUG
local WARN         = ngx.WARN

local LOG_PREFIX   = "[kafka-broker][debug] "

local M = {}
local mt = { __index = M }

--------------------------------------------------------------------------------
-- socket send/receive helper
--------------------------------------------------------------------------------
local function _sock_send_recieve(sock, req, brk)
    ngx_log(INFO, LOG_PREFIX,
        "_sock_send_recieve: api=", req.api_key,
        ", api_version=", req.api_version,
        ", broker=", brk and (brk.host .. ":" .. tostring(brk.port)) or "nil"
    )

    local bytes, err = sock:send(req:package())
    if not bytes then
        ngx_log(ERR, LOG_PREFIX, "_sock_send_recieve: send failed: ", err)
        return nil, err, true
    end

    local len, err = sock:receive(4)
    if not len then
        ngx_log(ERR, LOG_PREFIX,
            "_sock_send_recieve: receive length failed: ", err)
        if err == "timeout" then
            sock:close()
        end
        return nil, err, true
    end

    local resp_len = to_int32(len)
    ngx_log(INFO, LOG_PREFIX,
        "_sock_send_recieve: response length=", resp_len,
        ", broker=", brk and (brk.host .. ":" .. tostring(brk.port)) or "nil"
    )

    local data, err = sock:receive(resp_len)
    if not data then
        ngx_log(ERR, LOG_PREFIX, "_sock_send_recieve: receive body failed: ", err)
        if err == "timeout" then
            sock:close()
        end
        return nil, err, true
    end

    ngx_log(INFO, LOG_PREFIX,
        "_sock_send_recieve: response received OK for broker=",
        brk and brk.host or "nil", ":", brk and brk.port or "nil"
    )

    return response:new(data, req.api_version), nil, true
end

--------------------------------------------------------------------------------
-- SASL Handshake
--------------------------------------------------------------------------------
local function _sasl_handshake(sock, brk)
    ngx_log(INFO, LOG_PREFIX,
        "_sasl_handshake: starting, mechanism=",
        brk.auth and brk.auth.mechanism or "nil",
        ", user=", brk.auth and brk.auth.user or "nil"
    )

    local cli_id = "worker" .. pid()
    local req = request:new(
        request.SaslHandshakeRequest,
        0,
        cli_id,
        request.API_VERSION_V1
    )
    req:string(brk.auth.mechanism)

    local resp, err = _sock_send_recieve(sock, req, brk)
    if not resp then
        ngx_log(ERR, LOG_PREFIX, "_sasl_handshake: handshake failed: ", err)
        return nil, err
    end

    local err_code = resp:int16()
    ngx_log(INFO, LOG_PREFIX, "_sasl_handshake: err_code=", err_code)

    if err_code ~= 0 then
        local error_msg = resp:string()
        ngx_log(ERR, LOG_PREFIX,
            "_sasl_handshake: non-zero err_code, msg=", error_msg)
        return nil, error_msg
    end

    ngx_log(INFO, LOG_PREFIX, "_sasl_handshake: success")
    return true
end

--------------------------------------------------------------------------------
-- SASL Authentication
--------------------------------------------------------------------------------
local function sasl_auth(sock, brk)
    ngx_log(INFO, LOG_PREFIX,
        "sasl_auth: starting, mechanism=",
        brk.auth and brk.auth.mechanism or "nil",
        ", user=", brk.auth and brk.auth.user or "nil"
    )

    local cli_id = "worker" .. pid()
    local req = request:new(
        request.SaslAuthenticateRequest,
        0,
        cli_id,
        request.API_VERSION_V1
    )

    local ok, msg = sasl.encode(
        brk.auth.mechanism,
        nil,
        brk.auth.user,
        brk.auth.password,
        sock
    )
    if not ok then
        ngx_log(ERR, LOG_PREFIX, "sasl_auth: sasl.encode failed: ", msg)
        return nil, msg
    end
    req:bytes(msg)

    local resp, err = _sock_send_recieve(sock, req, brk)
    if not resp then
        ngx_log(ERR, LOG_PREFIX, "sasl_auth: send_receive failed: ", err)
        return nil, err
    end

    local err_code  = resp:int16()
    local error_msg = resp:string()
    local auth_bytes = resp:bytes()

    ngx_log(INFO, LOG_PREFIX,
        "sasl_auth: err_code=", err_code,
        ", error_msg=", error_msg or "nil",
        ", auth_bytes_len=", auth_bytes and #auth_bytes or 0
    )

    if err_code ~= 0 then
        ngx_log(ERR, LOG_PREFIX,
            "sasl_auth: authentication failed: ", error_msg)
        return nil, error_msg
    end

    ngx_log(INFO, LOG_PREFIX, "sasl_auth: success")
    return true
end

--------------------------------------------------------------------------------
-- Broker constructor
--------------------------------------------------------------------------------
function M.new(self, host, port, socket_config, sasl_config)
    ngx_log(INFO, LOG_PREFIX,
        "M.new: creating broker object, host=", host,
        ", port=", port
    )

    if socket_config then
        ngx_log(INFO, LOG_PREFIX,
            "M.new: socket_config: ssl=", tostring(socket_config.ssl),
            ", ssl_verify=", tostring(socket_config.ssl_verify),
            ", ssl_ca_location=", tostring(socket_config.ssl_ca_location),
            ", ssl_certificate_location=", tostring(socket_config.ssl_certificate_location),
            ", ssl_key_location=", tostring(socket_config.ssl_key_location),
            ", ssl_key_password_set=", tostring(socket_config.ssl_key_password and true or false),
            ", socket_timeout=", tostring(socket_config.socket_timeout),
            ", keepalive_timeout=", tostring(socket_config.keepalive_timeout),
            ", keepalive_size=", tostring(socket_config.keepalive_size)
        )
    else
        ngx_log(WARN, LOG_PREFIX,
            "M.new: socket_config is nil – SSL will not be used")
    end

    if sasl_config then
        ngx_log(INFO, LOG_PREFIX,
            "M.new: sasl_config present: mechanism=",
            tostring(sasl_config.mechanism),
            ", user=", tostring(sasl_config.user),
            ", password_set=", tostring(sasl_config.password and true or false)
        )
    else
        ngx_log(INFO, LOG_PREFIX, "M.new: sasl_config is nil (no SASL)")
    end

    return setmetatable({
        host   = host,
        port   = port,
        config = socket_config,
        auth   = sasl_config,
    }, mt)
end

--------------------------------------------------------------------------------
-- Send / Receive request
--------------------------------------------------------------------------------
function M.send_receive(self, req)
    ngx_log(INFO, LOG_PREFIX,
        "send_receive: start, host=", self.host,
        ", port=", self.port
    )

    local sock, err = tcp()
    if not sock then
        ngx_log(ERR, LOG_PREFIX,
            "send_receive: failed to create socket: ", err)
        return nil, err, true
    end

    local timeout = (self.config and self.config.socket_timeout) or 30000
    ngx_log(INFO, LOG_PREFIX,
        "send_receive: setting timeout=", timeout)
    sock:settimeout(timeout)

    ngx_log(INFO, LOG_PREFIX,
        "send_receive: connecting to ", self.host, ":", self.port)
    local ok, err = sock:connect(self.host, self.port)
    if not ok then
        ngx_log(ERR, LOG_PREFIX,
            "send_receive: connect failed: ", err)
        return nil, err, true
    end

    local times, err = sock:getreusedtimes()
    if not times then
        ngx_log(ERR, LOG_PREFIX,
            "send_receive: getreusedtimes failed: ", err)
        return nil, err
    end

    ngx_log(INFO, LOG_PREFIX,
        "send_receive: socket reused times=", times,
        ", ssl=", self.config and self.config.ssl or false,
        ", ssl_verify=", self.config and self.config.ssl_verify or false
    )

    --------------------------------------------------------------------
    -- SSL handshake if enabled (mTLS client cert BEFORE handshake)
    --------------------------------------------------------------------
    if self.config and self.config.ssl and times == 0 then
        ngx_log(INFO, LOG_PREFIX,
            "send_receive: SSL enabled, preparing client cert (if any)")

        -- Prefer *_location if present, else fallback to stock ssl_cert/ssl_key
        local cert = self.config.ssl_certificate_location or self.config.ssl_cert
        local key  = self.config.ssl_key_location       or self.config.ssl_key

        if cert and key then
            ngx_log(INFO, LOG_PREFIX,
                "send_receive: setting client cert & key BEFORE SSL handshake, cert=",
                tostring(cert),
                ", key=", tostring(key),
                ", key_password_set=",
                tostring(self.config.ssl_key_password and true or false)
            )

            local okc, errc = sock:setclientcert(
                cert,
                key,
                self.config.ssl_key_password
            )
            if not okc then
                ngx_log(ERR, LOG_PREFIX,
                    "send_receive: failed to set client cert/key: ", errc)
                return nil,
                    "failed to set client cert/key: " .. (errc or "unknown"),
                    true
            end

            ngx_log(INFO, LOG_PREFIX,
                "send_receive: client cert & key set successfully")
        else
            ngx_log(WARN, LOG_PREFIX,
                "send_receive: no client cert configured in socket_config; " ..
                "if Kafka requires mTLS, broker may send 'bad certificate'. " ..
                "socket_config.ssl_cert=", tostring(self.config.ssl_cert),
                ", socket_config.ssl_key=", tostring(self.config.ssl_key),
                ", socket_config.ssl_certificate_location=", tostring(self.config.ssl_certificate_location),
                ", socket_config.ssl_key_location=", tostring(self.config.ssl_key_location)
            )
        end

        ngx_log(INFO, LOG_PREFIX,
            "send_receive: performing SSL handshake (CA from lua_ssl_trusted_certificate), " ..
            "host(SNI)=", tostring(self.host),
            ", verify=", tostring(self.config.ssl_verify)
        )

        -- CA for verifying the broker comes from lua_ssl_trusted_certificate
        local ok_ssl, err_ssl = sock:sslhandshake(
            false,                 -- reused_session
            self.host,             -- sni
            self.config.ssl_verify -- verify (uses lua_ssl_trusted_certificate)
            -- 4th param (OCSP) left nil
        )
        if not ok_ssl then
            ngx_log(ERR, LOG_PREFIX,
                "send_receive: SSL handshake FAILED with ",
                self.host, ":", tostring(self.port),
                " err:", err_ssl
            )
            return nil,
                "failed to do SSL handshake with " ..
                self.host .. ":" .. tostring(self.port) ..
                " err:" .. err_ssl,
                true
        end

        ngx_log(INFO, LOG_PREFIX,
            "send_receive: SSL handshake SUCCESS with ",
            self.host, ":", tostring(self.port)
        )

        -- Try to log peer cert details (if supported)
        local ok_pc, peer_cert = pcall(sock.getpeercert, sock)
        if ok_pc and peer_cert then
            ngx_log(INFO, LOG_PREFIX,
                "send_receive: peer cert: subject=",
                tostring(peer_cert.subject),
                ", issuer=", tostring(peer_cert.issuer),
                ", not_before=", tostring(peer_cert.not_before),
                ", not_after=", tostring(peer_cert.not_after)
            )
        else
            ngx_log(INFO, LOG_PREFIX,
                "send_receive: getpeercert not available or no peer cert returned")
        end

        local ok_pn, peer_name = pcall(sock.getpeername, sock)
        if ok_pn and peer_name then
            ngx_log(INFO, LOG_PREFIX,
                "send_receive: peer name=",
                tostring(peer_name.host), ":",
                tostring(peer_name.port)
            )
        end
    else
        if self.config and self.config.ssl and times > 0 then
            ngx_log(INFO, LOG_PREFIX,
                "send_receive: SSL enabled but socket reused times>0, " ..
                "assuming previous session already negotiated")
        else
            ngx_log(INFO, LOG_PREFIX,
                "send_receive: SSL disabled for this connection")
        end
    end

    --------------------------------------------------------------------
    -- SASL if enabled
    --------------------------------------------------------------------
    if self.auth and times == 0 then
        ngx_log(INFO, LOG_PREFIX,
            "send_receive: SASL auth enabled, mechanism=",
            self.auth.mechanism or "nil",
            ", user=", tostring(self.auth.user)
        )

        local ok_hs, err_hs = _sasl_handshake(sock, self)
        if not ok_hs then
            ngx_log(ERR, LOG_PREFIX,
                "send_receive: SASL handshake failed: ", err_hs)
            return nil,
                "failed to do SASL handshake with " ..
                self.host .. ":" .. tostring(self.port) ..
                " err:" .. err_hs,
                true
        end

        local ok_auth, err_auth = sasl_auth(sock, self)
        if not ok_auth then
            ngx_log(ERR, LOG_PREFIX,
                "send_receive: SASL auth failed: ", err_auth)
            return nil,
                "failed to do SASL " ..
                (self.auth.mechanism or "unknown") ..
                " auth with " .. self.host .. ":" ..
                tostring(self.port) .. " err:" .. err_auth,
                true
        end

        ngx_log(INFO, LOG_PREFIX,
            "send_receive: SASL auth success for user=",
            tostring(self.auth.user)
        )
    elseif self.auth then
        ngx_log(INFO, LOG_PREFIX,
            "send_receive: SASL config present but socket reused (times>0), " ..
            "skipping SASL handshake")
    end

    --------------------------------------------------------------------
    -- Actual Kafka request
    --------------------------------------------------------------------
    ngx_log(INFO, LOG_PREFIX,
        "send_receive: sending Kafka request now")
    local data, serr, retryable = _sock_send_recieve(sock, req, self)

    ngx_log(INFO, LOG_PREFIX,
        "send_receive: _sock_send_recieve returned, err=",
        tostring(serr), ", retryable=", tostring(retryable)
    )

    -- Keepalive config
    local keepalive_timeout = self.config and self.config.keepalive_timeout or 60000
    local keepalive_size    = self.config and self.config.keepalive_size or 100

    local ok_ka, err_ka = sock:setkeepalive(keepalive_timeout, keepalive_size)
    if not ok_ka then
        ngx_log(WARN, LOG_PREFIX,
            "send_receive: setkeepalive failed: ", err_ka,
            " (timeout=", keepalive_timeout,
            ", size=", keepalive_size, ")"
        )
    else
        ngx_log(INFO, LOG_PREFIX,
            "send_receive: setkeepalive done (timeout=",
            keepalive_timeout, ", size=", keepalive_size, ")"
        )
    end

    return data, serr, retryable
end

return M
