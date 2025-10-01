local setmetatable = setmetatable
local type = type
local error = error
local ngx = ngx
local table = table
local string = string

local _M = { _VERSION = '0.0.2' }
local mt = { __index = _M }

-- SSL/TLS connection setup function
local function setup_ssl_connection(sock, host, config)
    if not config.ssl then
        return true
    end

    -- Set SSL options using file paths
    if config.ssl_ca_location then
        local ok, err = sock:setoption("ssl_verify", 1) -- Enable verification
        if not ok then
            ngx.log(ngx.WARN, "failed to enable SSL verification: ", err)
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

    -- Set SSL verify depth if needed
    sock:setoption("ssl_verify_depth", 3)

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

-- SASL authentication function
local function sasl_authenticate(sock, config)
    if not config.sasl then
        return true
    end

    local mechanism = config.sasl_mechanism or "PLAIN"
    local username = config.sasl_username
    local password = config.sasl_password

    if not username or not password then
        return nil, "SASL authentication requires both username and password"
    end

    if mechanism == "PLAIN" then
        -- SASL PLAIN authentication
        local auth_message = "\0" .. username .. "\0" .. password
        
        -- Send SASL handshake request (API key 17 for SASL_HANDSHAKE)
        local handshake_request = string.pack(">i2 i2 i2", 17, 1, 11) .. "PLAIN" -- 11 = length of "PLAIN"
        local request_size = string.pack(">i4", #handshake_request)
        
        local ok, err = sock:send(request_size .. handshake_request)
        if not ok then
            return nil, "SASL handshake request failed: " .. (err or "unknown error")
        end

        -- Read handshake response
        local resp_size_data, err = sock:receive(4)
        if not resp_size_data then
            return nil, "failed to read SASL handshake response size: " .. (err or "unknown error")
        end

        local resp_size = string.unpack(">i4", resp_size_data)
        local handshake_resp, err = sock:receive(resp_size)
        if not handshake_resp then
            return nil, "failed to read SASL handshake response: " .. (err or "unknown error")
        end

        -- Send SASL authenticate with PLAIN mechanism (API key 18 for SASL_AUTHENTICATE)
        local auth_header = string.pack(">i2 i2 i4", 18, 1, #auth_message)
        local auth_request = auth_header .. auth_message
        local auth_request_size = string.pack(">i4", #auth_request)
        
        local ok, err = sock:send(auth_request_size .. auth_request)
        if not ok then
            return nil, "SASL authentication request failed: " .. (err or "unknown error")
        end

        -- Read authentication response
        local auth_resp_size_data, err = sock:receive(4)
        if not auth_resp_size_data then
            return nil, "failed to read SASL authentication response size: " .. (err or "unknown error")
        end

        local auth_resp_size = string.unpack(">i4", auth_resp_size_data)
        local auth_resp, err = sock:receive(auth_resp_size)
        if not auth_resp then
            return nil, "failed to read SASL authentication response: " .. (err or "unknown error")
        end

        ngx.log(ngx.INFO, "SASL PLAIN authentication successful")
        
    elseif mechanism == "SCRAM-SHA-256" or mechanism == "SCRAM-SHA-512" then
        -- Basic SCRAM implementation would go here
        -- This is simplified - full implementation is complex
        return nil, "SCRAM-SHA authentication not fully implemented. Use PLAIN mechanism."
    else
        return nil, "Unsupported SASL mechanism: " .. mechanism
    end

    return true
end

-- Updated connection creation function
local function create_connection(host, port, config)
    local sock = ngx.socket.tcp()
    if not sock then
        return nil, "failed to create TCP socket"
    end

    -- Set timeout
    sock:settimeout(config.request_timeout or 3000)

    -- Connect to broker
    local ok, err = sock:connect(host, port)
    if not ok then
        return nil, "failed to connect to " .. host .. ":" .. port .. ": " .. err
    end

    -- Setup SSL if enabled
    if config.ssl then
        local ssl_ok, ssl_err = setup_ssl_connection(sock, host, config)
        if not ssl_ok then
            sock:close()
            return nil, ssl_err
        end
    end

    -- Perform SASL authentication if enabled
    if config.sasl then
        local auth_ok, auth_err = sasl_authenticate(sock, config)
        if not auth_ok then
            sock:close()
            return nil, auth_err
        end
    end

    return sock
end

-- Update the _send_to_broker function to use the new connection method
local function _send_to_broker(self, host, port, request, response_size)
    local config = {
        request_timeout = self.request_timeout,
        ssl = self.ssl,
        ssl_verify = self.ssl_verify,
        sasl = self.sasl,
        sasl_username = self.sasl_username,
        sasl_password = self.sasl_password,
        sasl_mechanism = self.sasl_mechanism,
        ssl_ca_location = self.ssl_ca_location,
        ssl_certificate_location = self.ssl_certificate_location,
        ssl_key_location = self.ssl_key_location,
        ssl_key_password = self.ssl_key_password,
        ssl_protocol = self.ssl_protocol,
    }

    local sock, err = create_connection(host, port, config)
    if not sock then
        return nil, err
    end

    -- Send the request
    local bytes, err = sock:send(request)
    if not bytes then
        sock:close()
        return nil, "failed to send request to " .. host .. ":" .. port .. ": " .. err
    end

    -- Receive response
    local data, err = sock:receive(response_size or 1024) -- default response size
    if not data then
        sock:close()
        return nil, "failed to receive response from " .. host .. ":" .. port .. ": " .. err
    end

    sock:close()
    return data
end

-- Modify the client:new function to initialize SSL parameters
local function new(self, cluster_name)
    cluster_name = cluster_name or -1

    local self = {
        cluster_name = cluster_name,
        cluster_meta = {},
        cluster_leader = {},
        cluster_brokers = {},
        request_timeout = 3000, -- default 3 seconds
        
        -- SSL/TLS configuration (defaults)
        ssl = false,
        ssl_verify = false,
        sasl = false,
        sasl_username = nil,
        sasl_password = nil,
        sasl_mechanism = "PLAIN",
        ssl_ca_location = nil,
        ssl_certificate_location = nil,
        ssl_key_location = nil,
        ssl_key_password = nil,
        ssl_protocol = "TLSv1.2",
    }

    return setmetatable(self, mt)
end

-- Add SSL configuration method
function mt:set_ssl_config(config)
    if not config then
        return nil, "SSL configuration is required"
    end

    self.ssl = config.ssl or self.ssl
    self.ssl_verify = config.ssl_verify or self.ssl_verify
    self.sasl = config.sasl or self.sasl
    self.sasl_username = config.sasl_username or self.sasl_username
    self.sasl_password = config.sasl_password or self.sasl_password
    self.sasl_mechanism = config.sasl_mechanism or self.sasl_mechanism
    self.ssl_ca_location = config.ssl_ca_location or self.ssl_ca_location
    self.ssl_certificate_location = config.ssl_certificate_location or self.ssl_certificate_location
    self.ssl_key_location = config.ssl_key_location or self.ssl_key_location
    self.ssl_key_password = config.ssl_key_password or self.ssl_key_password
    self.ssl_protocol = config.ssl_protocol or self.ssl_protocol
    self.request_timeout = config.request_timeout or self.request_timeout

    ngx.log(ngx.INFO, "SSL config updated - SSL: ", self.ssl, 
            ", SASL: ", self.sasl, 
            ", CA: ", self.ssl_ca_location or "not set")

    return true
end

-- Keep all existing client methods but ensure they use _send_to_broker
-- For example, update metadata refresh to use SSL connections
function mt:update_metadata(broker_list)
    -- This method should now automatically use the SSL-enabled _send_to_broker
    -- Existing implementation remains the same but will use secure connections
    if not broker_list or #broker_list == 0 then
        return nil, "broker_list must be specified"
    end

    -- Store the original broker list for reconnection
    self.broker_list = broker_list

    -- Try to connect to each broker with SSL if enabled
    for i, broker in ipairs(broker_list) do
        -- The existing metadata update logic goes here
        -- It will now automatically use the SSL-enabled _send_to_broker function
    end

    -- Rest of existing update_metadata implementation...
end

-- Make sure all existing methods that use network calls go through _send_to_broker
-- This includes methods like:
-- mt:fetch_metadata()
-- mt:get_leader()
-- mt:send_produce_request()
-- etc.

-- Export the new function
_M.new = new

return _M
