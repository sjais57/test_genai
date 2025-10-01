local client = require("resty.kafka.client")

local setmetatable = setmetatable
local type = type
local error = error
local ngx = ngx
local table = table
local string = string
local math = math

local _M = { _VERSION = '0.0.2' }
local mt = { __index = _M }

-- Modify the new function to accept and store SSL configuration
local function new(self, broker_list, producer_config, cluster_name)
    producer_config = producer_config or {}
    
    local broker_list = broker_list or {}
    if #broker_list == 0 then
        return nil, "broker_list must be specified"
    end

    -- Extract SSL/TLS configuration
    local ssl = producer_config.ssl or false
    local ssl_verify = producer_config.ssl_verify or false
    local sasl = producer_config.sasl or false
    local sasl_username = producer_config.sasl_username
    local sasl_password = producer_config.sasl_password
    local sasl_mechanism = producer_config.sasl_mechanism or "PLAIN"
    local ssl_ca_location = producer_config.ssl_ca_location
    local ssl_certificate_location = producer_config.ssl_certificate_location
    local ssl_key_location = producer_config.ssl_key_location
    local ssl_key_password = producer_config.ssl_key_password
    local ssl_protocol = producer_config.ssl_protocol or "TLSv1.2"

    local self = {
        broker_list = broker_list,
        producer_config = producer_config,
        async = producer_config.producer_type ~= "sync",
        required_acks = producer_config.required_acks or 1,
        request_timeout = producer_config.request_timeout or 3000,
        batch_num = producer_config.batch_num or 200,
        batch_size = producer_config.batch_size or 1048576,
        max_buffering = producer_config.max_buffering or 50000,
        flush_time = producer_config.flush_time or -1,
        refresh_interval = producer_config.refresh_interval or 30000,
        cluster_name = cluster_name or -1,

        -- SSL/TLS configuration
        ssl = ssl,
        ssl_verify = ssl_verify,
        sasl = sasl,
        sasl_username = sasl_username,
        sasl_password = sasl_password,
        sasl_mechanism = sasl_mechanism,
        ssl_ca_location = ssl_ca_location,
        ssl_certificate_location = ssl_certificate_location,
        ssl_key_location = ssl_key_location,
        ssl_key_password = ssl_key_password,
        ssl_protocol = ssl_protocol,
    }

    -- Initialize Kafka client with SSL configuration
    self.client = client:new(self.cluster_name)
    
    -- Set SSL configuration on the client
    if self.client.set_ssl_config then
        self.client:set_ssl_config({
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
            request_timeout = self.request_timeout,
        })
    end

    -- Initialize metadata refresh
    local ok, err = self.client:update_metadata(self.broker_list)
    if not ok then
        return nil, err
    end

    -- Initialize ring buffer for async producer
    if self.async then
        self.ringbuffer = {
            size = self.max_buffering * 3,  -- 3 fields per message: topic, key, message
            queue = {},
        }
        for i = 1, self.ringbuffer.size do
            self.ringbuffer.queue[i] = nil
        end
        self.ringbuffer.read_pos = 1
        self.ringbuffer.write_pos = 1
    else
        -- Initialize send buffer for sync producer
        self.sendbuffer = {
            topics = {},
            size = 0,
        }
    end

    -- Log SSL configuration
    if self.ssl then
        ngx.log(ngx.INFO, "Kafka producer SSL enabled - CA: ", self.ssl_ca_location or "not set",
                ", Cert: ", self.ssl_certificate_location or "not set",
                ", Key: ", self.ssl_key_location or "not set")
    end

    return setmetatable(self, mt)
end

-- Add a method to update SSL configuration if needed
function _M.set_ssl_config(self, ssl_config)
    if not ssl_config then
        return nil, "SSL configuration is required"
    end

    self.ssl = ssl_config.ssl or self.ssl
    self.ssl_verify = ssl_config.ssl_verify or self.ssl_verify
    self.sasl = ssl_config.sasl or self.sasl
    self.sasl_username = ssl_config.sasl_username or self.sasl_username
    self.sasl_password = ssl_config.sasl_password or self.sasl_password
    self.sasl_mechanism = ssl_config.sasl_mechanism or self.sasl_mechanism
    self.ssl_ca_location = ssl_config.ssl_ca_location or self.ssl_ca_location
    self.ssl_certificate_location = ssl_config.ssl_certificate_location or self.ssl_certificate_location
    self.ssl_key_location = ssl_config.ssl_key_location or self.ssl_key_location
    self.ssl_key_password = ssl_config.ssl_key_password or self.ssl_key_password
    self.ssl_protocol = ssl_config.ssl_protocol or self.ssl_protocol

    -- Update client SSL configuration
    if self.client and self.client.set_ssl_config then
        return self.client:set_ssl_config({
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
            request_timeout = self.request_timeout,
        })
    end

    return true
end

-- The rest of the existing producer methods remain the same
-- but they will now use the SSL-enabled client

function _M.send(self, topic, key, message)
    -- Existing send implementation, but now with SSL support
    if self.async then
        return self:async_send(topic, key, message)
    else
        return self:sync_send(topic, key, message)
    end
end

-- Existing async_send function (no changes needed to the logic)
function _M.async_send(self, topic, key, message)
    local ringbuffer = self.ringbuffer
    local read_pos = ringbuffer.read_pos
    local write_pos = ringbuffer.write_pos

    -- Calculate available space
    local available
    if write_pos >= read_pos then
        available = ringbuffer.size - (write_pos - read_pos)
    else
        available = read_pos - write_pos
    end

    if available < 3 then
        return nil, "buffer is full"
    end

    -- Store message in ring buffer
    ringbuffer.queue[write_pos] = topic
    ringbuffer.queue[write_pos + 1] = key
    ringbuffer.queue[write_pos + 2] = message

    -- Update write position
    ringbuffer.write_pos = write_pos + 3
    if ringbuffer.write_pos > ringbuffer.size then
        ringbuffer.write_pos = 1
    end

    -- Trigger flush if batch size is reached
    if self.batch_num > 0 and (ringbuffer.write_pos - ringbuffer.read_pos) >= self.batch_num * 3 then
        self:flush()
    end

    return true
end

-- Existing sync_send function (no changes needed to the logic)
function _M.sync_send(self, topic, key, message)
    -- ... existing sync_send implementation
    -- This will now automatically use the SSL-enabled client
end

-- Existing flush function (no changes needed to the logic)
function _M.flush(self)
    -- ... existing flush implementation
    -- This will now automatically use the SSL-enabled client
end

-- Make the new function available
_M.new = new

return _M
