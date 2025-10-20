local schema = {
    type = "object",
    properties = {
        -- modern field: array of "host:port"
        brokers = {
            type = "array",
            minItems = 1,
            items = { type = "string", pattern = "^[^:]+:%d+$" },
            description = "Array of Kafka brokers in 'host:port' form"
        },

        -- backward compatibility (optional)
        broker_list = {
            type = "array",
            items = { type = "string" },
            description = "DEPRECATED: use 'brokers' instead"
        },

        topic = { type = "string" },

        producer_type = {
            type = "string",
            enum = { "async", "sync" },
            default = "async"
        },
        timeout = { type = "integer", minimum = 1, default = 2000 },
        batch_max_size = { type = "integer", minimum = 1, default = 100 },

        -- SSL/TLS options (used by your broker.lua)
        ssl = { type = "boolean", default = false },
        ssl_verify = { type = "boolean", default = true },
        ssl_cafile = { type = "string" },
        ssl_cert = { type = "string" },
        ssl_key = { type = "string" }
    },

    -- either brokers or broker_list must exist
    oneOf = {
        { required = { "brokers", "topic" } },
        { required = { "broker_list", "topic" } }
    },
    additionalProperties = false
}


-- Add SSL/TLS options if enabled (flattened for resty.kafka compatibility)
if conf.ssl then
    broker_config.ssl = true
    broker_config.ssl_verify   = conf.ssl_verify
    broker_config.ssl_cafile   = conf.ssl_cafile
    broker_config.ssl_cert     = conf.ssl_cert
    broker_config.ssl_key      = conf.ssl_key
    broker_config.ssl_protocol = conf.ssl_protocol
end

=======================

-- --------------------------------------------------------------------------
-- Reliable batch processor initialization (APISIX 3.x compatible)
-- --------------------------------------------------------------------------

-- Try to get an existing batch processor context
local entry_added
if bp_manager.add_entry then
    local ok, err = pcall(function()
        entry_added = bp_manager:add_entry(conf, entry)
    end)
    if not ok then
        core.log.warn("kafka-logger: batch processor not ready (", err, "), will create new")
    end
end

if entry_added then
    return
end

-- Build broker list
local broker_list = core.table.clone(conf.brokers or {})
if conf.broker_list then
    for _, host_port in pairs(conf.broker_list) do
        table.insert(broker_list, { host = host_port.host, port = host_port.port })
    end
end

-- Kafka producer configuration
local broker_config = {
    request_timeout  = conf.timeout or 1000,
    producer_type    = conf.producer_type,
    required_acks    = conf.required_acks,
    batch_num        = conf.producer_batch_num,
    batch_size       = conf.producer_batch_size,
    max_buffering    = conf.producer_max_buffering,
    flush_time       = (conf.producer_time_linger or -1) * 1000,
    refresh_interval = (conf.meta_refresh_interval or 30) * 1000,
}

if conf.ssl then
    broker_config.ssl = true
    broker_config.ssl_verify   = conf.ssl_verify
    broker_config.ssl_cafile   = conf.ssl_cafile
    broker_config.ssl_cert     = conf.ssl_cert
    broker_config.ssl_key      = conf.ssl_key
    broker_config.ssl_protocol = conf.ssl_protocol
end

-- Create or reuse Kafka producer
local prod, err = lrucache.plugin_ctx(lrucache, ctx, nil,
    create_producer, broker_list, broker_config, conf.cluster_name)
if not prod then
    core.log.error("failed to create kafka producer: ", err)
    return
end

-- Function that sends data to Kafka
local func = function(entries, batch_max_size)
    local data, jerr
    if batch_max_size == 1 then
        data = entries[1]
        if type(data) ~= "string" then
            data, jerr = core.json.encode(data)
        end
    else
        data, jerr = core.json.encode(entries)
    end
    if not data then
        return false, "error encoding data: " .. (jerr or "unknown")
    end
    return send_kafka_data(conf, ctx, prod, data)
end

-- Now create a fresh processor before adding entries
local ok, err = bp_manager:add_entry_to_new_processor(conf, entry, ctx, func)
if not ok then
    core.log.error("kafka-logger: failed to create batch processor: ", err)
end

