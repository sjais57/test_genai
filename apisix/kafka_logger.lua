-- Apache APISIX - kafka-logger plugin (extended for SSL/SASL)
--
-- This version:
--   * Keeps APISIX 3.12 behaviour
--   * Adds top-level SSL/SASL settings on the plugin config
--   * Maps global SASL into per-broker sasl_config if not already present
--   * Passes SSL options down to lua-resty-kafka via producer_config
--   * Compatible with your custom broker.lua (ssl_ca_location, client cert, sasl)

local expr          = require("resty.expr.v1")
local core          = require("apisix.core")
local log_util      = require("apisix.utils.log-util")
local producer      = require("resty.kafka.producer")
local bp_manager    = require("apisix.utils.batch-processor-manager")

local math          = math
local pairs         = pairs
local type          = type
local req_read_body = ngx.req.read_body
local plugin_name   = "kafka-logger"

local LOG_PREFIX    = "[kafka-logger][debug] "

local lrucache = core.lrucache.new({ type = "plugin" })

----------------------------------------------------------------------
-- Schema
----------------------------------------------------------------------

local schema = {
    type = "object",
    properties = {
        meta_format = {
            type = "string",
            default = "default",
            enum = {"default", "origin"},
        },

        log_format  = { type = "object" },

        -- Modern APISIX 'brokers' field
        brokers = {
            type = "array",
            minItems = 1,
            items = {
                type = "object",
                properties = {
                    host = {
                        type = "string",
                        description = "the host of kafka broker",
                    },
                    port = {
                        type = "integer",
                        minimum = 1, maximum = 65535,
                        description = "the port of kafka broker",
                    },
                    sasl_config = {
                        type = "object",
                        description = "per-broker SASL config (backward compatible)",
                        properties = {
                            mechanism = {
                                type = "string",
                                default = "PLAIN",
                                enum = {"PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"},
                            },
                            user = { type = "string" },
                            password = { type = "string" },
                        },
                        required = {"user", "password"},
                    },
                },
                required = {"host", "port"},
            },
            uniqueItems = true,
        },

        -- Older APISIX 'broker_list' (still accepted and merged)
        broker_list = {
            type = "array",
            items = {
                type = "object",
                properties = {
                    host = { type = "string" },
                    port = { type = "integer", minimum = 1, maximum = 65535 },
                },
                required = {"host", "port"},
            }
        },

        kafka_topic   = { type = "string" },

        producer_type = {
            type = "string",
            default = "async",
            enum = {"async", "sync"},
        },

        required_acks = {
            type = "integer",
            default = 1,
            enum = {-1, 1, 0},
        },

        key = { type = "string" },

        timeout = {
            type = "integer",
            minimum = 1,
            default = 1000,  -- ms
        },

        ------------------------------------------------------------------
        -- SSL / SASL (global-level, mapped into lua-resty-kafka)
        ------------------------------------------------------------------
        ssl = {
            type = "boolean",
            default = false,
            description = "Enable SSL/TLS connection to Kafka (passed to lua-resty-kafka client.ssl)",
        },
        ssl_verify = {
            type = "boolean",
            default = false,
            description = "Verify Kafka broker certificate (client.ssl_verify)",
        },

        -- If you want to control CA / client certs by file path.
        -- NOTE: openresty normally uses nginx directives for CA;
        -- here we simply pass these values down and your custom
        -- client.lua/broker.lua reads them from socket_config.
        ssl_ca_location = {
            type = "string",
            description = "Path to CA certificate file (used by your custom broker.lua/client.lua)",
        },
        ssl_certificate_location = {
            type = "string",
            description = "Path to client certificate (for mTLS, optional)",
        },
        ssl_key_location = {
            type = "string",
            description = "Path to client key (for mTLS, optional)",
        },
        ssl_key_password = {
            type = "string",
            description = "Password for client key (if encrypted, optional)",
        },

        -- Global SASL (convenience) – will be mapped into per-broker sasl_config
        sasl = {
            type = "boolean",
            default = false,
            description = "Enable SASL auth for all brokers (if per-broker sasl_config missing)",
        },
        sasl_username = {
            type = "string",
            description = "Global SASL username",
        },
        sasl_password = {
            type = "string",
            description = "Global SASL password",
        },
        sasl_mechanism = {
            type = "string",
            enum = {"PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"},
            default = "PLAIN",
            description = "Global SASL mechanism",
        },

        ------------------------------------------------------------------
        -- Body collection options
        ------------------------------------------------------------------
        include_req_body = { type = "boolean", default = false },
        include_req_body_expr = {
            type = "array",
            minItems = 1,
            items = { type = "array" },
        },

        include_resp_body = { type = "boolean", default = false },
        include_resp_body_expr = {
            type = "array",
            minItems = 1,
            items = { type = "array" },
        },

        max_req_body_bytes  = { type = "integer", minimum = 1, default = 524288 },
        max_resp_body_bytes = { type = "integer", minimum = 1, default = 524288 },

        cluster_name = { type = "integer", minimum = -1, default = -1 },

        -- These go straight into lua-resty-kafka producer options
        producer_batch_num     = { type = "integer", minimum = 1, default = 200 },
        producer_batch_size    = { type = "integer", minimum = 1, default = 1048576 },
        producer_max_buffering = { type = "integer", minimum = 1, default = 50000 },

        -- Seconds in APISIX; converted to ms for lua-resty-kafka `flush_time`
        producer_time_linger   = { type = "integer", minimum = 1, default = 1 },

        -- Seconds; passed to lua-resty-kafka `refresh_interval`
        meta_refresh_interval  = { type = "integer", minimum = 1, default = 30 },
    },
    required = {"brokers", "kafka_topic"},
}

local metadata_schema = {
    type = "object",
    properties = {
        log_format = { type = "object" },
    },
}

----------------------------------------------------------------------
-- Module
----------------------------------------------------------------------

local _M = {
    version = 0.1,
    priority = 403,
    name = plugin_name,
    schema = bp_manager:wrap_schema(schema),
    metadata_schema = metadata_schema,
}

----------------------------------------------------------------------
-- Schema validation
----------------------------------------------------------------------

function _M.check_schema(conf, schema_type)
    if schema_type == core.schema.TYPE_METADATA then
        return core.schema.check(metadata_schema, conf)
    end

    local ok, err = core.schema.check(schema, conf)
    if not ok then
        core.log.error(LOG_PREFIX, "schema validation failed: ", err)
        return nil, err
    end

    -- Optional: validate SSL paths exist when ssl=true
    if conf.ssl then
        if conf.ssl_ca_location then
            local f = io.open(conf.ssl_ca_location, "r")
            if not f then
                return nil, "SSL CA file not found: " .. conf.ssl_ca_location
            end
            f:close()
        end

        if conf.ssl_certificate_location then
            local f = io.open(conf.ssl_certificate_location, "r")
            if not f then
                return nil, "SSL client cert file not found: " .. conf.ssl_certificate_location
            end
            f:close()
        end

        if conf.ssl_key_location then
            local f = io.open(conf.ssl_key_location, "r")
            if not f then
                return nil, "SSL client key file not found: " .. conf.ssl_key_location
            end
            f:close()
        end
    end

    local ok2, err2 = log_util.check_log_schema(conf)
    if not ok2 then
        return nil, err2
    end

    return true
end

----------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------

local function get_partition_id(prod, topic, log_message)
    -- Try to map a log message to its Kafka partition (debug helper)
    if prod.async then
        local ringbuffer = prod.ringbuffer
        if not ringbuffer or not ringbuffer.size or not ringbuffer.queue then
            return nil
        end

        for i = 1, ringbuffer.size, 3 do
            if ringbuffer.queue[i] == topic and
               ringbuffer.queue[i + 2] == log_message then
                return math.floor(i / 3)
            end
        end
        return nil
    end

    local sendbuffer = prod.sendbuffer
    if not sendbuffer or not sendbuffer.topics or not sendbuffer.topics[topic] then
        return nil
    end

    for _, message in pairs(sendbuffer.topics[topic]) do
        if log_message == message.queue[2] then
            return 1
        end
    end

    return nil
end

local function create_producer(broker_list, broker_config, cluster_name)
    core.log.info(LOG_PREFIX, "create_producer: brokers=", #broker_list,
                  ", cluster_name=", cluster_name or "nil",
                  ", ssl=", broker_config.ssl or false)

    local p, err = producer:new(broker_list, broker_config, cluster_name)
    if not p then
        core.log.error(LOG_PREFIX, "producer:new failed: ", err)
        return nil, err
    end

    return p
end

local function send_kafka_data(conf, prod, log_message)
    local ok, err = prod:send(conf.kafka_topic, conf.key, log_message)
    if not ok then
        core.log.error(LOG_PREFIX, "failed to send data to Kafka: ", err,
                       ", topic=", conf.kafka_topic, ", key=", conf.key)
        return false, "failed to send to Kafka topic " .. conf.kafka_topic ..
                      ": " .. (err or "unknown")
    end
    return true
end

----------------------------------------------------------------------
-- Phases
----------------------------------------------------------------------

function _M.access(conf, ctx)
    if conf.include_req_body then
        local should_read_body = true

        if conf.include_req_body_expr then
            if not conf.request_expr then
                local request_expr, err = expr.new(conf.include_req_body_expr)
                if not request_expr then
                    core.log.error(LOG_PREFIX, "generate request expr err: ", err)
                    return
                end
                conf.request_expr = request_expr
            end

            local result = conf.request_expr:eval(ctx.var)
            if not result then
                should_read_body = false
            end
        end

        if should_read_body then
            req_read_body()
        end
    end
end

function _M.body_filter(conf, ctx)
    log_util.collect_body(conf, ctx)
end

function _M.log(conf, ctx)
    local entry
    if conf.meta_format == "origin" then
        entry = log_util.get_req_original(ctx, conf)
    else
        entry = log_util.get_log_entry(plugin_name, conf, ctx)
    end

    local added = bp_manager:add_entry(conf, entry)
    if added then
        return
    end

    ------------------------------------------------------------------
    -- Build broker_list and producer_config
    ------------------------------------------------------------------
    local broker_list = core.table.clone(conf.brokers or {})
    if conf.broker_list then
        for _, host_port in pairs(conf.broker_list) do
            core.table.insert(broker_list, {
                host = host_port.host,
                port = host_port.port,
            })
        end
    end

    -- Apply global SASL -> per-broker sasl_config (if not present)
    if conf.sasl and conf.sasl_username and conf.sasl_password then
        for _, b in ipairs(broker_list) do
            if not b.sasl_config then
                b.sasl_config = {
                    mechanism = conf.sasl_mechanism or "PLAIN",
                    user      = conf.sasl_username,
                    password  = conf.sasl_password,
                }
            end
        end
    end

    local broker_config = {}

    -- timeouts in ms
    broker_config.request_timeout = conf.timeout or 1000

    broker_config.producer_type   = conf.producer_type
    broker_config.required_acks   = conf.required_acks
    broker_config.batch_num       = conf.producer_batch_num
    broker_config.batch_size      = conf.producer_batch_size
    broker_config.max_buffering   = conf.producer_max_buffering

    -- APISIX uses seconds; lua-resty-kafka uses ms for flush_time
    broker_config.flush_time      = (conf.producer_time_linger or 1) * 1000

    -- lua-resty-kafka expects seconds for refresh_interval
    broker_config.refresh_interval = conf.meta_refresh_interval or 30

    -- SSL options propagated into client.socket_config (via client.lua)
    broker_config.ssl                 = conf.ssl or false
    broker_config.ssl_verify          = conf.ssl_verify or false
    broker_config.ssl_ca_location     = conf.ssl_ca_location
    broker_config.ssl_certificate_location = conf.ssl_certificate_location
    broker_config.ssl_key_location    = conf.ssl_key_location
    broker_config.ssl_key_password    = conf.ssl_key_password

    local prod, err = lrucache.plugin_ctx(
        lrucache, ctx, nil, create_producer,
        broker_list, broker_config, conf.cluster_name
    )

    if not prod then
        core.log.error(LOG_PREFIX, "failed to create kafka producer: ", err)
        return
    end

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
            core.log.error(LOG_PREFIX, "failed to encode data: ", jerr)
            return false, "encode error: " .. (jerr or "unknown")
        end

        local ok2, send_err = send_kafka_data(conf, prod, data)
        return ok2, send_err
    end

    bp_manager:add_entry_to_new_processor(conf, entry, ctx, func)
end

return _M
