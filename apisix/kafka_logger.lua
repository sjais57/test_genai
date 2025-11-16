-- Copyright (C) Apache APISIX

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

core.log.info(LOG_PREFIX, "loading plugin module")

local lrucache = core.lrucache.new({
    type = "plugin",
})

-- --------------------------------------------------------------------------
-- Schema
-- --------------------------------------------------------------------------
core.log.info(LOG_PREFIX, "defining schema")

local schema = {
    type = "object",
    properties = {
        meta_format = {
            type = "string",
            default = "default",
            enum = {"default", "origin"},
        },

        log_format  = { type = "object" },

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
                        description = "per-broker SASL config",
                        properties = {
                            mechanism = {
                                type = "string",
                                default = "PLAIN",
                                enum = {"PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"},
                            },
                            user = { type = "string", description = "user" },
                            password = { type = "string", description = "password" },
                        },
                        required = {"user", "password"},
                    },
                },
                required = {"host", "port"},
            },
            uniqueItems = true,
        },

        -- Deprecated, but kept for backward compatibility
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
            default = 1000,  -- milliseconds
            description = "request timeout in ms for Kafka producer (passed as request_timeout)"
        },

        ----------------------------------------------------------------------
        -- SSL / TLS + SASL options (mapped to lua-resty-kafka)
        ----------------------------------------------------------------------
        ssl = {
            type = "boolean",
            default = false,
            description = "Enable SSL/TLS connection to Kafka (producer_config.ssl)"
        },
        ssl_verify = {
            type = "boolean",
            default = false,
            description = "Verify Kafka broker certificate (producer_config.ssl_verify)"
        },

        -- Optional “global” SASL config (we map it into brokers[*].sasl_config)
        sasl = {
            type = "boolean",
            default = false,
            description = "Enable SASL authentication on all brokers if sasl_config is not set per broker"
        },
        sasl_username = {
            type = "string",
            description = "Global SASL username (used when sasl = true)"
        },
        sasl_password = {
            type = "string",
            description = "Global SASL password (used when sasl = true)"
        },
        sasl_mechanism = {
            type = "string",
            enum = {"PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"},
            default = "PLAIN",
            description = "Global SASL mechanism"
        },

        -- These are only validated here; actual trust is controlled by
        -- lua_ssl_trusted_certificate / lua_ssl_verify_depth in nginx.conf.
        ssl_ca_location = {
            type = "string",
            description = "Path to CA certificate file (optional, for validation only)"
        },
        ssl_certificate_location = {
            type = "string",
            description = "Path to client certificate file (optional, if mTLS enabled)"
        },
        ssl_key_location = {
            type = "string",
            description = "Path to client private key file (optional, if mTLS enabled)"
        },
        ssl_key_password = {
            type = "string",
            description = "Password for client private key (optional)"
        },

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

        producer_batch_num    = { type = "integer", minimum = 1, default = 200 },
        producer_batch_size   = { type = "integer", minimum = 1, default = 1048576 },
        producer_max_buffering= { type = "integer", minimum = 1, default = 50000 },
        producer_time_linger  = { type = "integer", minimum = -1, default = -1 },
        meta_refresh_interval = { type = "integer", minimum = 1, default = 30 },
    },
    required = {"brokers", "kafka_topic"},
}

local metadata_schema = {
    type = "object",
    properties = {
        log_format = { type = "object" },
    },
}

-- --------------------------------------------------------------------------
-- Module definition
-- --------------------------------------------------------------------------
core.log.info(LOG_PREFIX, "defining module table")

local _M = {
    version = 0.1,
    priority = 403,
    name = plugin_name,
    schema = bp_manager:wrap_schema(schema),
    metadata_schema = metadata_schema,
}

function _M.check_schema(conf, schema_type)
    core.log.info(LOG_PREFIX, "check_schema called, schema_type: ", schema_type)

    if schema_type == core.schema.TYPE_METADATA then
        core.log.info(LOG_PREFIX, "validating metadata schema")
        return core.schema.check(metadata_schema, conf)
    end

    core.log.info(LOG_PREFIX, "validating main schema, ssl=", tostring(conf.ssl),
                  ", brokers=", conf.brokers and #conf.brokers or 0,
                  ", topic=", conf.kafka_topic)

    local ok, err = core.schema.check(schema, conf)
    if not ok then
        core.log.error(LOG_PREFIX, "schema validation failed: ", err)
        return nil, err
    end

    -- basic sanity checks if global SASL is enabled
    if conf.sasl then
        if not conf.sasl_username or not conf.sasl_password then
            return nil, "sasl=true but sasl_username / sasl_password are missing"
        end
    end

    -- Validate SSL certificate files exist if SSL is enabled
    if conf.ssl then
        core.log.info(LOG_PREFIX, "SSL enabled in config, validating certificate paths")

        if conf.ssl_ca_location then
            core.log.info(LOG_PREFIX, "checking ssl_ca_location: ", conf.ssl_ca_location)
            local file = io.open(conf.ssl_ca_location, "r")
            if not file then
                core.log.error(LOG_PREFIX, "SSL CA certificate file not found: ", conf.ssl_ca_location)
                return nil, "SSL CA certificate file not found: " .. conf.ssl_ca_location
            end
            file:close()
        else
            core.log.info(LOG_PREFIX, "ssl_ca_location not provided (will rely on lua_ssl_trusted_certificate)")
        end

        if conf.ssl_certificate_location then
            core.log.info(LOG_PREFIX, "checking ssl_certificate_location: ", conf.ssl_certificate_location)
            local file = io.open(conf.ssl_certificate_location, "r")
            if not file then
                core.log.error(LOG_PREFIX, "SSL client certificate file not found: ", conf.ssl_certificate_location)
                return nil, "SSL client certificate file not found: " .. conf.ssl_certificate_location
            end
            file:close()
        else
            core.log.info(LOG_PREFIX, "ssl_certificate_location not provided (mTLS may be disabled)")
        end

        if conf.ssl_key_location then
            core.log.info(LOG_PREFIX, "checking ssl_key_location: ", conf.ssl_key_location)
            local file = io.open(conf.ssl_key_location, "r")
            if not file then
                core.log.error(LOG_PREFIX, "SSL client key file not found: ", conf.ssl_key_location)
                return nil, "SSL client key file not found: " .. conf.ssl_key_location
            end
            file:close()
        else
            core.log.info(LOG_PREFIX, "ssl_key_location not provided (mTLS may be disabled)")
        end
    else
        core.log.info(LOG_PREFIX, "SSL is disabled in config")
    end

    core.log.info(LOG_PREFIX, "calling log_util.check_log_schema")
    local ok2, err2 = log_util.check_log_schema(conf)
    if not ok2 then
        core.log.error(LOG_PREFIX, "log schema validation failed: ", err2)
        return nil, err2
    end

    core.log.info(LOG_PREFIX, "check_schema finished successfully")
    return true
end

-- --------------------------------------------------------------------------
-- Internal helpers
-- --------------------------------------------------------------------------

local function get_partition_id(prod, topic, log_message)
    core.log.info(LOG_PREFIX, "get_partition_id called for topic=", topic)

    -- Async mode: try ringbuffer
    if prod.async then
        core.log.info(LOG_PREFIX, "producer is async, checking ringbuffer")
        local ringbuffer = prod.ringbuffer
        if not ringbuffer or not ringbuffer.size or not ringbuffer.queue then
            core.log.info(LOG_PREFIX, "ringbuffer not initialized")
            return nil
        end

        for i = 1, ringbuffer.size, 3 do
            if ringbuffer.queue[i] == topic and
               ringbuffer.queue[i+2] == log_message then
                local pid = math.floor(i / 3)
                core.log.info(LOG_PREFIX, "partition found in ringbuffer at index=", pid)
                return pid
            end
        end
        core.log.info(LOG_PREFIX, "no partition found in ringbuffer for topic=", topic)
        return nil
    end

    -- Sync mode: look into sendbuffer
    core.log.info(LOG_PREFIX, "producer is sync, checking sendbuffer")
    local sendbuffer = prod.sendbuffer
    if not sendbuffer or not sendbuffer.topics or not sendbuffer.topics[topic] then
        core.log.info(LOG_PREFIX, "current topic in sendbuffer has no message")
        return nil
    end

    for _, message in pairs(sendbuffer.topics[topic]) do
        if log_message == message.queue[2] then
            core.log.info(LOG_PREFIX, "partition found in sendbuffer (returning 1)")
            return 1 -- first partition index found
        end
    end

    core.log.info(LOG_PREFIX, "no partition match in sendbuffer for topic=", topic)
end

local function create_producer(broker_list, broker_config, cluster_name)
    core.log.info(LOG_PREFIX, "create_producer called, brokers=", #broker_list,
                  ", cluster_name=", cluster_name,
                  ", ssl=", tostring(broker_config.ssl))

    for i, b in ipairs(broker_list) do
        core.log.info(LOG_PREFIX, "broker[", i, "] host=", b.host, ", port=", b.port)
    end

    local p, err = producer:new(broker_list, broker_config, cluster_name)
    if not p then
        core.log.error(LOG_PREFIX, "producer:new failed: ", err)
        return nil, err
    end

    core.log.info(LOG_PREFIX, "producer created successfully: ", tostring(p))
    return p
end

local function send_kafka_data(conf, ctx, prod, log_message)
    core.log.info(LOG_PREFIX, "send_kafka_data called, topic=", conf.kafka_topic,
                  ", msg_len=", #log_message)

    local ok, err = prod:send(conf.kafka_topic, conf.key, log_message)
    if not ok then
        core.log.error(LOG_PREFIX, "failed to send data to Kafka: ", err,
                       ", topic=", conf.kafka_topic,
                       ", key=", conf.key,
                       ", request_uri=", ctx and ctx.var and ctx.var.request_uri or "nil")

        return false, "failed to send data to Kafka topic: " .. (err or "unknown") ..
                      ", brokers: " .. core.json.encode(conf.brokers) ..
                      ", request: " .. (ctx and ctx.var and ctx.var.request_uri or "nil")
    end

    core.log.info(LOG_PREFIX, "successfully sent log to Kafka for request: ",
                  ctx and ctx.var and ctx.var.request_uri or "nil",
                  ", client: ", ctx and ctx.var and ctx.var.remote_addr or "nil",
                  ", topic: ", conf.kafka_topic,
                  ", data size: ", #log_message)
    return true
end

-- --------------------------------------------------------------------------
-- Phases
-- --------------------------------------------------------------------------

function _M.access(conf, ctx)
    core.log.info(LOG_PREFIX, "access phase entered, include_req_body=", tostring(conf.include_req_body))

    if conf.include_req_body then
        local should_read_body = true
        if conf.include_req_body_expr then
            core.log.info(LOG_PREFIX, "include_req_body_expr configured")

            if not conf.request_expr then
                core.log.info(LOG_PREFIX, "building request_expr from expr config")
                local request_expr, err = expr.new(conf.include_req_body_expr)
                if not request_expr then
                    core.log.error(LOG_PREFIX, "generate request expr err: ", err)
                    return
                end
                conf.request_expr = request_expr
            end

            local result = conf.request_expr:eval(ctx.var)
            core.log.info(LOG_PREFIX, "request_expr eval result: ", tostring(result))
            if not result then
                should_read_body = false
            end
        end

        if should_read_body then
            core.log.info(LOG_PREFIX, "calling ngx.req.read_body()")
            req_read_body()
        else
            core.log.info(LOG_PREFIX, "skipping body read as per expr evaluation")
        end
    end
end

function _M.body_filter(conf, ctx)
    core.log.info(LOG_PREFIX, "body_filter called, include_resp_body=", tostring(conf.include_resp_body))
    log_util.collect_body(conf, ctx)
end

function _M.log(conf, ctx)
    core.log.info(LOG_PREFIX, "log phase entered for request: ",
                  ctx and ctx.var and ctx.var.request_uri or "nil",
                  ", meta_format=", conf.meta_format)

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

    ----------------------------------------------------------------------
    -- Build broker_list + client / producer config
    ----------------------------------------------------------------------
    local broker_list = core.table.clone(conf.brokers or {})
    if conf.broker_list then
        for _, host_port in pairs(conf.broker_list) do
            local broker = {
                host = host_port.host,
                port = host_port.port
            }
            core.table.insert(broker_list, broker)
        end
    end

    -- If global SASL is enabled, inject sasl_config into each broker that
    -- doesn't already have per-broker sasl_config.
    if conf.sasl and conf.sasl_username and conf.sasl_password then
        for i, b in ipairs(broker_list) do
            if not b.sasl_config then
                b.sasl_config = {
                    mechanism = conf.sasl_mechanism or "PLAIN",
                    user      = conf.sasl_username,
                    password  = conf.sasl_password,
                }
                core.log.info(LOG_PREFIX, "applied global sasl_config to broker[", i, "]")
            end
        end
    end

    local broker_config = {}

    -- request_timeout is in ms for lua-resty-kafka
    broker_config.request_timeout = (conf.timeout or 1000)
    broker_config.producer_type   = conf.producer_type
    broker_config.required_acks   = conf.required_acks
    broker_config.batch_num       = conf.producer_batch_num
    broker_config.batch_size      = conf.producer_batch_size
    broker_config.max_buffering   = conf.producer_max_buffering
    broker_config.flush_time      = conf.producer_time_linger
    broker_config.refresh_interval= conf.meta_refresh_interval

    -- SSL / TLS flags as expected by lua-resty-kafka
    broker_config.ssl        = conf.ssl or false
    broker_config.ssl_verify = conf.ssl_verify or false

    core.log.info(LOG_PREFIX, "broker_config: request_timeout=", broker_config.request_timeout,
                  ", producer_type=", broker_config.producer_type,
                  ", required_acks=", broker_config.required_acks,
                  ", batch_num=", broker_config.batch_num,
                  ", batch_size=", broker_config.batch_size,
                  ", max_buffering=", broker_config.max_buffering,
                  ", flush_time=", broker_config.flush_time,
                  ", refresh_interval=", broker_config.refresh_interval,
                  ", ssl=", tostring(broker_config.ssl),
                  ", ssl_verify=", tostring(broker_config.ssl_verify),
                  ", brokers_count=", #broker_list,
                  ", cluster_name=", conf.cluster_name)

    local prod, err = lrucache.plugin_ctx(
        lrucache, ctx, nil, create_producer,
        broker_list, broker_config, conf.cluster_name
    )

    if not prod then
        core.log.error(LOG_PREFIX, "failed to create kafka producer: ", err)
        return nil, "failed to create kafka producer: " .. (err or "unknown")
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
            core.log.error(LOG_PREFIX, "failed to encode data for request: ",
                           ctx and ctx.var and ctx.var.request_uri or "nil",
                           ", error: ", jerr)
            return false, "error occurred while encoding the data: " .. (jerr or "unknown") ..
                          ", request: " .. (ctx and ctx.var and ctx.var.request_uri or "nil")
        end

        local ok, send_err = send_kafka_data(conf, ctx, prod, data)
        return ok, send_err
    end

    bp_manager:add_entry_to_new_processor(conf, entry, ctx, func)
end

return _M
