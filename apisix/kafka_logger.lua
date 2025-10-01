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

local lrucache = core.lrucache.new({
    type = "plugin",
})

-- --------------------------------------------------------------------------
-- Schema
-- --------------------------------------------------------------------------
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
                        description = "sasl config",
                        properties = {
                            mechanism = {
                                type = "string",
                                default = "PLAIN",
                                enum = {"PLAIN"},
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
            default = 1000,
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

        -- SSL/TLS options
        ssl = { type = "boolean", default = false },
        ssl_verify = { type = "boolean", default = false },
        ssl_cafile = { type = "string" },
        ssl_cert   = { type = "string" },
        ssl_key    = { type = "string" },
        ssl_protocol = {
            type = "string",
            enum = {"tlsv1", "tlsv1_1", "tlsv1_2", "tlsv1_3"},
            default = "tlsv1_2"
        },
    },

    oneOf = {
        { required = {"broker_list", "kafka_topic"} },
        { required = {"brokers", "kafka_topic"} },
    },
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
local _M = {
    version = 0.2,
    priority = 403,
    name = plugin_name,
    schema = bp_manager:wrap_schema(schema),
    metadata_schema = metadata_schema,
}

function _M.check_schema(conf, schema_type)
    if schema_type == core.schema.TYPE_METADATA then
        return core.schema.check(metadata_schema, conf)
    end

    local ok, err = core.schema.check(schema, conf)
    if not ok then
        return nil, err
    end

    return log_util.check_log_schema(conf)
end

-- --------------------------------------------------------------------------
-- Internal helpers
-- --------------------------------------------------------------------------

local function create_producer(broker_list, broker_config, cluster_name)
    core.log.info("create new kafka producer")
    return producer:new(broker_list, broker_config, cluster_name)
end

local function send_kafka_data(conf, ctx, prod, log_message)
    local ok, err = prod:send(conf.kafka_topic, conf.key, log_message)
    if not ok then
        return false, "failed to send data to Kafka topic: " .. (err or "unknown") ..
                      ", brokers: " .. core.json.encode(conf.broker_list)
    end
    return true
end

-- --------------------------------------------------------------------------
-- Phases
-- --------------------------------------------------------------------------

function _M.access(conf, ctx)
    if conf.include_req_body then
        local should_read_body = true
        if conf.include_req_body_expr then
            if not conf.request_expr then
                local request_expr, err = expr.new(conf.include_req_body_expr)
                if not request_expr then
                    core.log.error("generate request expr err: ", err)
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

    if bp_manager:add_entry(conf, entry) then
        return
    end

    local broker_list = core.table.clone(conf.brokers or {})
    local broker_config = {}

    if conf.broker_list then
        for _, host_port in pairs(conf.broker_list) do
            local broker = { host = host_port.host, port = host_port.port }
            core.table.insert(broker_list, broker)
        end
    end

    broker_config["request_timeout"]   = conf.timeout or 1000
    broker_config["producer_type"]     = conf.producer_type
    broker_config["required_acks"]     = conf.required_acks
    broker_config["batch_num"]         = conf.producer_batch_num
    broker_config["batch_size"]        = conf.producer_batch_size
    broker_config["max_buffering"]     = conf.producer_max_buffering
    broker_config["flush_time"]        = (conf.producer_time_linger or -1) * 1000
    broker_config["refresh_interval"]  = (conf.meta_refresh_interval or 30) * 1000

    -- Add SSL/TLS options if enabled
    if conf.ssl then
        broker_config.ssl = true
        broker_config.ssl_opts = {
            protocol    = conf.ssl_protocol,
            verify      = conf.ssl_verify and "peer" or "none",
            cafile      = conf.ssl_cafile,
            certificate = conf.ssl_cert,
            key         = conf.ssl_key,
        }
    end

    local prod, err = lrucache.plugin_ctx(lrucache, ctx, nil, create_producer,
        broker_list, broker_config, conf.cluster_name)

    if err then
        return nil, "failed to identify the broker specified: " .. err
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
            return false, "error occurred while encoding the data: " .. (jerr or "unknown")
        end

        core.log.info("send data to kafka: ", data)
        return send_kafka_data(conf, ctx, prod, data)
    end

    bp_manager:add_entry_to_new_processor(conf, entry, ctx, func)
end

return _M
