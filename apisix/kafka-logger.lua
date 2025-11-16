-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--

local expr     = require("resty.expr.v1")
local core     = require("apisix.core")
local log_util = require("apisix.utils.log-util")

local producer = require("resty.kafka.producer")

local bp_manager_mod = require("apisix.utils.batch-processor-manager")
local plugin         = require("apisix.plugin")

local math  = math
local pairs = pairs
local type  = type

local req_read_body = ngx.req.read_body
local plugin_name   = "kafka-logger"

local LOG_PREFIX    = "[kafka-logger][debug] "

-- IMPORTANT: use manager instance, as in upstream 3.12
local batch_processor_manager = bp_manager_mod.new("kafka logger")

local lrucache = core.lrucache.new({
    type = "plugin",
})

--------------------------------------------------------------------------------
-- Schema
--------------------------------------------------------------------------------

local schema = {
    type = "object",
    properties = {
        meta_format = {
            type = "string",
            default = "default",
            enum = {"default", "origin"},
        },

        log_format = { type = "object" },

        -- deprecated, use "brokers" instead
        broker_list = {
            type = "object",
            minProperties = 1,
            patternProperties = {
                [".*"] = {
                    description = "the port of kafka broker",
                    type = "integer",
                    minimum = 1,
                    maximum = 65535,
                },
            },
        },

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
                        minimum = 1,
                        maximum = 65535,
                        description = "the port of kafka broker",
                    },
                    sasl_config = {
                        type = "object",
                        description = "sasl config",
                        properties = {
                            mechanism = {
                                type = "string",
                                default = "PLAIN",
                                enum = {"PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"},
                            },
                            user = {
                                type = "string",
                                description = "user",
                            },
                            password = {
                                type = "string",
                                description = "password",
                            },
                        },
                        required = { "user", "password" },
                    },
                },
                required = { "host", "port" },
            },
            uniqueItems = true,
        },

        kafka_topic   = { type = "string" },

        producer_type = {
            type = "string",
            default = "async",
            enum = { "async", "sync" },
        },

        required_acks = {
            type = "integer",
            default = 1,
            enum = { 1, -1 },
        },

        key = { type = "string" },

        -- APISIX docs: seconds
        timeout = {
            type = "integer",
            minimum = 1,
            default = 3,
        },

        ----------------------------------------------------------------------------
        -- SSL options for lua-resty-kafka
        ----------------------------------------------------------------------------
        ssl = {
            type        = "boolean",
            default     = false,
            description = "Enable SSL/TLS for Kafka connection (lua-resty-kafka client.ssl)",
        },

        ssl_verify = {
            type        = "boolean",
            default     = false,
            description = "Verify Kafka broker certificate (lua-resty-kafka client.ssl_verify)",
        },

        -- Plugin-level SSL paths (we map them to lua-resty-kafka names)
        ssl_ca_location = {
            type        = "string",
            description = "Path to CA certificate file used to verify broker (optional if broker cert is public / in system trust store)",
        },

        ssl_certificate_location = {
            type        = "string",
            description = "Path to client certificate file for mTLS (optional)",
        },

        ssl_key_location = {
            type        = "string",
            description = "Path to client private key file for mTLS (optional)",
        },

        ssl_key_password = {
            type        = "string",
            description = "Password for client private key (if encrypted, optional)",
        },

        ----------------------------------------------------------------------------
        -- Body capture settings
        ----------------------------------------------------------------------------
        include_req_body = {
            type    = "boolean",
            default = false,
        },

        include_req_body_expr = {
            type     = "array",
            minItems = 1,
            items    = {
                type = "array",
            },
        },

        include_resp_body = {
            type    = "boolean",
            default = false,
        },

        include_resp_body_expr = {
            type     = "array",
            minItems = 1,
            items    = {
                type = "array",
            },
        },

        max_req_body_bytes = {
            type     = "integer",
            minimum  = 1,
            default  = 524288,
        },

        max_resp_body_bytes = {
            type     = "integer",
            minimum  = 1,
            default  = 524288,
        },

        -- in lua-resty-kafka, cluster_name is defined as number
        -- see https://github.com/doujiang24/lua-resty-kafka#new-1
        cluster_name = {
            type    = "integer",
            minimum = 1,
            default = 1,
        },

        -- config for lua-resty-kafka, default value is same as lua-resty-kafka
        producer_batch_num = {
            type    = "integer",
            minimum = 1,
            default = 200,
        },

        producer_batch_size = {
            type    = "integer",
            minimum = 0,
            default = 1048576,
        },

        producer_max_buffering = {
            type    = "integer",
            minimum = 1,
            default = 50000,
        },

        -- seconds
        producer_time_linger = {
            type    = "integer",
            minimum = 1,
            default = 1,
        },

        -- seconds (APISIX docs say seconds; lua-resty-kafka expects ms, we convert)
        meta_refresh_interval = {
            type    = "integer",
            minimum = 1,
            default = 30,
        },
    },

    oneOf = {
        {
            required = { "broker_list", "kafka_topic" },
        },
        {
            required = { "brokers", "kafka_topic" },
        },
    },
}

local metadata_schema = {
    type = "object",
    properties = {
        log_format = {
            type = "object",
        },
        max_pending_entries = {
            type        = "integer",
            description = "maximum number of pending entries in the batch processor",
            minimum     = 1,
        },
    },
}

--------------------------------------------------------------------------------
-- Module table
--------------------------------------------------------------------------------

local _M = {
    version         = 0.1,
    priority        = 403,
    name            = plugin_name,
    schema          = batch_processor_manager:wrap_schema(schema),
    metadata_schema = metadata_schema,
}

--------------------------------------------------------------------------------
-- Schema check
--------------------------------------------------------------------------------

function _M.check_schema(conf, schema_type)
    if schema_type == core.schema.TYPE_METADATA then
        return core.schema.check(metadata_schema, conf)
    end

    core.log.info(LOG_PREFIX,
        "check_schema: validating main schema, ssl=",
        tostring(conf.ssl),
        ", ssl_verify=", tostring(conf.ssl_verify),
        ", ssl_ca_location=", tostring(conf.ssl_ca_location),
        ", ssl_certificate_location=", tostring(conf.ssl_certificate_location),
        ", ssl_key_location=", tostring(conf.ssl_key_location)
    )

    local ok, err = core.schema.check(schema, conf)
    if not ok then
        core.log.error(LOG_PREFIX, "check_schema: main schema invalid: ", err)
        return nil, err
    end

    -- Optional: sanity-check SSL files if ssl is enabled
    if conf.ssl then
        if conf.ssl_ca_location then
            local f = io.open(conf.ssl_ca_location, "r")
            if not f then
                core.log.error(LOG_PREFIX,
                    "check_schema: SSL CA file not found: ",
                    conf.ssl_ca_location
                )
                return nil, "SSL CA file not found: " .. conf.ssl_ca_location
            end
            f:close()
        end

        if conf.ssl_certificate_location then
            local f = io.open(conf.ssl_certificate_location, "r")
            if not f then
                core.log.error(LOG_PREFIX,
                    "check_schema: SSL client certificate file not found: ",
                    conf.ssl_certificate_location
                )
                return nil, "SSL client certificate file not found: "
                            .. conf.ssl_certificate_location
            end
            f:close()
        end

        if conf.ssl_key_location then
            local f = io.open(conf.ssl_key_location, "r")
            if not f then
                core.log.error(LOG_PREFIX,
                    "check_schema: SSL client key file not found: ",
                    conf.ssl_key_location
                )
                return nil, "SSL client key file not found: "
                            .. conf.ssl_key_location
            end
            f:close()
        end
    end

    local ok2, err2 = log_util.check_log_schema(conf)
    if not ok2 then
        core.log.error(LOG_PREFIX, "check_schema: log schema invalid: ", err2)
        return nil, err2
    end

    core.log.info(LOG_PREFIX, "check_schema: schema validation OK")
    return true
end

--------------------------------------------------------------------------------
-- Helper: determine partition id (debug only)
--------------------------------------------------------------------------------

local function get_partition_id(prod, topic, log_message)
    if prod.async then
        local ringbuffer = prod.ringbuffer

        for i = 1, ringbuffer.size, 3 do
            if ringbuffer.queue[i] == topic
                and ringbuffer.queue[i + 2] == log_message
            then
                return math.floor(i / 3)
            end
        end

        core.log.info(LOG_PREFIX,
            "get_partition_id: current topic in ringbuffer has no message")
        return nil
    end

    -- sync mode
    local sendbuffer = prod.sendbuffer

    if not sendbuffer.topics[topic] then
        core.log.info(LOG_PREFIX,
            "get_partition_id: current topic in sendbuffer has no message")
        return nil
    end

    for i, message in pairs(sendbuffer.topics[topic]) do
        if log_message == message.queue[2] then
            return i
        end
    end
end

--------------------------------------------------------------------------------
-- Helper: create producer
--------------------------------------------------------------------------------

local function create_producer(broker_list, broker_config, cluster_name)
    core.log.info(LOG_PREFIX,
        "create_producer: creating new kafka producer instance, brokers_count=",
        #broker_list,
        ", cluster_name=", tostring(cluster_name),
        ", ssl=", tostring(broker_config.ssl),
        ", ssl_verify=", tostring(broker_config.ssl_verify),
        ", ssl_cafile=", tostring(broker_config.ssl_cafile),
        ", ssl_cert=", tostring(broker_config.ssl_cert),
        ", ssl_key=", tostring(broker_config.ssl_key)
    )

    return producer:new(broker_list, broker_config, cluster_name)
end

--------------------------------------------------------------------------------
-- Helper: send to Kafka
--------------------------------------------------------------------------------

local function send_kafka_data(conf, log_message, prod)
    local ok, err = prod:send(conf.kafka_topic, conf.key, log_message)

    core.log.info(
        LOG_PREFIX,
        "send_kafka_data: partition_id=",
        core.log.delay_exec(get_partition_id, prod, conf.kafka_topic, log_message)
    )

    if not ok then
        core.log.error(LOG_PREFIX,
            "send_kafka_data: failed to send to topic=",
            conf.kafka_topic,
            ", err=", err or "nil"
        )

        return false,
            "failed to send data to Kafka topic: "
                .. (err or "unknown")
                .. ", brokers: "
                .. (conf.broker_list and core.json.encode(conf.broker_list)
                                     or "nil")
    end

    core.log.info(LOG_PREFIX,
        "send_kafka_data: successfully sent to topic=",
        conf.kafka_topic)
    return true
end

--------------------------------------------------------------------------------
-- Phases
--------------------------------------------------------------------------------

function _M.access(conf, ctx)
    core.log.info(LOG_PREFIX,
        "access phase: include_req_body=",
        tostring(conf.include_req_body),
        ", include_req_body_expr_set=",
        tostring(conf.include_req_body_expr ~= nil)
    )

    if conf.include_req_body then
        local should_read_body = true

        if conf.include_req_body_expr then
            if not conf.request_expr then
                local request_expr, err = expr.new(conf.include_req_body_expr)
                if not request_expr then
                    core.log.error(LOG_PREFIX,
                        "access: generate request expr err: ", err)
                    return
                end

                conf.request_expr = request_expr
            end

            local result = conf.request_expr:eval(ctx.var)
            core.log.info(LOG_PREFIX,
                "access: request_expr eval result=",
                tostring(result))
            if not result then
                should_read_body = false
            end
        end

        if should_read_body then
            core.log.info(LOG_PREFIX, "access: calling req_read_body()")
            req_read_body()
        else
            core.log.info(LOG_PREFIX,
                "access: skipping req_read_body() based on expr result")
        end
    end
end

function _M.body_filter(conf, ctx)
    core.log.info(LOG_PREFIX,
        "body_filter: include_resp_body=",
        tostring(conf.include_resp_body),
        ", include_resp_body_expr_set=",
        tostring(conf.include_resp_body_expr ~= nil)
    )
    log_util.collect_body(conf, ctx)
end

function _M.log(conf, ctx)
    core.log.info(LOG_PREFIX,
        "log phase: meta_format=", conf.meta_format,
        ", kafka_topic=", tostring(conf.kafka_topic),
        ", producer_type=", tostring(conf.producer_type),
        ", ssl=", tostring(conf.ssl),
        ", ssl_verify=", tostring(conf.ssl_verify),
        ", ssl_ca_location=", tostring(conf.ssl_ca_location),
        ", ssl_certificate_location=", tostring(conf.ssl_certificate_location),
        ", ssl_key_location=", tostring(conf.ssl_key_location)
    )

    local metadata = plugin.plugin_metadata(plugin_name)
    local max_pending_entries =
        metadata
        and metadata.value
        and metadata.value.max_pending_entries
        or nil

    local entry
    if conf.meta_format == "origin" then
        entry = log_util.get_req_original(ctx, conf)
    else
        entry = log_util.get_log_entry(plugin_name, conf, ctx)
    end

    if batch_processor_manager:add_entry(conf, entry, max_pending_entries) then
        core.log.info(LOG_PREFIX,
            "log: added entry to existing batch processor, returning")
        return
    end

    ------------------------------------------------------------------------
    -- Build broker list & broker_config (this is where we inject SSL)
    ------------------------------------------------------------------------
    local broker_list   = core.table.clone(conf.brokers or {})
    local broker_config = {}

    if conf.broker_list then
        for host, port in pairs(conf.broker_list) do
            local broker = {
                host = host,
                port = port,
            }
            core.table.insert(broker_list, broker)
        end
    end

    for i, b in ipairs(broker_list) do
        core.log.info(LOG_PREFIX,
            "log: broker[", i, "] host=", tostring(b.host),
            ", port=", tostring(b.port))
    end

    -- lua-resty-kafka expects ms for request_timeout/flush_time/refresh_interval
    broker_config.request_timeout  = (conf.timeout or 3) * 1000
    broker_config.producer_type    = conf.producer_type
    broker_config.required_acks    = conf.required_acks
    broker_config.batch_num        = conf.producer_batch_num
    broker_config.batch_size       = conf.producer_batch_size
    broker_config.max_buffering    = conf.producer_max_buffering
    broker_config.flush_time       = (conf.producer_time_linger or 1) * 1000
    broker_config.refresh_interval = (conf.meta_refresh_interval or 30) * 1000

    -- SSL flags
    broker_config.ssl        = conf.ssl or false
    broker_config.ssl_verify = conf.ssl_verify or false

    -- Canonical lua-resty-kafka field names (what client.lua expects)
    if conf.ssl_ca_location then
        broker_config.ssl_cafile = conf.ssl_ca_location
    end

    if conf.ssl_certificate_location then
        broker_config.ssl_cert = conf.ssl_certificate_location
    end

    if conf.ssl_key_location then
        broker_config.ssl_key = conf.ssl_key_location
    end

    if conf.ssl_key_password then
        broker_config.ssl_key_password = conf.ssl_key_password
    end

    -- Also keep *_location for backward compatibility / logging
    broker_config.ssl_ca_location          = conf.ssl_ca_location
    broker_config.ssl_certificate_location = conf.ssl_certificate_location
    broker_config.ssl_key_location         = conf.ssl_key_location

    core.log.info(LOG_PREFIX,
        "log: broker_config summary: request_timeout=",
        tostring(broker_config.request_timeout),
        ", flush_time=", tostring(broker_config.flush_time),
        ", refresh_interval=", tostring(broker_config.refresh_interval),
        ", ssl=", tostring(broker_config.ssl),
        ", ssl_verify=", tostring(broker_config.ssl_verify),
        ", ssl_cafile=", tostring(broker_config.ssl_cafile),
        ", ssl_cert=", tostring(broker_config.ssl_cert),
        ", ssl_key=", tostring(broker_config.ssl_key),
        ", ssl_key_password_set=",
        tostring(broker_config.ssl_key_password and true or false)
    )

    local prod, err = core.lrucache.plugin_ctx(
        lrucache, ctx, nil,
        create_producer,
        broker_list, broker_config, conf.cluster_name
    )

    core.log.info(
        LOG_PREFIX,
        "log: kafka cluster name=", tostring(conf.cluster_name),
        ", first broker port=",
        prod and prod.client and prod.client.broker_list
            and prod.client.broker_list[1]
            and prod.client.broker_list[1].port or "nil"
    )

    if err then
        core.log.error(LOG_PREFIX,
            "log: failed to identify broker: ", err)
        return nil, "failed to identify the broker specified: " .. err
    end

    -- Function executed by batch processor
    local func = function(entries, batch_max_size)
        local data, jerr

        if batch_max_size == 1 then
            data = entries[1]
            if type(data) ~= "string" then
                data, jerr = core.json.encode(data) -- encode as single {}
            end
        else
            data, jerr = core.json.encode(entries) -- encode as array [{}]
        end

        if not data then
            core.log.error(LOG_PREFIX,
                "batch func: failed to encode data: ", jerr)
            return false, "error occurred while encoding the data: "
                          .. (jerr or "unknown")
        end

        core.log.info(LOG_PREFIX,
            "batch func: sending encoded data to kafka, length=",
            #data)

        return send_kafka_data(conf, data, prod)
    end

    batch_processor_manager:add_entry_to_new_processor(
        conf, entry, ctx, func, max_pending_entries
    )

    core.log.info(LOG_PREFIX,
        "log: created new batch processor and added first entry")
end

return _M
