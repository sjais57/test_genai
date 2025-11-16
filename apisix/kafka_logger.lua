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
        -- NEW: SSL options for lua-resty-kafka
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

        -- These are passed through client.socket_config to your custom broker.lua
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

    local ok, err = core.schema.check(schema, conf)
    if not ok then
        return nil, err
    end

    -- Optional: sanity-check SSL files if ssl is enabled
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
                return nil, "SSL client certificate file not found: " .. conf.ssl_certificate_location
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

    return log_util.check_log_schema(conf)
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

        core.log.info("current topic in ringbuffer has no message")
        return nil
    end

    -- sync mode
    local sendbuffer = prod.sendbuffer

    if not sendbuffer.topics[topic] then
        core.log.info("current topic in sendbuffer has no message")
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
    core.log.info("create new kafka producer instance")
    return producer:new(broker_list, broker_config, cluster_name)
end

--------------------------------------------------------------------------------
-- Helper: send to Kafka
--------------------------------------------------------------------------------

local function send_kafka_data(conf, log_message, prod)
    local ok, err = prod:send(conf.kafka_topic, conf.key, log_message)

    core.log.info(
        "partition_id: ",
        core.log.delay_exec(get_partition_id, prod, conf.kafka_topic, log_message)
    )

    if not ok then
        return false,
            "failed to send data to Kafka topic: "
                .. err
                .. ", brokers: "
                .. core.json.encode(conf.broker_list)
    end

    return true
end

--------------------------------------------------------------------------------
-- Phases
--------------------------------------------------------------------------------

function _M.access(conf, ctx)
    if conf.include_req_body then
        local should_read_body = true

        if conf.include_req_body_expr then
            if not conf.request_expr then
                local request_expr, err = expr.new(conf.include_req_body_expr)
                if not request_expr then
                    core.log.error("generate request expr err ", err)
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
    -- *** IMPORTANT: use APISIX batch processor correctly ***
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
        return
    end

    ------------------------------------------------------------------------
    -- Build broker list & broker_config (this is where we inject SSL)
    ------------------------------------------------------------------------
    -- reuse producer via lrucache to avoid unbalanced partitions of messages in kafka
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

    -- lua-resty-kafka expects ms for request_timeout/flush_time/refresh_interval
    broker_config["request_timeout"]   = conf.timeout * 1000
    broker_config["producer_type"]     = conf.producer_type
    broker_config["required_acks"]     = conf.required_acks
    broker_config["batch_num"]         = conf.producer_batch_num
    broker_config["batch_size"]        = conf.producer_batch_size
    broker_config["max_buffering"]     = conf.producer_max_buffering
    broker_config["flush_time"]        = conf.producer_time_linger * 1000
    broker_config["refresh_interval"]  = conf.meta_refresh_interval * 1000

    -- NEW: SSL options propagated into client.socket_config → broker.lua
    broker_config["ssl"]                   = conf.ssl or false
    broker_config["ssl_verify"]            = conf.ssl_verify or false
    broker_config["ssl_ca_location"]       = conf.ssl_ca_location
    broker_config["ssl_certificate_location"] = conf.ssl_certificate_location
    broker_config["ssl_key_location"]      = conf.ssl_key_location
    broker_config["ssl_key_password"]      = conf.ssl_key_password

    local prod, err = core.lrucache.plugin_ctx(
        lrucache, ctx, nil,
        create_producer,
        broker_list, broker_config, conf.cluster_name
    )

    core.log.info(
        "kafka cluster name ",
        conf.cluster_name,
        ", broker_list[1] port ",
        prod and prod.client and prod.client.broker_list
            and prod.client.broker_list[1]
            and prod.client.broker_list[1].port or "nil"
    )

    if err then
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
            return false, "error occurred while encoding the data: " .. jerr
        end

        core.log.info("send data to kafka: ", data)
        return send_kafka_data(conf, data, prod)
    end

    batch_processor_manager:add_entry_to_new_processor(
        conf, entry, ctx, func, max_pending_entries
    )
end

return _M
