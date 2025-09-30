local core = require("apisix.core")
local producer = require("resty.kafka.producer")
local plugin_name = "kafka-logger"

local schema = {
    type = "object",
    properties = {
        brokers = {
            type = "array",
            items = { type = "string" }
        },
        kafka_topic = { type = "string" },
        key = { type = "string" },
        timeout = { type = "integer", minimum = 1, default = 3 },
        batch_max_size = { type = "integer", minimum = 1, default = 1000 },
        inactive_timeout = { type = "integer", minimum = 1, default = 5 },
        buffer_duration = { type = "integer", minimum = 1, default = 60 },
        max_retry_count = { type = "integer", minimum = 0, default = 0 },
        retry_delay = { type = "integer", minimum = 0, default = 1 },
        
        -- New SSL/TLS options
        ssl = { 
            type = "boolean", 
            default = false,
            description = "Enable SSL/TLS connection to Kafka"
        },
        ssl_verify = { 
            type = "boolean", 
            default = false,
            description = "Verify Kafka server certificate"
        },
        sasl = { 
            type = "boolean", 
            default = false,
            description = "Enable SASL authentication"
        },
        sasl_username = { 
            type = "string",
            description = "SASL username for authentication"
        },
        sasl_password = { 
            type = "string",
            description = "SASL password for authentication"
        },
        sasl_mechanism = { 
            type = "string", 
            enum = { "PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512" },
            default = "PLAIN",
            description = "SASL authentication mechanism"
        },
        -- Certificate options - use string for base64 encoded certs
        ca_cert = { 
            type = "string",
            description = "Base64 encoded CA certificate"
        },
        client_cert = { 
            type = "string", 
            description = "Base64 encoded client certificate"
        },
        client_key = { 
            type = "string",
            description = "Base64 encoded client private key"
        },
    },
    required = { "brokers", "kafka_topic" }
}

local _M = {
    version = 2.0,
    priority = 406,
    name = plugin_name,
    schema = schema,
}

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

-- Create Kafka producer configuration
local function create_kafka_config(conf)
    local kafka_config = {
        broker_list = conf.brokers,
        producer_type = "async",
        required_acks = 1,
        -- SSL/TLS configuration
        ssl = conf.ssl,
        ssl_verify = conf.ssl_verify,
        sasl = conf.sasl,
        sasl_username = conf.sasl_username,
        sasl_password = conf.sasl_password,
        sasl_mechanism = conf.sasl_mechanism,
    }

    -- Handle SSL certificates if provided
    if conf.ssl then
        if conf.ca_cert then
            kafka_config.ssl_ca_cert = conf.ca_cert
        end
        if conf.client_cert then
            kafka_config.ssl_client_cert = conf.client_cert
        end
        if conf.client_key then
            kafka_config.ssl_client_key = conf.client_key
        end
    end

    return kafka_config
end

-- Batch processor function
local function batch_process(entries)
    local conf = entries[1].conf
    local entry_count = #entries
    
    core.log.info("Processing ", entry_count, " log entries to Kafka topic: ", conf.kafka_topic)
    
    local kafka_config = create_kafka_config(conf)
    local prod, err = producer:new(kafka_config)
    
    if not prod then
        core.log.error("failed to create kafka producer: ", err)
        return false, err
    end

    for i, entry in ipairs(entries) do
        local ok, send_err = prod:send(conf.kafka_topic, conf.key, entry.data)
        if not ok then
            core.log.error("failed to send log to kafka: ", send_err)
            -- You might want to implement retry logic here
        end
    end

    return true
end

function _M.log(conf, ctx)
    local entry = core.json.encode({
        -- Your existing log format here
        client_ip = ctx.var.remote_addr,
        method = ctx.var.request_method,
        uri = ctx.var.request_uri,
        host = ctx.var.host,
        time = ngx.now() * 1000, -- current timestamp in milliseconds
        service_name = "apisix"
    })

    local log_entry = {
        conf = conf,
        data = entry
    }

    -- Use batch processor if available, otherwise send directly
    if core.batch_processor then
        core.batch_processor:push(log_entry, batch_process)
    else
        -- Fallback to immediate sending
        local kafka_config = create_kafka_config(conf)
        local prod, err = producer:new(kafka_config)
        
        if not prod then
            core.log.error("failed to create kafka producer: ", err)
            return
        end

        local ok, send_err = prod:send(conf.kafka_topic, conf.key, entry)
        if not ok then
            core.log.error("failed to send log to kafka: ", send_err)
        end
    end
end

return _M
