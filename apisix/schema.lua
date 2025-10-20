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

{
  "uri": "/test-kafka-logger",
  "methods": ["GET"],
  "plugins": {
    "kafka-logger": {
      "brokers": [
        { "host": "kafka1.mycorp.com", "port": 9093 }
      ],
      "kafka_topic": "apisix-logs",
      "producer_type": "async",
      "required_acks": 1,
      "timeout": 2000,
      "producer_batch_num": 10,
      "producer_batch_size": 1048576,
      "meta_refresh_interval": 30,
      "ssl": true,
      "ssl_verify": true,
      "ssl_cafile": "/etc/pki/tls/certs/ca-bundle.crt"
    }
  },
  "upstream": {
    "type": "roundrobin",
    "nodes": {
      "127.0.0.1:80": 1
    }
  }
}

