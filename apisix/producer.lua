-- In the producer:new function
local function new(self, broker_list, producer_config)
    producer_config = producer_config or {}
    
    local broker_list = broker_list or {}
    if #broker_list == 0 then
        return nil, "broker_list must be specified"
    end

    local self = {
        broker_list = broker_list,
        producer_config = producer_config,
        -- existing config...
        
        -- SSL/TLS configuration
        ssl = producer_config.ssl,
        ssl_verify = producer_config.ssl_verify,
        sasl = producer_config.sasl,
        sasl_username = producer_config.sasl_username,
        sasl_password = producer_config.sasl_password,
        sasl_mechanism = producer_config.sasl_mechanism,
        ssl_ca_cert = producer_config.ssl_ca_cert,
        ssl_client_cert = producer_config.ssl_client_cert,
        ssl_client_key = producer_config.ssl_client_key,
    }
    
    -- rest of existing initialization...
end
