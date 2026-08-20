--
-- Centreon Broker Stream Connector
-- Normalized BBDO -> NDJSON for Wazuh
--
-- All Centreon-specific fields are stored below "centreon"
-- to avoid collisions with existing Wazuh/OpenSearch mappings.
--
-- Output example:
--
-- {
--   "timestamp": 1786561000,
--   "@source": "centreon",
--   "centreon": {
--     "category": "NEB",
--     "event_type": "service_status",
--     "category_id": 1,
--     "element_id": 29,
--
--     "host": {
--       "id": 12,
--       "name": "srv-linux-01"
--     },
--
--     "service": {
--       "id": 87,
--       "name": "Disk-/var"
--     },
--
--     "status": {
--       "code": 2,
--       "name": "CRITICAL",
--       "state_type": "HARD"
--     },
--
--     "acknowledgement": {
--       "type": 0
--     },
--
--     "downtime": {
--       "depth": 0
--     }
--   },
--
--   "message": "CRITICAL: /var is 96% full",
--   "performance_data": "..."
-- }
--

local output_file = "/var/log/centreon-broker/events.json"
local debug_file  = "/var/log/centreon-broker/json-dump.log"


----------------------------------------------------------------------
-- Categories
----------------------------------------------------------------------

local category_names = {
    [1]     = "NEB",
    [2]     = "BBDO",
    [3]     = "STORAGE",
    [4]     = "CORRELATION",
    [5]     = "DUMPER",
    [6]     = "BAM",
    [7]     = "EXTCMD",
    [65535] = "INTERNAL"
}


----------------------------------------------------------------------
-- Events we want to normalize
----------------------------------------------------------------------

local event_names = {

    [1] = {
        [27] = "service",
        [29] = "service_status",
        [30] = "host",
        [31] = "adaptive_host",
        [32] = "host_status",
        [33] = "severity",
        [34] = "tag",
        [35] = "comment",
        [36] = "downtime",
        [37] = "custom_variable",
        [38] = "custom_variable_status",
        [39] = "host_check",
        [40] = "service_check",
        [41] = "log_entry",
        [42] = "instance_status",
        [44] = "instance",
        [45] = "acknowledgement",
        [46] = "responsive_instance",
        [49] = "host_group",
        [50] = "service_group_member",
        [51] = "service_group",
        [53] = "host_parent",
        [54] = "instance_configuration",
        [55] = "adaptive_service_status",
        [56] = "adaptive_host_status"
    },

    [2] = {
        [7] = "welcome",
        [8] = "ack",
        [9] = "stop"
    },

    [3] = {
        [7]  = "rebuild",
        [8]  = "remove_graph",
        [9]  = "metric",
        [10] = "status",
        [11] = "index_mapping",
        [12] = "metric_mapping"
    },

    [6] = {
        [12] = "rebuild",
        [18] = "inherited_downtime",
        [19] = "ba_status",
        [20] = "ba_event",
        [21] = "kpi_event",
        [27] = "kpi_status",
        [28] = "ba_duration"
    }
}

----------------------------------------------------------------------
-- Helper: safe category/event names
----------------------------------------------------------------------

local function get_category_name(category)
    return category_names[category]
        or ("UNKNOWN_" .. tostring(category))
end

local function get_event_name(category, element)
    if event_names[category] ~= nil
       and event_names[category][element] ~= nil then
        return event_names[category][element]
    end
    return "unknown_" .. tostring(element)
end

----------------------------------------------------------------------
-- Resolve host/service information
----------------------------------------------------------------------

local function resolve_resource(d)
    local result = {
        host_id = d.host_id,
        service_id = d.service_id,
        index_id = d.index_id,
        metric_id = d.metric_id
    }

    ------------------------------------------------------------------
    -- Resolve metric -> index
    ------------------------------------------------------------------

    if result.metric_id ~= nil
       and result.metric_id ~= 0 then
        local metric =
            broker_cache:get_metric_mapping(
                result.metric_id
            )
        if metric ~= nil
           and metric.index_id ~= nil then
            result.index_id =
                metric.index_id
        end
    end

    ------------------------------------------------------------------
    -- Resolve index -> host/service
    ------------------------------------------------------------------

    if result.index_id ~= nil
       and result.index_id ~= 0 then
        local index =
            broker_cache:get_index_mapping(
                result.index_id
            )
        if index ~= nil then
            if result.host_id == nil
               or result.host_id == 0 then
                result.host_id =
                    index.host_id
            end
            if result.service_id == nil
               or result.service_id == 0 then
                result.service_id =
                    index.service_id
            end
        end
    end

    ------------------------------------------------------------------
    -- Hostname
    ------------------------------------------------------------------

    if result.host_id ~= nil
       and result.host_id ~= 0 then
        result.host_name =
            broker_cache:get_hostname(
                result.host_id
            )
    end

    ------------------------------------------------------------------
    -- Service name
    ------------------------------------------------------------------

    if result.host_id ~= nil
       and result.host_id ~= 0
       and result.service_id ~= nil
       and result.service_id ~= 0 then
        result.service_name =
            broker_cache:get_service_description(
                result.host_id,
                result.service_id
            )
    end
    return result
end

----------------------------------------------------------------------
-- State conversion
----------------------------------------------------------------------

local function service_state_name(state)
    local states = {
        [0] = "OK",
        [1] = "WARNING",
        [2] = "CRITICAL",
        [3] = "UNKNOWN",
        [4] = "PENDING"
    }
    return states[state]
end

local function host_state_name(state)
    local states = {
        [0] = "UP",
        [1] = "DOWN",
        [2] = "UNREACHABLE"
    }
    return states[state]
end

local function state_type_name(state_type)
    local types = {
        [0] = "SOFT",
        [1] = "HARD"
    }
    return types[state_type]
end

local function check_type_name(check_type)
    local types = {
        [0] = "ACTIVE",
        [1] = "PASSIVE"
    }
    return types[check_type]
end

----------------------------------------------------------------------
-- Find the most appropriate timestamp
----------------------------------------------------------------------

local function get_timestamp(d)
    --
    -- BBDO event structures don't all use the same field.
    --
    return d.time
        or d.timestamp
        or d.last_check
        or d.last_state_change
        or os.time()
end

----------------------------------------------------------------------
-- Build normalized status object
----------------------------------------------------------------------

local function build_status(d, event_type, resource)
    if d.state == nil then
        return nil
    end
    local result = {
        code = d.state
    }

    ------------------------------------------------------------------
    -- Host state
    ------------------------------------------------------------------

    if event_type == "host_status"
       or event_type == "host_check"
       or event_type == "adaptive_host_status"
       or (resource.service_id == nil
           or resource.service_id == 0) then
        result.name =
            host_state_name(d.state)
    else
        result.name =
            service_state_name(d.state)
    end

    ------------------------------------------------------------------
    -- HARD / SOFT
    ------------------------------------------------------------------

    if d.state_type ~= nil then
        result.state_type =
            state_type_name(
                d.state_type
            )
        result.state_type_code =
            d.state_type
    end

    ------------------------------------------------------------------
    -- ACTIVE / PASSIVE
    ------------------------------------------------------------------

    if d.check_type ~= nil then
        result.check_type =
            check_type_name(
                d.check_type
            )
        result.check_type_code =
            d.check_type
    end

    ------------------------------------------------------------------
    -- Attempt
    ------------------------------------------------------------------

    if d.check_attempt ~= nil then
        result.attempt =
            d.check_attempt
    elseif d.current_attempt ~= nil then
        result.attempt =
            d.current_attempt
    end

    if d.max_check_attempts ~= nil then
        result.max_attempts =
            d.max_check_attempts
    end

    return result
end

----------------------------------------------------------------------
-- Select useful message/output
----------------------------------------------------------------------

local function get_message(d)
    return d.output
        or d.message
        or d.log_message
        or d.description
end

----------------------------------------------------------------------
-- Remove values that cannot be represented in valid JSON
----------------------------------------------------------------------

local function sanitize_json(value)
    local t = type(value)
    if t == "number" then
        -- NaN
        if value ~= value then
            return nil
        end
        -- +Inf / -Inf
        if value == math.huge
           or value == -math.huge then
            return nil
        end
        return value
    end

    if t == "table" then
        local clean = {}
        for k, v in pairs(value) do
            local sanitized =
                sanitize_json(v)
            if sanitized ~= nil then
                clean[k] = sanitized
            end
        end
        return clean
    end

    return value
end

----------------------------------------------------------------------
-- Build normalized event
----------------------------------------------------------------------

local function normalize_event(d)
    local category =
        d.category
    local element =
        d.element
    local category_name =
        get_category_name(category)
    local event_type =
        get_event_name(
            category,
            element
        )
    local resource =
        resolve_resource(d)

    ------------------------------------------------------------------
    -- Top-level fields
    --
    -- Keep only generic fields here that are safe and useful.
    -- Everything Centreon-specific lives under "centreon".
    ------------------------------------------------------------------

    local result = {
        ["@source"] =
            "centreon",
        centreon = {
            -- Convert seconds -> milliseconds
            event_timestamp = 
                get_timestamp(d) * 1000,
            category =
                category_name,
            event_type =
                event_type,
            category_id =
                category,
            element_id =
                element
        }
    }

    ------------------------------------------------------------------
    -- Host
    ------------------------------------------------------------------

    if resource.host_id ~= nil
       and resource.host_id ~= 0 then
        result.centreon.host = {
            id = resource.host_id,
            name = resource.host_name
        }
    end

    ------------------------------------------------------------------
    -- Service
    ------------------------------------------------------------------

    if resource.service_id ~= nil
       and resource.service_id ~= 0 then
        result.centreon.service = {
            id = resource.service_id,
            name = resource.service_name
        }
    end

    ------------------------------------------------------------------
    -- Metric
    ------------------------------------------------------------------

    if resource.metric_id ~= nil
       and resource.metric_id ~= 0 then
        result.centreon.metric = {
            id = resource.metric_id
        }
        if d.name ~= nil then
            result.centreon.metric.name =
                d.name
        end
        if d.value ~= nil then
            result.centreon.metric.value =
                d.value
        end
        if d.unit ~= nil then
            result.centreon.metric.unit =
                d.unit
        end
    end

    ------------------------------------------------------------------
    -- Storage index
    ------------------------------------------------------------------

    if resource.index_id ~= nil
       and resource.index_id ~= 0 then
        result.centreon.storage_index = {
            id = resource.index_id
        }
    end

    ------------------------------------------------------------------
    -- Status
    --
    -- IMPORTANT:
    -- Do NOT use top-level "status".
    -- data.status is already mapped as a keyword in Wazuh/OpenSearch.
    ------------------------------------------------------------------

    local status =
        build_status(
            d,
            event_type,
            resource
        )

    if status ~= nil then
        result.centreon.status =
            status
    end

    ------------------------------------------------------------------
    -- User-readable output
    --
    -- Keep message top-level because a scalar string is convenient
    -- for Wazuh searches and rules.
    ------------------------------------------------------------------

    local message =
        get_message(d)

    if message ~= nil
       and message ~= "" then
        result.centreon.message =
            message
    end

    ------------------------------------------------------------------
    -- Performance data
    --
    -- Scalar string, so safe to keep top-level.
    ------------------------------------------------------------------

    if d.perfdata ~= nil
       and d.perfdata ~= "" then
        result.centreon.performance_data =
            d.perfdata
    end

    ------------------------------------------------------------------
    -- Acknowledgement
    ------------------------------------------------------------------

    if d.acknowledgement_type ~= nil then
        result.centreon.acknowledgement = {
            type =
                d.acknowledgement_type
        }
    end

    ------------------------------------------------------------------
    -- Scheduled downtime
    ------------------------------------------------------------------

    if d.scheduled_downtime_depth ~= nil then
        result.centreon.downtime = {
            depth =
                d.scheduled_downtime_depth
        }
    end

    ------------------------------------------------------------------
    -- Poller / instance
    ------------------------------------------------------------------

    if d.instance_id ~= nil then
        result.centreon.poller = {
            id =
                d.instance_id
        }
    elseif d.poller_id ~= nil then
        result.centreon.poller = {
            id =
                d.poller_id
        }
    end

    return result
end

----------------------------------------------------------------------
-- Init
----------------------------------------------------------------------

function init(conf)
    if conf["output_file"] ~= nil
       and conf["output_file"] ~= "" then
        output_file =
            conf["output_file"]
    end
    broker_log:set_parameters(
        3,
        debug_file
    )
    broker_log:info(
        1,
        "Normalized JSON stream connector initialized"
    )
    broker_log:info(
        1,
        "Writing NDJSON to "
        .. output_file
    )
end

----------------------------------------------------------------------
-- Receive all Broker events
----------------------------------------------------------------------

function filter(category, element)
    return true
end

----------------------------------------------------------------------
-- Process event
----------------------------------------------------------------------

function write(d)
    local normalized =
        normalize_event(d)
    normalized =
        sanitize_json(
            normalized
        )
    local json =
        broker.json_encode(
            normalized
        )
    if json == nil then
        broker_log:error(
            1,
            "Could not serialize event"
        )
        return false
    end

    local file, err =
        io.open(
            output_file,
            "a"
        )

    if file == nil then
        broker_log:error(
            1,
            "Could not open "
            .. output_file
            .. ": "
            .. tostring(err)
        )
        return false
    end

    local success, write_err =
        file:write(
            json .. "\n"
        )

    if success == nil then
        broker_log:error(
            1,
            "Could not write "
            .. output_file
            .. ": "
            .. tostring(write_err)
        )
        file:close()
        return false
    end

    file:flush()
    file:close()
    return true
end

function flush()
    return true
end
