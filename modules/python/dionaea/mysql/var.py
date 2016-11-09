import random
from collections import OrderedDict
from datetime import datetime

CFG_VARS = [
    {
        "name": "authentication_windows_log_level",
        "type": "integer",
        "type_options": {
            "value_default": 0,
            "value_max": 4,
            "value_min": 0
        }
    },
    {
        "name": "authentication_windows_use_principal_name",
        "type": "boolean",
        "type_options": {
            "value_default": True
        }
    },
    {
        "name": "auto_generate_certs",
        "type": "boolean",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": True
        }
    },
    {
        "name": "autocommit",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": True
        }
    },
    {
        "name": "automatic_sp_privileges",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "avoid_temporal_upgrade",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "back_log",
        "type": "integer",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_max": 65535,
            "value_min": 1
        }
    },
    {
        "name": "basedir",
        "type": "directory_name",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "big_tables",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": False
        }
    },
    {
        "name": "bind_address",
        "type": "string",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": "*"
        }
    },
    {
        "name": "block_encryption_mode",
        "type": "string",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": "aes-128-ecb"
        }
    },
    {
        "name": "bulk_insert_buffer_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 8388608,
            "value_max": 18446744073709551615,
            "value_min": 0
        }
    },
    {
        "name": "character_set_client",
        "type": "string",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ]
        }
    },
    {
        "name": "character_set_connection",
        "type": "string",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ]
        }
    },
    {
        "name": "character_set_database",
        "type": "string",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ]
        }
    },
    {
        "name": "character_set_filesystem",
        "type": "string",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": "binary"
        }
    },
    {
        "name": "character_set_results",
        "type": "string",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ]
        }
    },
    {
        "name": "character_set_server",
        "type": "string",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": "latin1"
        }
    },
    {
        "name": "character_set_system",
        "type": "string",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": "utf8"
        }
    },
    {
        "name": "character_sets_dir",
        "type": "directory_name",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "check_proxy_users",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "collation_connection",
        "type": "string",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ]
        }
    },
    {
        "name": "collation_database",
        "type": "string",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ]
        }
    },
    {
        "name": "collation_server",
        "type": "string",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": "latin1_swedish_ci"
        }
    },
    {
        "name": "completion_type",
        "type": "enumeration",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "valid_values": [
                "NO_CHAIN"
            ],
            "value_default": "NO_CHAIN"
        }
    },
    {
        "name": "concurrent_insert",
        "type": "enumeration",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "valid_values": [
                "NEVER"
            ],
            "value_default": "AUTO"
        }
    },
    {
        "name": "connect_timeout",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 10,
            "value_max": 31536000,
            "value_min": 2
        }
    },
    {
        "name": "core_file",
        "type": "boolean",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "datadir",
        "type": "directory_name",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "debug",
        "type": "string",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": "d:t:i:O,\\mysqld.trace"
        }
    },
    {
        "name": "debug_sync",
        "type": "string",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "session"
            ]
        }
    },
    {
        "name": "default_authentication_plugin",
        "type": "enumeration",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "valid_values": [
                "mysql_native_password"
            ],
            "value_default": "mysql_native_password"
        }
    },
    {
        "name": "default_password_lifetime",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 0,
            "value_max": 65535,
            "value_min": 0
        }
    },
    {
        "name": "default_storage_engine",
        "type": "enumeration",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": "InnoDB"
        }
    },
    {
        "name": "default_tmp_storage_engine",
        "type": "enumeration",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": "InnoDB"
        }
    },
    {
        "name": "default_week_format",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 0,
            "value_max": 7,
            "value_min": 0
        }
    },
    {
        "name": "delay_key_write",
        "type": "enumeration",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "valid_values": [
                "ON"
            ],
            "value_default": "ON"
        }
    },
    {
        "name": "delayed_insert_limit",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 100,
            "value_max": 18446744073709551615,
            "value_min": 1
        }
    },
    {
        "name": "delayed_insert_timeout",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 300
        }
    },
    {
        "name": "delayed_queue_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 1000,
            "value_max": 18446744073709551615,
            "value_min": 1
        }
    },
    {
        "name": "disabled_storage_engines",
        "type": "string",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": "empty string"
        }
    },
    {
        "name": "disconnect_on_expired_password",
        "type": "boolean",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "session"
            ],
            "value_default": True
        }
    },
    {
        "name": "div_precision_increment",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 4,
            "value_max": 30,
            "value_min": 0
        }
    },
    {
        "name": "end_markers_in_json",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": False
        }
    },
    {
        "name": "eq_range_index_dive_limit",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 200,
            "value_max": 4294967295,
            "value_min": 0
        }
    },
    {
        "name": "event_scheduler",
        "type": "enumeration",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "valid_values": [
                "ON"
            ],
            "value_default": "OFF"
        }
    },
    {
        "name": "expire_logs_days",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 0,
            "value_max": 99,
            "value_min": 0
        }
    },
    {
        "name": "explicit_defaults_for_timestamp",
        "type": "boolean",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": False
        }
    },
    {
        "name": "external_user",
        "type": "string",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "session"
            ]
        }
    },
    {
        "name": "flush",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "flush_time",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 0,
            "value_min": 0
        }
    },
    {
        "name": "ft_boolean_syntax",
        "type": "string",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": "+ -><()~*:\"\"&|"
        }
    },
    {
        "name": "ft_max_word_len",
        "type": "integer",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_min": 10
        }
    },
    {
        "name": "ft_min_word_len",
        "type": "integer",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": 4,
            "value_min": 1
        }
    },
    {
        "name": "ft_query_expansion_limit",
        "type": "integer",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": 20,
            "value_max": 1000,
            "value_min": 0
        }
    },
    {
        "name": "ft_stopword_file",
        "type": "file_name",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "general_log",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "general_log_file",
        "type": "file_name",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": "host_name.log"
        }
    },
    {
        "name": "group_concat_max_len",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 1024,
            "value_max": 18446744073709551615,
            "value_min": 4
        }
    },
    {
        "name": "have_statement_timeout",
        "type": "boolean",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "host_cache_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_max": 65536,
            "value_min": 0
        }
    },
    {
        "name": "hostname",
        "type": "string",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "ignore_db_dirs",
        "type": "string",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "init_connect",
        "type": "string",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "init_file",
        "type": "file_name",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "interactive_timeout",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 28800,
            "value_min": 1
        }
    },
    {
        "name": "internal_tmp_disk_storage_engine",
        "type": "enumeration",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "valid_values": [
                "MYISAM"
            ],
            "value_default": "INNODB"
        }
    },
    {
        "name": "join_buffer_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 262144,
            "value_max": 18446744073709547520,
            "value_min": 128
        }
    },
    {
        "name": "keep_files_on_create",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": False
        }
    },
    {
        "name": "key_buffer_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 8388608,
            "value_min": 8
        }
    },
    {
        "name": "key_cache_age_threshold",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 300,
            "value_max": 18446744073709551615,
            "value_min": 100
        }
    },
    {
        "name": "key_cache_block_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 1024,
            "value_max": 16384,
            "value_min": 512
        }
    },
    {
        "name": "key_cache_division_limit",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 100,
            "value_max": 100,
            "value_min": 1
        }
    },
    {
        "name": "keyring_file_data",
        "type": "file_name",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": "platform specific"
        }
    },
    {
        "name": "keyring_okv_conf_dir",
        "type": "directory_name",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": "empty string"
        }
    },
    {
        "name": "large_page_size",
        "type": "integer",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": 0
        }
    },
    {
        "name": "large_pages",
        "type": "boolean",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "lc_messages",
        "type": "string",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": "en_US"
        }
    },
    {
        "name": "lc_messages_dir",
        "type": "directory_name",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "lc_time_names",
        "type": "string",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ]
        }
    },
    {
        "name": "license",
        "type": "string",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": "GPL"
        }
    },
    {
        "name": "local_infile",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "lock_wait_timeout",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 31536000,
            "value_max": 31536000,
            "value_min": 1
        }
    },
    {
        "name": "log_backward_compatible_user_definitions",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "log_bin_trust_function_creators",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "log_builtin_as_identified_by_password",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "log_error",
        "type": "file_name",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "log_error_verbosity",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 3,
            "value_max": 3,
            "value_min": 1
        }
    },
    {
        "name": "log_output",
        "type": "set",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "valid_values": [
                "TABLE"
            ],
            "value_default": "FILE"
        }
    },
    {
        "name": "log_queries_not_using_indexes",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "log_slow_admin_statements",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "log_syslog",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": True
        }
    },
    {
        "name": "log_syslog_facility",
        "type": "string",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": "daemon"
        }
    },
    {
        "name": "log_syslog_include_pid",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": True
        }
    },
    {
        "name": "log_syslog_tag",
        "type": "string",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": "empty string"
        }
    },
    {
        "name": "log_throttle_queries_not_using_indexes",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 0
        }
    },
    {
        "name": "log_timestamps",
        "type": "enumeration",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "valid_values": [
                "UTC"
            ],
            "value_default": "UTC"
        }
    },
    {
        "name": "log_warnings",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 2,
            "value_max": 18446744073709551615,
            "value_min": 0
        }
    },
    {
        "name": "long_query_time",
        "type": "numeric",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 10,
            "value_min": 0
        }
    },
    {
        "name": "low_priority_updates",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": False
        }
    },
    {
        "name": "lower_case_file_system",
        "type": "boolean",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "lower_case_table_names",
        "type": "integer",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": 0,
            "value_max": 2,
            "value_min": 0
        }
    },
    {
        "name": "max_allowed_packet",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 4194304,
            "value_max": 1073741824,
            "value_min": 1024
        }
    },
    {
        "name": "max_connect_errors",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 100,
            "value_max": 18446744073709551615,
            "value_min": 1
        }
    },
    {
        "name": "max_connections",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 151,
            "value_max": 100000,
            "value_min": 1
        }
    },
    {
        "name": "max_delayed_threads",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 20,
            "value_max": 16384,
            "value_min": 0
        }
    },
    {
        "name": "max_digest_length",
        "type": "integer",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": 1024,
            "value_max": 1048576,
            "value_min": 0
        }
    },
    {
        "name": "max_error_count",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 64,
            "value_max": 65535,
            "value_min": 0
        }
    },
    {
        "name": "max_execution_time",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 0
        }
    },
    {
        "name": "max_heap_table_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 16777216,
            "value_max": 1844674407370954752,
            "value_min": 16384
        }
    },
    {
        "name": "max_insert_delayed_threads",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ]
        }
    },
    {
        "name": "max_join_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 18446744073709551615,
            "value_max": 18446744073709551615,
            "value_min": 1
        }
    },
    {
        "name": "max_length_for_sort_data",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 1024,
            "value_max": 8388608,
            "value_min": 4
        }
    },
    {
        "name": "max_points_in_geometry",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 65536,
            "value_max": 1048576,
            "value_min": 3
        }
    },
    {
        "name": "max_prepared_stmt_count",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 16382,
            "value_max": 1048576,
            "value_min": 0
        }
    },
    {
        "name": "max_relay_log_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 0,
            "value_max": 1073741824,
            "value_min": 0
        }
    },
    {
        "name": "max_seeks_for_key",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 18446744073709551615,
            "value_max": 18446744073709551615,
            "value_min": 1
        }
    },
    {
        "name": "max_sort_length",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 1024,
            "value_max": 8388608,
            "value_min": 4
        }
    },
    {
        "name": "max_sp_recursion_depth",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 0,
            "value_max": 255
        }
    },
    {
        "name": "max_statement_time",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 0
        }
    },
    {
        "name": "max_user_connections",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 0,
            "value_max": 4294967295,
            "value_min": 0
        }
    },
    {
        "name": "max_write_lock_count",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 18446744073709551615,
            "value_max": 18446744073709551615,
            "value_min": 1
        }
    },
    {
        "name": "mecab_rc_file",
        "type": "directory_name",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "metadata_locks_cache_size",
        "type": "integer",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": 1024,
            "value_max": 1048576,
            "value_min": 1
        }
    },
    {
        "name": "metadata_locks_hash_instances",
        "type": "integer",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": 8,
            "value_max": 1024,
            "value_min": 1
        }
    },
    {
        "name": "min_examined_row_limit",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 0,
            "value_max": 18446744073709551615,
            "value_min": 0
        }
    },
    {
        "name": "multi_range_count",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 256,
            "value_max": 4294967295,
            "value_min": 1
        }
    },
    {
        "name": "myisam_data_pointer_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 6,
            "value_max": 7,
            "value_min": 2
        }
    },
    {
        "name": "myisam_max_sort_file_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 9223372036854775807
        }
    },
    {
        "name": "myisam_mmap_size",
        "type": "integer",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": 18446744073709551615,
            "value_max": 18446744073709551615,
            "value_min": 7
        }
    },
    {
        "name": "myisam_repair_threads",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 1,
            "value_max": 18446744073709551615,
            "value_min": 1
        }
    },
    {
        "name": "myisam_sort_buffer_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 8388608,
            "value_max": 18446744073709551615,
            "value_min": 4096
        }
    },
    {
        "name": "myisam_stats_method",
        "type": "enumeration",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "valid_values": [
                "nulls_equal"
            ],
            "value_default": "nulls_unequal"
        }
    },
    {
        "name": "myisam_use_mmap",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "mysql_native_password_proxy_users",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "named_pipe",
        "type": "boolean",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "net_buffer_length",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 16384,
            "value_max": 1048576,
            "value_min": 1024
        }
    },
    {
        "name": "net_read_timeout",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 30,
            "value_min": 1
        }
    },
    {
        "name": "net_retry_count",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 10,
            "value_max": 18446744073709551615,
            "value_min": 1
        }
    },
    {
        "name": "net_write_timeout",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 60,
            "value_min": 1
        }
    },
    {
        "name": "new",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": False
        }
    },
    {
        "name": "ngram_token_size",
        "type": "integer",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": 2,
            "value_max": 10,
            "value_min": 1
        }
    },
    {
        "name": "offline_mode",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "old_alter_table",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": False
        }
    },
    {
        "name": "old_passwords",
        "type": "enumeration",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "valid_values": [
                "0"
            ],
            "value_default": "0"
        }
    },
    {
        "name": "open_files_limit",
        "type": "integer",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_min": 0
        }
    },
    {
        "name": "optimizer_prune_level",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": False
        }
    },
    {
        "name": "optimizer_search_depth",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 62,
            "value_max": 62,
            "value_min": 0
        }
    },
    {
        "name": "optimizer_switch",
        "type": "set",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "valid_values": [
                "batched_key_access={on|off}"
            ]
        }
    },
    {
        "name": "optimizer_trace",
        "type": "string",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ]
        }
    },
    {
        "name": "optimizer_trace_features",
        "type": "string",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ]
        }
    },
    {
        "name": "optimizer_trace_limit",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 1
        }
    },
    {
        "name": "optimizer_trace_max_mem_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 16384
        }
    },
    {
        "name": "optimizer_trace_offset",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": -1
        }
    },
    {
        "name": "parser_max_mem_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 18446744073709551615,
            "value_max": 18446744073709551615,
            "value_min": 400000
        }
    },
    {
        "name": "pid_file",
        "type": "file_name",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "plugin_dir",
        "type": "directory_name",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": "BASEDIR/lib/plugin"
        }
    },
    {
        "name": "port",
        "type": "integer",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": 3306,
            "value_max": 65535,
            "value_min": 0
        }
    },
    {
        "name": "preload_buffer_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 32768,
            "value_max": 1073741824,
            "value_min": 1024
        }
    },
    {
        "name": "protocol_version",
        "type": "integer",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "proxy_user",
        "type": "string",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "session"
            ]
        }
    },
    {
        "name": "pseudo_slave_mode",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "session"
            ]
        }
    },
    {
        "name": "pseudo_thread_id",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "session"
            ]
        }
    },
    {
        "name": "query_alloc_block_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 8192,
            "value_max": 18446744073709551615,
            "value_min": 1024
        }
    },
    {
        "name": "query_cache_limit",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 1048576,
            "value_max": 18446744073709551615,
            "value_min": 0
        }
    },
    {
        "name": "query_cache_min_res_unit",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 4096,
            "value_max": 18446744073709551615,
            "value_min": 512
        }
    },
    {
        "name": "query_cache_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 1048576,
            "value_max": 18446744073709551615,
            "value_min": 0
        }
    },
    {
        "name": "query_cache_type",
        "type": "enumeration",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "valid_values": [
                "0"
            ],
            "value_default": "0"
        }
    },
    {
        "name": "query_cache_wlock_invalidate",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": False
        }
    },
    {
        "name": "query_prealloc_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 8192,
            "value_max": 18446744073709551615,
            "value_min": 8192
        }
    },
    {
        "name": "range_alloc_block_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 4096,
            "value_max": 18446744073709547520,
            "value_min": 4096
        }
    },
    {
        "name": "range_optimizer_max_mem_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 8388608
        }
    },
    {
        "name": "rbr_exec_mode",
        "type": "enumeration",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "session"
            ],
            "valid_values": [
                "IDEMPOTENT"
            ],
            "value_default": "STRICT"
        }
    },
    {
        "name": "read_buffer_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 131072,
            "value_max": 2147479552,
            "value_min": 8200
        }
    },
    {
        "name": "read_only",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "read_rnd_buffer_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 262144,
            "value_max": 2147483647,
            "value_min": 1
        }
    },
    {
        "name": "relay_log_purge",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "relay_log_space_limit",
        "type": "integer",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": 0,
            "value_max": 18446744073709551615,
            "value_min": 0
        }
    },
    {
        "name": "report_host",
        "type": "string",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "report_password",
        "type": "string",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "report_port",
        "type": "integer",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_max": 65535,
            "value_min": 0
        }
    },
    {
        "name": "report_user",
        "type": "string",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "require_secure_transport",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "rpl_semi_sync_master_enabled",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "rpl_semi_sync_master_timeout",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 10000
        }
    },
    {
        "name": "rpl_semi_sync_master_trace_level",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 32
        }
    },
    {
        "name": "rpl_semi_sync_master_wait_for_slave_count",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 1,
            "value_max": 65535,
            "value_min": 1
        }
    },
    {
        "name": "rpl_semi_sync_master_wait_no_slave",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": True
        }
    },
    {
        "name": "rpl_semi_sync_master_wait_point",
        "type": "enumeration",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "valid_values": [
                "AFTER_SYNC"
            ],
            "value_default": "AFTER_SYNC"
        }
    },
    {
        "name": "rpl_semi_sync_slave_enabled",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "rpl_semi_sync_slave_trace_level",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 32
        }
    },
    {
        "name": "secure_auth",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": True
        }
    },
    {
        "name": "secure_file_priv",
        "type": "string",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": "platform specific"
        }
    },
    {
        "name": "server_id",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 0,
            "value_max": 4294967295,
            "value_min": 0
        }
    },
    {
        "name": "session_track_gtids",
        "type": "enumeration",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "valid_values": [
                "OFF"
            ],
            "value_default": "OFF"
        }
    },
    {
        "name": "session_track_schema",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": True
        }
    },
    {
        "name": "session_track_state_change",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": False
        }
    },
    {
        "name": "session_track_system_variables",
        "type": "string",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": "time_zone, autocommit, character_set_client, character_set_results, character_set_connection"
        }
    },
    {
        "name": "sha256_password_auto_generate_rsa_keys",
        "type": "boolean",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": True
        }
    },
    {
        "name": "sha256_password_private_key_path",
        "type": "file_name",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": "private_key.pem"
        }
    },
    {
        "name": "sha256_password_proxy_users",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "sha256_password_public_key_path",
        "type": "file_name",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": "public_key.pem"
        }
    },
    {
        "name": "shared_memory",
        "type": "boolean",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "shared_memory_base_name",
        "type": "string",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": "MYSQL"
        }
    },
    {
        "name": "show_compatibility_56",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "show_old_temporals",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": False
        }
    },
    {
        "name": "skip_external_locking",
        "type": "boolean",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": True
        }
    },
    {
        "name": "skip_name_resolve",
        "type": "boolean",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "slow_launch_time",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 2
        }
    },
    {
        "name": "slow_query_log",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "slow_query_log_file",
        "type": "file_name",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": "host_name-slow.log"
        }
    },
    {
        "name": "socket",
        "type": "string",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": "/tmp/mysql.sock"
        }
    },
    {
        "name": "sort_buffer_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 262144,
            "value_max": 18446744073709551615,
            "value_min": 32768
        }
    },
    {
        "name": "sql_auto_is_null",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": False
        }
    },
    {
        "name": "sql_big_selects",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": False
        }
    },
    {
        "name": "sql_buffer_result",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": False
        }
    },
    {
        "name": "sql_log_bin",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "session"
            ]
        }
    },
    {
        "name": "sql_log_off",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": False
        }
    },
    {
        "name": "sql_mode",
        "type": "set",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "valid_values": [
                "ALLOW_INVALID_DATES"
            ],
            "value_default": "ONLY_FULL_GROUP_BY STRICT_TRANS_TABLES NO_ZERO_IN_DATE NO_ZERO_DATE ERROR_FOR_DIVISION_BY_ZERO NO_AUTO_CREATE_USER NO_ENGINE_SUBSTITUTION"
        }
    },
    {
        "name": "sql_select_limit",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ]
        }
    },
    {
        "name": "ssl_ca",
        "type": "file_name",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "ssl_capath",
        "type": "directory_name",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "ssl_cert",
        "type": "file_name",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "ssl_cipher",
        "type": "string",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "ssl_crl",
        "type": "file_name",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "ssl_crlpath",
        "type": "directory_name",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "ssl_key",
        "type": "file_name",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "storage_engine",
        "type": "enumeration",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": "InnoDB"
        }
    },
    {
        "name": "stored_program_cache",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 256,
            "value_max": 524288,
            "value_min": 16
        }
    },
    {
        "name": "super_read_only",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "sync_frm",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "system_time_zone",
        "type": "string",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "table_definition_cache",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_max": 524288,
            "value_min": 400
        }
    },
    {
        "name": "table_open_cache",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 2000,
            "value_max": 524288,
            "value_min": 1
        }
    },
    {
        "name": "table_open_cache_instances",
        "type": "integer",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": 16,
            "value_max": 64,
            "value_min": 1
        }
    },
    {
        "name": "thread_cache_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_max": 16384,
            "value_min": 0
        }
    },
    {
        "name": "thread_concurrency",
        "type": "integer",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": 10,
            "value_max": 512,
            "value_min": 1
        }
    },
    {
        "name": "thread_handling",
        "type": "enumeration",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "valid_values": [
                "no-threads"
            ],
            "value_default": "one-thread-per-connection"
        }
    },
    {
        "name": "thread_pool_algorithm",
        "type": "integer",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": 0,
            "value_max": 1,
            "value_min": 0
        }
    },
    {
        "name": "thread_pool_high_priority_connection",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 0,
            "value_max": 1,
            "value_min": 0
        }
    },
    {
        "name": "thread_pool_max_unused_threads",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 0,
            "value_max": 4096,
            "value_min": 0
        }
    },
    {
        "name": "thread_pool_prio_kickup_timer",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 1000,
            "value_max": 4294967294,
            "value_min": 0
        }
    },
    {
        "name": "thread_pool_size",
        "type": "integer",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": 16,
            "value_max": 64,
            "value_min": 1
        }
    },
    {
        "name": "thread_pool_stall_limit",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": 6,
            "value_max": 600,
            "value_min": 4
        }
    },
    {
        "name": "thread_stack",
        "type": "integer",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": 262144,
            "value_max": 18446744073709551615,
            "value_min": 131072
        }
    },
    {
        "name": "time_zone",
        "type": "string",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ]
        }
    },
    {
        "name": "timed_mutexes",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global"
            ],
            "value_default": False
        }
    },
    {
        "name": "timestamp",
        "type": "numeric",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "session"
            ]
        }
    },
    {
        "name": "tls_version",
        "type": "string",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": "TLSv1,TLSv1.1"
        }
    },
    {
        "name": "tmp_table_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 16777216,
            "value_max": 18446744073709551615,
            "value_min": 1024
        }
    },
    {
        "name": "tmpdir",
        "type": "directory_name",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ]
        }
    },
    {
        "name": "transaction_alloc_block_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 8192,
            "value_max": 18446744073709551615,
            "value_min": 1024
        }
    },
    {
        "name": "transaction_prealloc_size",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 4096,
            "value_max": 18446744073709551615,
            "value_min": 1024
        }
    },
    {
        "name": "transaction_write_set_extraction",
        "type": "enumeration",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "valid_values": [
                "OFF"
            ],
            "value_default": "OFF"
        }
    },
    {
        "name": "tx_isolation",
        "type": "enumeration",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "valid_values": [
                "READ-UNCOMMITTED"
            ],
            "value_default": "REPEATABLE-READ"
        }
    },
    {
        "name": "tx_read_only",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": False
        }
    },
    {
        "name": "unique_checks",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": False
        }
    },
    {
        "name": "updatable_views_with_limit",
        "type": "boolean",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": False
        }
    },
    {
        "name": "validate_user_plugins",
        "type": "boolean",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": True
        }
    },
    {
        "name": "version",
        "type": "string",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": "5.7.16"
        }
    },
    {
        "name": "version_comment",
        "type": "string",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": "MySQL Community Server (GPL)"
        }
    },
    {
        "name": "version_compile_machine",
        "type": "string",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": "x86_64"
        }
    },
    {
        "name": "version_compile_os",
        "type": "string",
        "type_options": {
            "dynamic": False,
            "scopes": [
                "global"
            ],
            "value_default": "Linux"
        }
    },
    {
        "name": "wait_timeout",
        "type": "integer",
        "type_options": {
            "dynamic": True,
            "scopes": [
                "global",
                "session"
            ],
            "value_default": 28800,
            "value_max": 31536000,
            "value_min": 1
        }
    }
]


class VarHandler(object):
    def __init__(self):
        self._class_map = {
            "boolean": Bool,
            "integer": Integer,
            "string": String
        }
        self.values = OrderedDict()

    def _get_var_class(self, name):
        cls = self._class_map.get(name)
        if cls is None:
            pass
            #raise ValueError("Unable to find class to handle %s type" % name)

        return cls

    def load(self, vars):
        for var in vars:
            var_cls = self._get_var_class(var.get("type"))
            if var_cls is None:
                continue
            type_options = var.get("type_options")

            self.values[var.get("name")] = var_cls(**type_options)


class BaseVar(object):
    def __init__(self, dynamic=None, scopes=None):
        self.dynamic = dynamic
        self.scopes = scopes
        if self.scopes is None:
            self.scopes = []


class Bool(BaseVar):
    def __init__(self, dynamic=None, scopes=None, value=None, value_default=False):
        BaseVar.__init__(self, dynamic=dynamic, scopes=scopes)
        self.value = value
        self.value_default = value_default
        if self.value is None:
            self.value = self.value_default

    def __str__(self):
        if self.value:
            return "ON"
        return "OFF"


class Integer(BaseVar):
    def __init__(self, dynamic=None, scopes=None, value=None, value_default=0, value_max=None, value_min=None):
        BaseVar.__init__(self, dynamic=dynamic, scopes=scopes)
        self.value_default = value_default

        self.value_min = value_min
        self.value_max = value_max

        if value is None:
            self.value = self.value_default
        else:
            self.value = value

    def __str__(self):
        return str(self.value)

    def _value_get(self):
        return self._value

    def _value_set(self, value):
        self._value = value

    value = property(_value_get, _value_set)


class String(BaseVar):
    def __init__(self, dynamic=None, scopes=None, value=None, value_default=None):
        BaseVar.__init__(self, dynamic=dynamic, scopes=scopes)
        self.value = value
        self.value_default = value_default
        if self.value is None:
            self.value = self.value_default

    def __str__(self):
        if self.value is None:
            return ""
        return self.value
