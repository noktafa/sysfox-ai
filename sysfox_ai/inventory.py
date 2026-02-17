"""Dreamer infrastructure inventory — server definitions, components, log paths.

Source: dreamer ansible/inventory/hosts.ini + ansible/roles/*/templates/*.j2
"""

from dataclasses import dataclass, field

from sysfox_ai.config import settings


@dataclass
class DreamerServer:
    hostname: str
    public_ip: str
    private_ip: str
    role: str
    components: list[str] = field(default_factory=list)
    log_paths: list[str] = field(default_factory=list)
    systemd_services: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)


# All 7 dreamer servers
SERVERS: dict[str, DreamerServer] = {
    "poc-lb": DreamerServer(
        hostname="poc-lb",
        public_ip=settings.POC_LB_HOST,
        private_ip="10.10.0.3",
        role="load_balancer",
        components=["nginx_lb"],
        log_paths=[
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
        ],
        systemd_services=["nginx", "filebeat"],
        ports=[80, 443],
    ),
    "poc-app1": DreamerServer(
        hostname="poc-app1",
        public_ip=settings.POC_APP1_HOST,
        private_ip="10.10.0.7",
        role="app_server",
        components=["nginx_app", "app"],
        log_paths=[
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
            "/opt/dreamer/app/logs/app.log",
        ],
        systemd_services=["nginx", "dreamer-app", "filebeat"],
        ports=[80, 8000],
    ),
    "poc-app2": DreamerServer(
        hostname="poc-app2",
        public_ip=settings.POC_APP2_HOST,
        private_ip="10.10.0.8",
        role="app_server",
        components=["nginx_app", "app"],
        log_paths=[
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
            "/opt/dreamer/app/logs/app.log",
        ],
        systemd_services=["nginx", "dreamer-app", "filebeat"],
        ports=[80, 8000],
    ),
    "poc-rabbitmq": DreamerServer(
        hostname="poc-rabbitmq",
        public_ip=settings.POC_RABBITMQ_HOST,
        private_ip="10.10.0.2",
        role="message_broker",
        components=["rabbitmq"],
        log_paths=[
            "/var/log/rabbitmq/rabbit@poc-rabbitmq.log",
        ],
        systemd_services=["rabbitmq-server", "filebeat"],
        ports=[5672, 15672],
    ),
    "poc-consumer": DreamerServer(
        hostname="poc-consumer",
        public_ip=settings.POC_CONSUMER_HOST,
        private_ip="10.10.0.6",
        role="queue_consumer",
        components=["queue_consumer"],
        log_paths=[
            "/opt/dreamer/consumer/logs/consumer.log",
        ],
        systemd_services=["dreamer-consumer", "filebeat"],
        ports=[],
    ),
    "poc-postgresql": DreamerServer(
        hostname="poc-postgresql",
        public_ip=settings.POC_POSTGRESQL_HOST,
        private_ip="10.10.0.4",
        role="database",
        components=["postgresql"],
        log_paths=[
            "/var/log/postgresql/postgresql-15-main.log",
        ],
        systemd_services=["postgresql", "filebeat"],
        ports=[5432],
    ),
    "poc-elk": DreamerServer(
        hostname="poc-elk",
        public_ip=settings.POC_ELK_HOST,
        private_ip="10.10.0.5",
        role="logging",
        components=["elasticsearch", "logstash", "kibana"],
        log_paths=[
            "/var/log/elasticsearch/elasticsearch.log",
            "/var/log/logstash/logstash-plain.log",
        ],
        systemd_services=["elasticsearch", "logstash", "kibana", "filebeat"],
        ports=[9200, 5601, 5044],
    ),
}

# Valid server hostnames (for tool parameter enum)
SERVER_HOSTNAMES = list(SERVERS.keys())

# Component → server mapping
COMPONENT_TO_SERVERS: dict[str, list[str]] = {}
for _hostname, _server in SERVERS.items():
    for _component in _server.components:
        COMPONENT_TO_SERVERS.setdefault(_component, []).append(_hostname)

# Service → server mapping
SERVICE_TO_SERVERS: dict[str, list[str]] = {}
for _hostname, _server in SERVERS.items():
    for _service in _server.systemd_services:
        SERVICE_TO_SERVERS.setdefault(_service, []).append(_hostname)


def get_server_ips() -> dict[str, str]:
    """Return {hostname: public_ip} for SSH connection pool."""
    return {h: s.public_ip for h, s in SERVERS.items()}
