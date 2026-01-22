"""
Copyright (c) 2025, Oracle and/or its affiliates.
Licensed under the Universal Permissive License v1.0 as shown at
https://oss.oracle.com/licenses/upl.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

import oci
from pydantic import BaseModel, Field

# Helper function


def _oci_to_dict(obj):
    """Best-effort conversion of OCI SDK model objects to plain dicts."""
    if obj is None:
        return None
    try:
        from oci.util import to_dict as oci_to_dict

        return oci_to_dict(obj)
    except Exception:
        pass
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "__dict__"):
        return {k: v for k, v in obj.__dict__.items() if not k.startswith("_")}
    return None


# Sub-objects for LoadBalancer


class ReservedIP(BaseModel):
    id: Optional[str] = Field(
        None,
        description="The OCID of the reserved IP (public IP) to associate with the Load Balancer.",
    )


class IpAddress(BaseModel):
    ip_address: Optional[str] = Field(None, description="The IP address.")
    is_public: Optional[bool] = Field(
        None, description="Whether the IP address is public (True) or private (False)."
    )
    reserved_ip: Optional[ReservedIP] = Field(
        None, description="Details of a Reserved IP bound to the load balancer."
    )


class HealthChecker(BaseModel):
    protocol: Optional[Literal["HTTP", "TCP"]] = Field(
        None, description="The protocol the health check must use."
    )
    url_path: Optional[str] = Field(
        None, description="The path against which to run the health check (HTTP only)."
    )
    port: Optional[int] = Field(
        None,
        description="The backend server port against which to run the health check. If not set, the backend's port is used.",
    )
    return_code: Optional[int] = Field(
        None, description="The status code a healthy backend server should return."
    )
    retries: Optional[int] = Field(
        None,
        description="Number of retries before considering a backend unhealthy; also applies when recovering.",
    )
    timeout_in_millis: Optional[int] = Field(
        None, description="Maximum time, in ms, to wait for a reply to a health check."
    )
    interval_in_millis: Optional[int] = Field(
        None, description="Interval between health checks, in ms."
    )
    response_body_regex: Optional[str] = Field(
        None,
        description="Regex for parsing/validating the response body from the backend (HTTP only).",
    )
    is_force_plain_text: Optional[bool] = Field(
        None,
        description="If true, health checks are done in plain text even if backend set is using SSL.",
    )


class Backend(BaseModel):
    name: Optional[str] = Field(
        None, description="Read-only identifier of this backend in form ip:port."
    )
    ip_address: Optional[str] = Field(
        None, description="The IP address of the backend server."
    )
    port: Optional[int] = Field(
        None, description="The communication port for the backend server."
    )
    weight: Optional[int] = Field(
        None,
        description="Policy weight; higher values receive larger proportion of traffic.",
    )
    max_connections: Optional[int] = Field(
        None,
        description="Max simultaneous connections the load balancer can make to this backend.",
    )
    drain: Optional[bool] = Field(
        None,
        description="Whether the load balancer should drain this server (no new connections).",
    )
    backup: Optional[bool] = Field(
        None,
        description="Whether this server should be treated as backup and only used when primaries fail.",
    )
    offline: Optional[bool] = Field(
        None,
        description="Whether this server is treated as offline (receives no traffic).",
    )


class SessionPersistenceConfigurationDetails(BaseModel):
    cookie_name: Optional[str] = Field(
        None,
        description="Cookie name used to detect a session initiated by the backend server. '*' means any cookie.",
    )
    disable_fallback: Optional[bool] = Field(
        None,
        description="Prevent directing a persistent session client to a different backend when the original is unavailable.",
    )


class LBCookieSessionPersistenceConfigurationDetails(BaseModel):
    cookie_name: Optional[str] = Field(
        None,
        description="Name of the cookie inserted by the load balancer (defaults to X-Oracle-BMC-LBS-Route).",
    )
    disable_fallback: Optional[bool] = Field(
        None, description="Disable persistence fallback."
    )
    domain: Optional[str] = Field(None, description="Cookie domain.")
    path: Optional[str] = Field(None, description="Cookie path.")
    max_age_in_seconds: Optional[int] = Field(
        None, description="Cookie max-age attribute in seconds."
    )
    is_secure: Optional[bool] = Field(
        None, description="Whether the cookie should have the Secure attribute."
    )
    is_http_only: Optional[bool] = Field(
        None, description="Whether the cookie should have the HttpOnly attribute."
    )


class SSLConfiguration(BaseModel):
    protocols: Optional[List[str]] = Field(
        None,
        description="List of supported SSL/TLS protocols for HTTPS/SSL connections.",
    )
    cipher_suite_name: Optional[str] = Field(
        None, description="Name of the cipher suite to use for HTTPS/SSL connections."
    )
    server_order_preference: Optional[Literal["ENABLED", "DISABLED"]] = Field(
        None, description="Preference for server ciphers over client ciphers."
    )
    certificate_name: Optional[str] = Field(
        None, description="Friendly name of the certificate bundle to use."
    )
    certificate_ids: Optional[List[str]] = Field(
        None, description="OCI Certificates service certificate OCIDs."
    )
    trusted_certificate_authority_ids: Optional[List[str]] = Field(
        None,
        description="OCI Certificates service CA/Bundle OCIDs that the load balancer should trust.",
    )
    has_session_resumption: Optional[bool] = Field(
        None,
        description="Whether to resume encrypted sessions using cached parameters.",
    )
    verify_peer_certificate: Optional[bool] = Field(
        None, description="Whether peer certificates should be verified."
    )
    verify_depth: Optional[int] = Field(
        None, description="Maximum depth for peer certificate chain verification."
    )


class ConnectionConfiguration(BaseModel):
    idle_timeout: Optional[int] = Field(
        None,
        description="Maximum idle time (in seconds) between successive operations.",
    )
    backend_tcp_proxy_protocol_version: Optional[int] = Field(
        None, description="Backend TCP Proxy Protocol version (1 or 2)."
    )
    backend_tcp_proxy_protocol_options: Optional[List[str]] = Field(
        None,
        description="TCP PPv2 options enabled on TCP listeners (e.g., PP2_TYPE_AUTHORITY).",
    )


class BackendSet(BaseModel):
    name: Optional[str] = Field(None, description="Backend set friendly name.")
    policy: Optional[str] = Field(
        None,
        description="Load balancer policy for the backend set (e.g., LEAST_CONNECTIONS).",
    )
    backends: Optional[List[Backend]] = Field(None, description="List of backends.")
    backend_max_connections: Optional[int] = Field(
        None,
        description=(
            "Max simultaneous connections the load balancer can make to any backend in this set "
            "unless the backend overrides with its own maxConnections."
        ),
    )
    health_checker: Optional[HealthChecker] = Field(
        None, description="Health check policy configuration."
    )
    ssl_configuration: Optional[SSLConfiguration] = Field(
        None, description="Backend set SSL handling configuration."
    )
    session_persistence_configuration: Optional[
        SessionPersistenceConfigurationDetails
    ] = Field(
        None,
        description=(
            "Application cookie stickiness configuration. Mutually exclusive with LB cookie stickiness."
        ),
    )
    lb_cookie_session_persistence_configuration: Optional[
        LBCookieSessionPersistenceConfigurationDetails
    ] = Field(
        None,
        description=(
            "LB cookie stickiness configuration. Mutually exclusive with application cookie stickiness."
        ),
    )


class Hostname(BaseModel):
    name: Optional[str] = Field(None, description="Hostname resource name.")
    hostname: Optional[str] = Field(None, description="Virtual hostname.")


class SSLCipherSuite(BaseModel):
    name: Optional[str] = Field(None, description="Cipher suite name.")
    ciphers: Optional[List[str]] = Field(
        None, description="List of ciphers enabled in the suite."
    )


class Certificate(BaseModel):
    certificate_name: Optional[str] = Field(
        None, description="Certificate bundle friendly name."
    )
    public_certificate: Optional[str] = Field(
        None, description="Public certificate in PEM format."
    )
    ca_certificate: Optional[str] = Field(
        None, description="CA certificate or bundle in PEM format."
    )


class PathMatchType(BaseModel):
    match_type: Optional[
        Literal[
            "EXACT_MATCH", "FORCE_LONGEST_PREFIX_MATCH", "PREFIX_MATCH", "SUFFIX_MATCH"
        ]
    ] = Field(None, description="Type of matching to apply to incoming URIs.")


class PathRoute(BaseModel):
    path: Optional[str] = Field(None, description="The path string to match.")
    path_match_type: Optional[PathMatchType] = Field(
        None, description="Path matching configuration."
    )
    backend_set_name: Optional[str] = Field(
        None, description="Target backend set when the path matches."
    )


class PathRouteSet(BaseModel):
    name: Optional[str] = Field(None, description="Path route set name.")
    path_routes: Optional[List[PathRoute]] = Field(
        None, description="Set of path route rules."
    )


class ShapeDetails(BaseModel):
    minimum_bandwidth_in_mbps: Optional[int] = Field(
        None, description="Minimum pre-provisioned bandwidth in Mbps."
    )
    maximum_bandwidth_in_mbps: Optional[int] = Field(
        None, description="Maximum bandwidth in Mbps."
    )


class Action(BaseModel):
    name: Optional[Literal["FORWARD_TO_BACKENDSET"]] = Field(
        None, description="Action name (currently only FORWARD_TO_BACKENDSET)."
    )
    backend_set_name: Optional[str] = Field(
        None, description="Name of the backend set to forward to."
    )


class RoutingRule(BaseModel):
    name: Optional[str] = Field(None, description="Routing rule name.")
    condition: Optional[str] = Field(
        None, description="Routing condition written in the configured language."
    )
    actions: Optional[List[Action]] = Field(
        None, description="Actions to apply when the condition evaluates true."
    )


class RoutingPolicy(BaseModel):
    name: Optional[str] = Field(None, description="Routing policy name.")
    condition_language_version: Optional[str] = Field(
        None, description="Version of the condition language (e.g., V1)."
    )
    rules: Optional[List[RoutingRule]] = Field(
        None, description="Ordered list of routing rules."
    )


class RuleSet(BaseModel):
    name: Optional[str] = Field(None, description="Rule set name.")
    # Represent rules as unstructured dicts for flexibility (many variants)
    items: Optional[List[Dict[str, Any]]] = Field(
        None, description="List of rules composing the rule set."
    )


class LoadBalancer(BaseModel):
    id: Optional[str] = Field(None, description="The OCID of the load balancer.")
    compartment_id: Optional[str] = Field(
        None, description="The OCID of the compartment containing the load balancer."
    )
    display_name: Optional[str] = Field(
        None, description="A user-friendly display name for the load balancer."
    )
    lifecycle_state: Optional[
        Literal["CREATING", "FAILED", "ACTIVE", "DELETING", "DELETED"]
    ] = Field(None, description="The current lifecycle state of the load balancer.")
    time_created: Optional[datetime] = Field(
        None, description="The time the load balancer was created (RFC3339)."
    )

    ip_addresses: Optional[List[IpAddress]] = Field(
        None, description="Array of IP addresses."
    )
    shape_name: Optional[str] = Field(
        None, description="Shape name determining the pre-provisioned bandwidth."
    )
    shape_details: Optional[ShapeDetails] = Field(
        None, description="Flexible shape bandwidth configuration."
    )
    is_private: Optional[bool] = Field(
        None,
        description="Whether the load balancer has a VCN-local (private) IP address.",
    )
    is_delete_protection_enabled: Optional[bool] = Field(
        None, description="Whether delete protection is enabled."
    )
    is_request_id_enabled: Optional[bool] = Field(
        None, description="Whether Request Id feature for HTTP listeners is enabled."
    )
    request_id_header: Optional[str] = Field(
        None, description="Header name used for Request Id if enabled."
    )
    ip_mode: Optional[Literal["IPV4", "IPV6"]] = Field(
        None, description="Whether the load balancer has an IPv4 or IPv6 address."
    )

    subnet_ids: Optional[List[str]] = Field(
        None, description="List of subnet OCIDs associated with the load balancer."
    )
    network_security_group_ids: Optional[List[str]] = Field(
        None, description="List of NSG OCIDs associated with the load balancer."
    )

    listeners: Optional[Dict[str, "Listener"]] = Field(
        None, description="Listeners associated with the load balancer."
    )
    hostnames: Optional[Dict[str, Hostname]] = Field(
        None, description="Hostnames associated with the load balancer."
    )
    backend_sets: Optional[Dict[str, BackendSet]] = Field(
        None, description="Backend sets associated with the load balancer."
    )
    path_route_sets: Optional[Dict[str, PathRouteSet]] = Field(
        None, description="Path route sets associated with the load balancer."
    )
    certificates: Optional[Dict[str, Certificate]] = Field(
        None, description="Certificates associated with the load balancer."
    )
    ssl_cipher_suites: Optional[Dict[str, SSLCipherSuite]] = Field(
        None, description="SSL cipher suites associated with the load balancer."
    )

    rule_sets: Optional[Dict[str, RuleSet]] = Field(
        None, description="Rule sets associated with the load balancer."
    )
    routing_policies: Optional[Dict[str, RoutingPolicy]] = Field(
        None, description="Routing policies associated with the load balancer."
    )

    freeform_tags: Optional[Dict[str, str]] = Field(
        None, description="Free-form tags for this resource."
    )
    defined_tags: Optional[Dict[str, Dict[str, Any]]] = Field(
        None, description="Defined tags for this resource."
    )
    security_attributes: Optional[Dict[str, Dict[str, Any]]] = Field(
        None, description="Extended defined tags for ZPR (if present)."
    )
    system_tags: Optional[Dict[str, Dict[str, Any]]] = Field(
        None, description="System tags for this resource."
    )


class Listener(BaseModel):
    name: Optional[str] = Field(None, description="Listener friendly name.")
    default_backend_set_name: Optional[str] = Field(
        None, description="Name of the associated backend set."
    )
    port: Optional[int] = Field(None, description="Listener port.")
    protocol: Optional[str] = Field(
        None,
        description="Protocol on which the listener accepts connections (HTTP, HTTP2, TCP, GRPC).",
    )
    hostname_names: Optional[List[str]] = Field(
        None, description="Array of hostname resource names."
    )
    path_route_set_name: Optional[str] = Field(
        None,
        description="Deprecated: name of the path route set applied to this listener.",
    )
    ssl_configuration: Optional[SSLConfiguration] = Field(
        None, description="SSL handling configuration for the listener."
    )
    connection_configuration: Optional[ConnectionConfiguration] = Field(
        None, description="Client-backend connection configuration."
    )
    rule_set_names: Optional[List[str]] = Field(
        None, description="Names of rule sets applied to the listener."
    )
    routing_policy_name: Optional[str] = Field(
        None,
        description="Name of the routing policy applied to this listener's traffic.",
    )


# Mapping functions


def map_reserved_ip(obj) -> ReservedIP | None:
    if not obj:
        return None
    return ReservedIP(id=getattr(obj, "id", None))


def map_ip_address(obj) -> IpAddress | None:
    if not obj:
        return None
    return IpAddress(
        ip_address=getattr(obj, "ip_address", None),
        is_public=getattr(obj, "is_public", None),
        reserved_ip=map_reserved_ip(getattr(obj, "reserved_ip", None)),
    )


def map_health_checker(obj) -> HealthChecker | None:
    if not obj:
        return None
    return HealthChecker(
        protocol=getattr(obj, "protocol", None),
        url_path=getattr(obj, "url_path", None),
        port=getattr(obj, "port", None),
        return_code=getattr(obj, "return_code", None),
        retries=getattr(obj, "retries", None),
        timeout_in_millis=getattr(obj, "timeout_in_millis", None),
        interval_in_millis=getattr(obj, "interval_in_millis", None),
        response_body_regex=getattr(obj, "response_body_regex", None),
        is_force_plain_text=getattr(obj, "is_force_plain_text", None),
    )


def map_backend(obj) -> Backend | None:
    if not obj:
        return None
    return Backend(
        name=getattr(obj, "name", None),
        ip_address=getattr(obj, "ip_address", None),
        port=getattr(obj, "port", None),
        weight=getattr(obj, "weight", None),
        max_connections=getattr(obj, "max_connections", None),
        drain=getattr(obj, "drain", None),
        backup=getattr(obj, "backup", None),
        offline=getattr(obj, "offline", None),
    )


def map_session_persistence_configuration(
    obj,
) -> SessionPersistenceConfigurationDetails | None:
    if not obj:
        return None
    return SessionPersistenceConfigurationDetails(
        cookie_name=getattr(obj, "cookie_name", None),
        disable_fallback=getattr(obj, "disable_fallback", None),
    )


def map_lb_cookie_session_persistence_configuration(
    obj,
) -> LBCookieSessionPersistenceConfigurationDetails | None:
    if not obj:
        return None
    return LBCookieSessionPersistenceConfigurationDetails(
        cookie_name=getattr(obj, "cookie_name", None),
        disable_fallback=getattr(obj, "disable_fallback", None),
        domain=getattr(obj, "domain", None),
        path=getattr(obj, "path", None),
        max_age_in_seconds=getattr(obj, "max_age_in_seconds", None),
        is_secure=getattr(obj, "is_secure", None),
        is_http_only=getattr(obj, "is_http_only", None),
    )


def map_ssl_configuration(obj) -> SSLConfiguration | None:
    if not obj:
        return None
    return SSLConfiguration(
        protocols=getattr(obj, "protocols", None),
        cipher_suite_name=getattr(obj, "cipher_suite_name", None),
        server_order_preference=getattr(obj, "server_order_preference", None),
        certificate_name=getattr(obj, "certificate_name", None),
        certificate_ids=getattr(obj, "certificate_ids", None),
        trusted_certificate_authority_ids=getattr(
            obj, "trusted_certificate_authority_ids", None
        ),
        has_session_resumption=getattr(obj, "has_session_resumption", None),
        verify_peer_certificate=getattr(obj, "verify_peer_certificate", None),
        verify_depth=getattr(obj, "verify_depth", None),
    )


def map_connection_configuration(obj) -> ConnectionConfiguration | None:
    if not obj:
        return None
    return ConnectionConfiguration(
        idle_timeout=getattr(obj, "idle_timeout", None),
        backend_tcp_proxy_protocol_version=getattr(
            obj, "backend_tcp_proxy_protocol_version", None
        ),
        backend_tcp_proxy_protocol_options=getattr(
            obj, "backend_tcp_proxy_protocol_options", None
        ),
    )


def map_backend_set(obj) -> BackendSet | None:
    if not obj:
        return None
    backends = (
        [map_backend(b) for b in getattr(obj, "backends", [])]
        if getattr(obj, "backends", None)
        else None
    )
    return BackendSet(
        name=getattr(obj, "name", None),
        policy=getattr(obj, "policy", None),
        backends=backends,
        backend_max_connections=getattr(obj, "backend_max_connections", None),
        health_checker=map_health_checker(getattr(obj, "health_checker", None)),
        ssl_configuration=map_ssl_configuration(
            getattr(obj, "ssl_configuration", None)
        ),
        session_persistence_configuration=map_session_persistence_configuration(
            getattr(obj, "session_persistence_configuration", None)
        ),
        lb_cookie_session_persistence_configuration=map_lb_cookie_session_persistence_configuration(
            getattr(obj, "lb_cookie_session_persistence_configuration", None)
        ),
    )


def map_hostname(obj) -> Hostname | None:
    if not obj:
        return None
    return Hostname(
        name=getattr(obj, "name", None),
        hostname=getattr(obj, "hostname", None),
    )


def map_ssl_cipher_suite(obj) -> SSLCipherSuite | None:
    if not obj:
        return None
    return SSLCipherSuite(
        name=getattr(obj, "name", None),
        ciphers=getattr(obj, "ciphers", None),
    )


def map_certificate(obj) -> Certificate | None:
    if not obj:
        return None
    return Certificate(
        certificate_name=getattr(obj, "certificate_name", None),
        public_certificate=getattr(obj, "public_certificate", None),
        ca_certificate=getattr(obj, "ca_certificate", None),
    )


def map_path_match_type(obj) -> PathMatchType | None:
    if not obj:
        return None
    return PathMatchType(match_type=getattr(obj, "match_type", None))


def map_path_route(obj) -> PathRoute | None:
    if not obj:
        return None
    return PathRoute(
        path=getattr(obj, "path", None),
        path_match_type=map_path_match_type(getattr(obj, "path_match_type", None)),
        backend_set_name=getattr(obj, "backend_set_name", None),
    )


def map_path_route_set(obj) -> PathRouteSet | None:
    if not obj:
        return None
    routes = (
        [map_path_route(r) for r in getattr(obj, "path_routes", [])]
        if getattr(obj, "path_routes", None)
        else None
    )
    return PathRouteSet(name=getattr(obj, "name", None), path_routes=routes)


def map_shape_details(obj) -> ShapeDetails | None:
    if not obj:
        return None
    return ShapeDetails(
        minimum_bandwidth_in_mbps=getattr(obj, "minimum_bandwidth_in_mbps", None),
        maximum_bandwidth_in_mbps=getattr(obj, "maximum_bandwidth_in_mbps", None),
    )


def map_action(obj) -> Action | None:
    if not obj:
        return None
    return Action(
        name=getattr(obj, "name", None),
        backend_set_name=getattr(obj, "backend_set_name", None),
    )


def map_routing_rule(obj) -> RoutingRule | None:
    if not obj:
        return None
    actions = (
        [map_action(a) for a in getattr(obj, "actions", [])]
        if getattr(obj, "actions", None)
        else None
    )
    return RoutingRule(
        name=getattr(obj, "name", None),
        condition=getattr(obj, "condition", None),
        actions=actions,
    )


def map_routing_policy(obj) -> RoutingPolicy | None:
    if not obj:
        return None
    rules = (
        [map_routing_rule(r) for r in getattr(obj, "rules", [])]
        if getattr(obj, "rules", None)
        else None
    )
    return RoutingPolicy(
        name=getattr(obj, "name", None),
        condition_language_version=getattr(obj, "condition_language_version", None),
        rules=rules,
    )


def map_rule_set(obj) -> RuleSet | None:
    if not obj:
        return None
    # Keep items as loose dicts to accommodate all rule variants
    items = getattr(obj, "items", None)
    try:
        if items is not None:
            items = [_oci_to_dict(i) for i in items]
    except Exception:
        items = None
    return RuleSet(name=getattr(obj, "name", None), items=items)


def map_listener(obj) -> Listener | None:
    if not obj:
        return None
    return Listener(
        name=getattr(obj, "name", None),
        default_backend_set_name=getattr(obj, "default_backend_set_name", None),
        port=getattr(obj, "port", None),
        protocol=getattr(obj, "protocol", None),
        hostname_names=getattr(obj, "hostname_names", None),
        path_route_set_name=getattr(obj, "path_route_set_name", None),
        ssl_configuration=map_ssl_configuration(
            getattr(obj, "ssl_configuration", None)
        ),
        connection_configuration=map_connection_configuration(
            getattr(obj, "connection_configuration", None)
        ),
        rule_set_names=getattr(obj, "rule_set_names", None),
        routing_policy_name=getattr(obj, "routing_policy_name", None),
    )


def map_load_balancer(obj: oci.load_balancer.models.LoadBalancer) -> LoadBalancer:
    """Map OCI LoadBalancer to custom Pydantic model."""
    ip_addresses = (
        [map_ip_address(ip) for ip in getattr(obj, "ip_addresses", [])]
        if getattr(obj, "ip_addresses", None)
        else None
    )

    listeners = (
        {k: map_listener(v) for k, v in getattr(obj, "listeners", {}).items()}
        if getattr(obj, "listeners", None)
        else None
    )
    hostnames = (
        {k: map_hostname(v) for k, v in getattr(obj, "hostnames", {}).items()}
        if getattr(obj, "hostnames", None)
        else None
    )
    backend_sets = (
        {k: map_backend_set(v) for k, v in getattr(obj, "backend_sets", {}).items()}
        if getattr(obj, "backend_sets", None)
        else None
    )
    path_route_sets = (
        {
            k: map_path_route_set(v)
            for k, v in getattr(obj, "path_route_sets", {}).items()
        }
        if getattr(obj, "path_route_sets", None)
        else None
    )
    certificates = (
        {k: map_certificate(v) for k, v in getattr(obj, "certificates", {}).items()}
        if getattr(obj, "certificates", None)
        else None
    )
    ssl_cipher_suites = (
        {
            k: map_ssl_cipher_suite(v)
            for k, v in getattr(obj, "ssl_cipher_suites", {}).items()
        }
        if getattr(obj, "ssl_cipher_suites", None)
        else None
    )
    rule_sets = (
        {k: map_rule_set(v) for k, v in getattr(obj, "rule_sets", {}).items()}
        if getattr(obj, "rule_sets", None)
        else None
    )
    routing_policies = (
        {
            k: map_routing_policy(v)
            for k, v in getattr(obj, "routing_policies", {}).items()
        }
        if getattr(obj, "routing_policies", None)
        else None
    )
    return LoadBalancer(
        id=getattr(obj, "id", None),
        compartment_id=getattr(obj, "compartment_id", None),
        display_name=getattr(obj, "display_name", None),
        lifecycle_state=getattr(obj, "lifecycle_state", None),
        time_created=getattr(obj, "time_created", None),
        ip_addresses=ip_addresses,
        shape_name=getattr(obj, "shape_name", None),
        shape_details=map_shape_details(getattr(obj, "shape_details", None)),
        is_private=getattr(obj, "is_private", None),
        is_delete_protection_enabled=getattr(obj, "is_delete_protection_enabled", None),
        is_request_id_enabled=getattr(obj, "is_request_id_enabled", None),
        request_id_header=getattr(obj, "request_id_header", None),
        ip_mode=getattr(obj, "ip_mode", None),
        subnet_ids=getattr(obj, "subnet_ids", None),
        network_security_group_ids=getattr(obj, "network_security_group_ids", None),
        listeners=listeners,
        hostnames=hostnames,
        backend_sets=backend_sets,
        path_route_sets=path_route_sets,
        certificates=certificates,
        ssl_cipher_suites=ssl_cipher_suites,
        rule_sets=rule_sets,
        routing_policies=routing_policies,
        freeform_tags=getattr(obj, "freeform_tags", None),
        defined_tags=getattr(obj, "defined_tags", None),
        security_attributes=getattr(obj, "security_attributes", None),
        defined_tags_extended=getattr(obj, "defined_tags_extended", None),
        system_tags=getattr(obj, "system_tags", None),
    )
